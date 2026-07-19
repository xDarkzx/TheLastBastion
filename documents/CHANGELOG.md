# Changelog — Bastion Protocol Security & Reliability Audit

**2026-07-18 to 2026-07-19**

This covers a full audit pass over the Bastion Protocol SDK (`sdk/lastbastion/`)
and the parts of the backend it touches (`core/`, `protocols/`), done in two
phases: an initial 3-fork audit (security / correctness / architecture),
followed by a second round explicitly targeting memory leaks, bloated/dead
code, and remaining security gaps, with a mandate to keep optimizing rather
than stop at "good enough." Every fix below was verified with the same
method: git-stash the fix, confirm the regression test fails against the
old code, restore the fix, confirm it passes. Claims about performance are
backed by the same rigorous multi-trial methodology already documented in
`BENCHMARK_METHODOLOGY.md` — nothing here is asserted without having been
directly measured or reproduced.

---

## Critical

**Session resumption tickets were replayable for up to ~59 minutes with no
private key needed.** Tickets are valid for `DEFAULT_TICKET_TTL_SECONDS`
(1 hour), but single-use enforcement reused `NonceRegistry`'s 30-second
handshake-freshness purge window — correct for short-lived handshake
nonces, wrong for anything that legitimately lives longer. A ticket's
single-use record was forgotten 30 seconds after redemption while the
ticket itself stayed valid for the remaining ~59 minutes, directly
contradicting `resumption.py`'s own documented guarantee ("an attacker who
steals one ticket only gets one resumption"). Fixed by giving
`NonceRegistry` a per-instance TTL instead of a hardcoded constant, and
having `ResumptionResponder` size its dedicated registry to the ticket's
actual lifetime.

Verifying this surfaced a second, independent bug in the same three call
sites: `nonce_registry or <default>` silently discarded any
explicitly-passed *empty* registry, because `NonceRegistry` defines
`__len__` and Python treats a zero-length object as falsy. Any caller
following the documented "pass your own registry" pattern was silently
ignored — including the first attempt at a regression test for the ticket
bug, which is how this was caught. Fixed all three sites to check
`is not None` instead.

**Escalation-lockout appeal endpoints (`POST /m2m/appeal`,
`POST /m2m/appeal/{id}/resolve`) were fully unauthenticated.** Anyone could
file an appeal for any agent and then approve their own appeal, with zero
credentials, completely bypassing the tier-3 escalation lockout mechanism
those endpoints exist to gate. `x_api_key_id` was accepted as a header but
never actually validated against anything. Gated both behind the same
`ADMIN_KEY` pattern already used for `/refinery/quarantine/*/resolve` and
`/anchoring/approve/*` (both other "an operator, not the agent itself,
approves this" actions).

**`trust_decay_loop()` has likely never actually applied a decay in a live
run.** The decay-application line referenced `inactive_days`, a name never
bound anywhere in the function — the real variable is `inactivity_days`.
That f-string is evaluated while building `apply_trust_decay()`'s
arguments, so the `NameError` fired *before* `apply_trust_decay()` was ever
called. This happened on every single decay event, in both demo and normal
mode, silently caught by the loop's own broad `except Exception` with
nothing but a `print()` to show for it — meaning inactive-agent trust decay
and the auto-revocation-below-0.40 safety net have likely never fired.
No existing test exercised the loop itself (the one decay test only calls
`apply_trust_decay()` directly with hardcoded values), so this went
uncaught. Fixed the typo; added a regression test that mocks the DB layer
and runs one real loop iteration, confirmed it fails on the old code and
passes on the fix.

## High

- **`protocol_bus.log()` doesn't exist — six call sites crashed with
  `AttributeError` on every hit.** Passport issuance, all three escalation
  tiers, and both appeal file/resolve paths called a method that was never
  defined on `ProtocolMessageBus` (only `.record()` is). Found live, while
  testing the appeal-auth fix above, via a real `curl` against a running
  Docker stack returning 500 instead of the expected pass-through. Fixed
  all six call sites and verified each one live end-to-end afterward
  (including triggering the DENIED resolve branch specifically, a separate
  code path from APPROVED).

- **`m2m_router.py`'s in-memory `_tasks`/`_results` warm caches had six
  write paths that bypassed their own size cap**, one of them reachable via
  the fully unauthenticated `GET /refinery/status/{data_hash}` — every DB
  cache-miss on that endpoint grew `_results` with no bound. Every write
  site now calls `_evict_cache()`.

- **`bastion_bus._active_sessions` leaked one entry per failed handshake,
  forever.** Only `CONNECTION_CLOSED` was treated as a terminal event; any
  handshake or frame error (auth rejection, timeout, transport failure)
  recorded `ERROR` instead, which was never cleaned up. `ERROR` is now
  terminal too, with a hard size cap on both `_active_sessions` and
  `_agent_last_seen` as defense-in-depth for any path not yet identified.

- **Session resumption ticket-replay and registry-selection bugs** — see
  Critical above.

- **Malformed peer payloads raised raw msgpack/`KeyError`/`TypeError`
  instead of the documented `ConnectionError` contract.** Every
  `AgentConnection` docstring says catch `ConnectionError`; a peer sending
  a structurally valid frame with a non-msgpack payload (trivial in
  `trusted_transport=True` mode, where there's no decrypt/MAC step to
  reject it first) raised something else entirely. Added
  `_safe_deserialize()` at every wire-payload parse site. Same pass also
  caught and fixed two adjacent bounds bugs: an unvalidated `chunk_index`
  (uncaught `IndexError` on an out-of-range claim) and an unvalidated
  `chunk_count` vs `total_size` (a peer could claim a tiny `total_size`
  alongside an enormous `chunk_count`, forcing an immediate huge list
  allocation).

- **Concurrent `send_stream()`/`recv_stream()` calls could interleave and
  corrupt each other.** The send/recv locks were held per-frame, not for
  the whole logical stream operation, so a second stream (or a plain
  `send()`) could interleave its frames mid-stream. Reproduced directly —
  two concurrent streams with a small chunk size reliably crashed the old
  code with `ConnectionResetError` ("Expected STREAM_CHUNK, got 0x05" — a
  `STREAM_START` from the other stream landing mid-sequence). Fixed by
  holding the lock for the entire operation, using the lock-free
  `_write_frame_raw()`/`_read_frame_raw()` internally to avoid deadlocking
  on the already-held lock (`asyncio.Lock` isn't reentrant).

- **`PeerTrustStore` never re-read its backing file after construction.**
  In any deployment with more than one process sharing a trust-store file
  (multiple workers, a separate revocation-check process), `revoke()` in
  one process was invisible to every other instance until it independently
  restarted. Fixed with an mtime-check-before-decision reload on every
  read/decision path.

- **Unbounded concurrent pending handshakes** — no cap on in-flight
  handshakes meant a burst of connection attempts could exhaust server
  resources before any of them authenticated. Added a bounded
  `asyncio.Semaphore` (default 100) around the pre-auth portion of
  connection handling, released as soon as the handshake completes.

## Medium

- **`gateway.py`'s `refresh_budget()` never gave the stale-budget sweep a
  chance to run and never refreshed `last_seen`.** A just-reverified
  agent's entry could still get evicted as "stale" by the next unrelated
  call to `_init_budget()`. Now calls the sweep and refreshes `last_seen`
  on every refresh.

- **`AgentRegistry` had no eviction or cap at all.**
  `get_stale_agents()` existed but nothing ever called it.
  `register_agent()` is reachable unauthenticated via `POST /m2m/register`
  with a client-supplied `agent_id`, so `_agents`/`_agent_services` grew
  without bound for the life of the process. Now swept on every
  registration (evicting agents past `STALE_THRESHOLD_HOURS`), plus a hard
  cap (`_MAX_AGENTS = 5000`) as defense-in-depth for agents that never
  accumulate a `last_seen` at all.

- **Sequence-number overflow raised a bare `OverflowError` instead of
  `ConnectionError`.** Normalized to match the documented contract, with
  the connection marked closed on the way out.

## Low

- **Dead fail-open branch in signature verification.**
  `FrameDecoder._verify_signature()` had `if not self._verify_key: return
  True` — unreachable today (the one call site already guards for this),
  but a latent trap for any future caller that skipped the guard: no key
  would mean "verified." Changed to fail closed (`return False`) — no key
  means verification is impossible, not automatically valid.

- **`AgentSocketServer`/`DirectAgentSocketServer` only swept closed
  connections when a *new* one arrived.** A server that went idle after
  bursty traffic kept every closed connection's readers/writers in memory
  indefinitely. Added a periodic 30s background sweep to both, matching
  the existing keepalive-watchdog pattern.

- **Fire-and-forget startup tasks in `regional_core.py`
  (`agent_network.start()`, `research_arena.start()`,
  `trust_decay_loop()`) had no visibility if they crashed** — `asyncio.
  create_task()` with nothing awaiting the result means an uncaught
  exception just stops the task forever, surfacing only as a low-level
  "Task exception was never retrieved" warning on eventual garbage
  collection. Added a small `_spawn_background_task()` helper with a
  done-callback that logs any crash by name and traceback.

- Redundant `except (SpecificError, Exception)` clauses removed in two
  places (`SpecificError` is itself an `Exception` subclass, so listing it
  separately was dead/misleading either way).

## Dead code and bloat

- Msgpack container limits (`max_array_len`/`max_map_len` = 100k) added on
  all deserialized payloads — previously unbounded on attacker-controlled
  bytes parsed *before* authentication for HELLO/RESUME frames
  specifically (the claimed public key needed to verify a HELLO's
  signature is itself inside the payload being parsed).
- pyflakes-verified dead-import sweep across the whole SDK: `socket.py`,
  `passport_generator.py`, `client.py`, `gateway.py`, `middleware.py`,
  `crypto.py`, `mcp_tools.py`, `models.py`, `frames.py`, `handshake.py`,
  `passport.py`, and `regional_core.py`.
- Removed the dead `RunAttacksRequest` model (`sdk/lastbastion/models.py`)
  — zero references anywhere outside its own definition.
- Removed a broken f-string with no placeholders in `middleware.py`
  (cosmetic — the string content was already correct, just an unnecessary
  `f` prefix).
- Renamed `gateway.py`'s `create_middleware()`-nested class from
  `LastBastionMiddleware` to `_GatewayBoundMiddleware` — it shared its
  exact class name with the unrelated standalone `LastBastionMiddleware`
  in `middleware.py`, despite a completely different constructor contract
  (bound closure over an existing gateway vs. builds its own config from
  kwargs). Would show identically in any stack trace or
  `type(x).__name__`. Nothing referenced the nested class by name, so the
  rename is behavior-preserving.

## Test suite fixes

Two of the fixes above were only found *because* their tests were broken
in ways that made them silently useless:

- **`test_passport_verifier` never actually verified anything.** It built
  its fixture passport without `issuer_public_key` (unlike every other JWT
  test in the file), so `full_verify()`'s issuer check failed closed and
  the "should be valid" assertion never actually passed — the test had
  been quietly checking the wrong thing.

- **`test_progressive_trust.py`'s Phase A never passed.** It computed a
  "HMAC fallback signature" (`sha256(nonce + public_key)`) that the actual
  `/m2m/register/verify` endpoint has never accepted — that endpoint is
  Ed25519-only. Confirmed failing on the pre-audit baseline commit too
  (not a regression from this work). Fixed by generating a real Ed25519
  keypair and signing with it, matching how a real agent registers.

- **Same file, Phase D: a hardcoded `agent_id` ("sandbox-test-agent")**
  meant sandbox-graduation state accumulated in the real database across
  every re-run of the suite — unlike every other identity in the same
  test function, which is correctly randomized. Re-running the suite a
  second time made the "low resilience should not graduate" assertion
  fail, because it picked up a stale "best score" left over from the
  previous run instead of evaluating only the current run's sessions.
  Randomized it; verified stable across 3 consecutive runs.

- **`scripts/run_backend_test.py` had no `sys.path` setup.** The
  invocation documented in `CLAUDE.md` (`python run_backend_test.py`) has
  been broken since the file was relocated into `scripts/` — Python only
  auto-adds the script's own directory to `sys.path`, not the project
  root, so every `core.*`/`protocols.*` import failed. Added the missing
  path insert.

## Performance: uvloop, tested and refuted

An earlier architectural review flagged `uvloop` as the highest-leverage
untested lever for closing Bastion's remaining gap to plain JSON (unused
anywhere in this project; public benchmarks show 2.6–5.5x more event-loop
throughput). Tested it directly with the same 10-trial rigorous
methodology already used elsewhere, on the best-case configuration
(`trusted_transport=True` + `uvloop` together, on Linux/WSL2).

**Result: it made the gap worse, not better.** Round-trip ratio went from
0.28x to 0.19x of JSON's throughput; pipelined stayed roughly flat. uvloop
genuinely sped up raw socket I/O for both protocols — JSON's own
round-trip throughput jumped 50% — but Bastion's own frame-processing
overhead (already identified via `cProfile` as the dominant remaining cost
in an earlier pass, not the shared I/O layer) doesn't shrink from a faster
event loop, since none of it is I/O-bound. A faster shared I/O layer helps
whichever side does *less other work* proportionally more — that's JSON,
not Bastion. Full methodology and numbers in `BENCHMARK_METHODOLOGY.md`.
`--uvloop` support is kept in both bench tools as a reusable capability,
independent of this specific negative result — the honest thing to publish
is the measurement, not the hypothesis.

## Known follow-ups (not yet attempted)

- **`core/database.py`/`m2m_router.py`'s `SessionLocal` try/finally
  boilerplate** appears at roughly 119 call sites. A context-manager
  refactor is the obvious cleanup, but the blast radius is large enough
  that it wasn't attempted without discussing scope with the project owner
  first.
- The MCP Bridge (`core/mcp_bridge.py`) still has the Docker MCP Gateway
  adapter present but actual tool integration incomplete — unrelated to
  this audit, called out in `CLAUDE.md` as a pre-existing gap.
