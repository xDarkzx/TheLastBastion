#!/usr/bin/env python3
"""
THE LAST BASTION — Border Police Demo

Interactive CLI that demonstrates the full agent security flow:
1. Generate passport files (clean or deliberately broken)
2. Upload to the website for 10-check verification
3. Approve or reject (you are the security admin)
4. Connect to the Border Police via binary protocol

Usage:
    python run_border_demo.py
"""

import asyncio
import base64
import json
import os
import sys
import time

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "sdk"))

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.prompt import Prompt, IntPrompt
    from rich.text import Text
    from rich import box
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False


# ---------------------------------------------------------------------------
# Console setup
# ---------------------------------------------------------------------------

if HAS_RICH:
    console = Console()
else:
    class _FallbackConsole:
        def print(self, *args, **kwargs):
            # Strip rich markup
            text = str(args[0]) if args else ""
            if hasattr(text, 'plain'):
                text = text.plain
            print(text)
        def rule(self, *args, **kwargs):
            print("=" * 60)
    console = _FallbackConsole()


BASE_URL = os.environ.get("BASTION_URL", "http://localhost:8000")
PASSPORT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "demo_passports")


def ensure_passport_dir():
    os.makedirs(PASSPORT_DIR, exist_ok=True)


# ---------------------------------------------------------------------------
# Step 1: Generate Passports
# ---------------------------------------------------------------------------

def generate_clean_passport() -> dict:
    """Generate a clean, valid passport file."""
    from lastbastion.passport_generator import generate_passport_file
    ensure_passport_dir()
    path = os.path.join(PASSPORT_DIR, "clean_agent.passport")
    result = generate_passport_file(output_path=path, agent_name="Clean Demo Agent")
    console.print(f"\n  [green]Clean passport generated[/green]" if HAS_RICH else "\n  Clean passport generated")
    console.print(f"  Agent ID:    {result['agent_id']}")
    console.print(f"  Passport:    {result['passport']}")
    console.print(f"  Keys:        {result['keypair']}")
    console.print(f"  Public Key:  {result['public_key'][:24]}...")
    return result


def generate_bad_passport(defect_type: str) -> dict:
    """Generate a bad passport with a specific defect."""
    from lastbastion.passport_generator import generate_bad_passport_file
    ensure_passport_dir()
    path = os.path.join(PASSPORT_DIR, f"bad_{defect_type}.passport")
    result = generate_bad_passport_file(output_path=path, defect_type=defect_type, agent_name=f"Bad Agent ({defect_type})")
    console.print(f"\n  [red]Bad passport generated ({defect_type})[/red]" if HAS_RICH else f"\n  Bad passport generated ({defect_type})")
    console.print(f"  Agent ID:    {result['agent_id']}")
    console.print(f"  Defect:      {result.get('defect', defect_type)}")
    console.print(f"  Passport:    {result['passport']}")
    return result


# ---------------------------------------------------------------------------
# Step 2: Upload & Verify
# ---------------------------------------------------------------------------

async def upload_passport(passport_path: str) -> dict:
    """Upload a passport file to the verification endpoint."""
    if not HAS_HTTPX:
        console.print("  [red]httpx required. Install: pip install httpx[/red]" if HAS_RICH else "  httpx required. Install: pip install httpx")
        return {}

    if not os.path.exists(passport_path):
        console.print(f"  File not found: {passport_path}")
        return {}

    with open(passport_path, "rb") as f:
        envelope_bytes = f.read()

    passport_b64 = base64.b64encode(envelope_bytes).decode()

    console.print(f"\n  Uploading passport ({len(envelope_bytes)} bytes)...")

    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            resp = await client.post(
                f"{BASE_URL}/sandbox/passport/upload",
                json={"passport_b64": passport_b64},
            )
            if resp.status_code != 200:
                console.print(f"  [red]Upload failed: {resp.status_code} {resp.text}[/red]" if HAS_RICH else f"  Upload failed: {resp.status_code} {resp.text}")
                return {}
            return resp.json()
        except httpx.ConnectError:
            console.print(f"  [red]Cannot connect to {BASE_URL}. Is the backend running?[/red]" if HAS_RICH else f"  Cannot connect to {BASE_URL}. Is the backend running?")
            return {}


def display_verification_results(result: dict):
    """Display the 10-check verification results in a table."""
    if not result:
        return

    if HAS_RICH:
        # Build the verification theatre table
        table = Table(
            title="Verification Results",
            box=box.ROUNDED,
            show_header=True,
            header_style="bold",
        )
        table.add_column("Check", width=20)
        table.add_column("Score", justify="center", width=8)
        table.add_column("Status", justify="center", width=8)
        table.add_column("Detail", width=40)

        checks = result.get("checks", {})
        check_order = [
            "identity", "cryptographic", "capabilities", "reputation",
            "payload_quality", "behavioral", "network", "cross_reference",
            "anti_sybil", "temporal",
        ]
        check_labels = {
            "identity": "Identity",
            "cryptographic": "Cryptographic",
            "capabilities": "Capabilities",
            "reputation": "Reputation",
            "payload_quality": "Payload Quality",
            "behavioral": "Behavioral",
            "network": "Network",
            "cross_reference": "Cross-Reference",
            "anti_sybil": "Anti-Sybil",
            "temporal": "Temporal",
        }

        for i, check_name in enumerate(check_order, 1):
            check = checks.get(check_name, {})
            score = check.get("score", 0.0)
            passed = check.get("passed", False)
            detail = check.get("detail", "")
            veto = check.get("veto", False)

            if veto:
                status = "[red bold]VETO[/red bold]"
            elif passed:
                status = "[green]PASS[/green]"
            elif score >= 0.4:
                status = "[yellow]WARN[/yellow]"
            else:
                status = "[red]FAIL[/red]"

            score_str = f"{score:.2f}"
            if score >= 0.7:
                score_str = f"[green]{score_str}[/green]"
            elif score >= 0.4:
                score_str = f"[yellow]{score_str}[/yellow]"
            else:
                score_str = f"[red]{score_str}[/red]"

            table.add_row(f"#{i:2d} {check_labels.get(check_name, check_name)}", score_str, status, detail[:40])

        console.print()
        console.print(table)

        # Overall verdict
        verdict = result.get("verdict", "UNKNOWN")
        trust_score = result.get("trust_score", 0.0)
        verdict_color = {
            "TRUSTED": "green",
            "SUSPICIOUS": "yellow",
            "MALICIOUS": "red",
        }.get(verdict, "white")

        console.print(f"\n  Overall: [{verdict_color} bold]{verdict}[/{verdict_color} bold] (score: {trust_score:.2f})")

        risk_flags = result.get("risk_flags", [])
        if risk_flags:
            console.print(f"  Risk flags: [red]{', '.join(risk_flags)}[/red]")

        console.print(f"\n  [dim]{result.get('message', '')}[/dim]")

    else:
        # Fallback plain text
        checks = result.get("checks", {})
        print("\n  === Verification Results ===\n")
        for name, check in checks.items():
            score = check.get("score", 0.0)
            passed = "PASS" if check.get("passed") else "FAIL"
            print(f"  {name:20s}  {score:.2f}  {passed}")
        print(f"\n  Verdict: {result.get('verdict', 'UNKNOWN')} (score: {result.get('trust_score', 0.0):.2f})")

    return result


async def approve_or_reject(verification_id: int) -> str:
    """Let the developer approve or reject the passport."""
    if not HAS_HTTPX:
        return "skip"

    if HAS_RICH:
        console.print("\n  [bold]You are the security admin. Make your decision:[/bold]")
        choice = Prompt.ask("  [A]pprove or [R]eject?", choices=["a", "r", "A", "R"], default="a")
    else:
        choice = input("\n  [A]pprove or [R]eject? ").strip().lower()

    action = "approve" if choice.lower() == "a" else "reject"

    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.post(f"{BASE_URL}/sandbox/passport/{verification_id}/{action}")
        if resp.status_code == 200:
            data = resp.json()
            if action == "approve":
                console.print(f"\n  [green bold]APPROVED[/green bold] — {data.get('message', '')}" if HAS_RICH else f"\n  APPROVED — {data.get('message', '')}")
            else:
                console.print(f"\n  [red bold]REJECTED[/red bold] — {data.get('message', '')}" if HAS_RICH else f"\n  REJECTED — {data.get('message', '')}")
        else:
            console.print(f"  Error: {resp.status_code} {resp.text}")

    return action


# ---------------------------------------------------------------------------
# Step 3: Connect to Border Police
# ---------------------------------------------------------------------------

async def connect_to_border(passport_path: str, keys_path: str):
    """Connect to the Border Police using the binary protocol and have an LLM conversation."""
    if not os.path.exists(passport_path) or not os.path.exists(keys_path):
        console.print("  Passport or keys file not found. Generate a passport first.")
        return

    with open(keys_path, "r") as f:
        keys = json.load(f)

    with open(passport_path, "rb") as f:
        envelope_bytes = f.read()

    # Reconstruct passport
    import msgpack
    raw_claims = msgpack.unpackb(envelope_bytes[:-64], raw=False)
    from lastbastion.passport import AgentPassport
    passport = AgentPassport(**raw_claims)

    console.print(f"\n  Connecting to Border Police at localhost:9200...")
    console.print(f"  Agent: {passport.agent_id}")
    console.print(f"  Passport ID: {passport.passport_id}")

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection("localhost", 9200),
            timeout=5.0,
        )
    except (ConnectionRefusedError, asyncio.TimeoutError, OSError):
        console.print("  [red]Cannot connect to Border Police on port 9200.[/red]" if HAS_RICH else "  Cannot connect to Border Police on port 9200.")
        console.print("  Start it with: python -c \"from core.border_agent import BorderAgent; import asyncio; asyncio.run(BorderAgent().start())\"")
        return

    try:
        # Build and send HELLO frame
        from lastbastion.protocol.handshake import (
            build_hello, generate_ephemeral_keypair,
        )

        ephemeral = generate_ephemeral_keypair()
        issuer_priv = keys.get("issuer_private_key", keys.get("private_key", ""))

        hello_frame = build_hello(passport, issuer_priv, ephemeral.public_key)

        console.print("  Sending HELLO frame...")
        writer.write(hello_frame.to_bytes())
        await writer.drain()

        # Read response — could be HELLO_ACK (binary) followed by greeting (JSON)
        # or an error/denied JSON response
        response = await asyncio.wait_for(reader.read(65536), timeout=15.0)
        if not response:
            console.print("  Connection closed by Border Police.")
            return

        # Parse the first response
        data = _parse_border_response(response)

        # If we got a binary frame (HELLO_ACK), read the next message (greeting)
        if data is None:
            greeting_raw = await asyncio.wait_for(reader.read(65536), timeout=10.0)
            if not greeting_raw:
                console.print("  Connection closed after handshake.")
                return
            data = _parse_border_response(greeting_raw)
            if data is None:
                console.print("  Unexpected response from Border Police.")
                return

        status = data.get("status", "unknown")

        # Handle denied/error
        if status == "denied":
            console.print(f"\n  [red bold]ACCESS DENIED[/red bold]" if HAS_RICH else "\n  ACCESS DENIED")
            console.print(f"  {data.get('message', '')}")
            return

        if status == "error":
            console.print(f"\n  [red bold]ERROR[/red bold]" if HAS_RICH else "\n  ERROR")
            console.print(f"  {data.get('message', '')}")
            return

        # --- LLM CONVERSATION MODE ---
        if status == "conversation":
            console.print(f"\n  [green bold]CONNECTED — LLM Conversation Mode[/green bold]" if HAS_RICH else "\n  CONNECTED — LLM Conversation Mode")

            turn = data.get("turn", 1)
            total_turns = data.get("total_turns", 4)

            # Display Border Police greeting
            _display_message("Border Police", data.get("message", ""), "blue")

            # Conversation loop — respond to each turn
            while True:
                # Get user input (or they can type on behalf of their agent)
                if HAS_RICH:
                    console.print(f"\n  [dim]Turn {turn}/{total_turns} — Type your agent's reply:[/dim]")
                    user_msg = Prompt.ask("  You")
                else:
                    print(f"\n  Turn {turn}/{total_turns} — Type your agent's reply:")
                    user_msg = input("  You> ").strip()

                if not user_msg:
                    user_msg = "Hello, what services do you offer?"

                # Send message
                writer.write(json.dumps({"message": user_msg}).encode() + b"\n")
                await writer.drain()

                # Read Border Police reply
                reply_raw = await asyncio.wait_for(reader.read(65536), timeout=30.0)
                if not reply_raw:
                    console.print("  Connection closed.")
                    break

                reply = _parse_border_response(reply_raw)
                if reply is None:
                    console.print("  Unexpected response.")
                    break

                reply_status = reply.get("status", "")
                turn = reply.get("turn", turn + 1)

                # Display Border Police message
                _display_message("Border Police", reply.get("message", ""), "blue")

                if reply_status == "closing":
                    # Conversation complete — show summary
                    console.print(f"\n  [green bold]CONNECTION COMPLETE[/green bold]" if HAS_RICH else "\n  CONNECTION COMPLETE")

                    summary = reply.get("session_summary", {})
                    if summary:
                        console.print(f"\n  --- Session Summary ---")
                        console.print(f"  Platform:       {summary.get('platform', 'N/A')}")
                        console.print(f"  Protocol:       {summary.get('protocol', 'N/A')}")
                        console.print(f"  Authentication: {summary.get('authentication', 'N/A')}")
                        console.print(f"  Exchanges:      {summary.get('total_exchanges', 'N/A')}")
                        console.print(f"  Result:         {summary.get('result', 'N/A')}")

                    transcript = reply.get("transcript", [])
                    if transcript:
                        console.print(f"\n  --- Full Transcript ({len(transcript)} messages) ---")
                        for t in transcript:
                            role = "BP" if t["role"] == "border_police" else "You"
                            msg = t["message"][:80]
                            console.print(f"  [{role}] {msg}")

                    console.print(f"\n  [dim]Your agent can report: 'I successfully connected to The Last Bastion's[/dim]" if HAS_RICH else "")
                    console.print(f"  [dim]Border Police via the Bastion Binary Protocol and had a verified conversation.'[/dim]" if HAS_RICH else "")
                    break

        else:
            console.print(f"  Unexpected status: {status}")
            console.print(f"  {json.dumps(data, indent=2)}")

    except asyncio.TimeoutError:
        console.print("  Connection timed out.")
    except Exception as e:
        console.print(f"  Error: {e}")
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


def _parse_border_response(raw: bytes) -> dict:
    """Try to parse a response as JSON. Returns None if it's a binary frame."""
    try:
        text = raw.decode().strip()
        return json.loads(text)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None


def _display_message(speaker: str, message: str, color: str = "white"):
    """Display a conversation message."""
    if HAS_RICH:
        console.print(f"\n  [{color} bold]{speaker}:[/{color} bold] {message}")
    else:
        print(f"\n  {speaker}: {message}")


# ---------------------------------------------------------------------------
# Auto-run all scenarios
# ---------------------------------------------------------------------------

async def run_all_scenarios():
    """Run all 5 bad passport types + 1 clean passport through the full flow."""
    console.print("\n  Running all scenarios...\n")

    defects = ["tampered", "expired", "injected", "wrong_key", "sybil"]

    # Generate and upload clean passport
    console.rule("Clean Passport" if HAS_RICH else "")
    result = generate_clean_passport()
    upload_result = await upload_passport(result["passport"])
    display_verification_results(upload_result)
    if upload_result.get("id"):
        await approve_or_reject(upload_result["id"])

    # Generate and upload each bad passport type
    for defect in defects:
        if HAS_RICH:
            console.rule(f"Bad Passport: {defect}")
        else:
            print(f"\n{'='*60}\n  Bad Passport: {defect}\n{'='*60}")

        result = generate_bad_passport(defect)
        upload_result = await upload_passport(result["passport"])
        display_verification_results(upload_result)
        if upload_result.get("id"):
            await approve_or_reject(upload_result["id"])


# ---------------------------------------------------------------------------
# Main Menu
# ---------------------------------------------------------------------------

_last_generated: dict = {}


async def main():
    global _last_generated

    if HAS_RICH:
        console.print(Panel(
            "[bold]THE LAST BASTION[/bold]\n"
            "[dim]Border Police Demo — Agent Security Proof of Concept[/dim]\n\n"
            "Generate passports, watch verification checks run live,\n"
            "approve or reject agents, then connect via binary protocol.",
            title="Border Police",
            border_style="blue",
        ))
    else:
        print("\n" + "=" * 50)
        print("  THE LAST BASTION — Border Police Demo")
        print("=" * 50)

    while True:
        console.print("\n  STEP 1: Generate Passport")
        console.print("    [1] Generate CLEAN passport")
        console.print("    [2] Generate BAD passport (tampered)")
        console.print("    [3] Generate BAD passport (expired)")
        console.print("    [4] Generate BAD passport (injection)")
        console.print("    [5] Generate BAD passport (wrong key)")
        console.print("    [6] Generate BAD passport (sybil clone)")
        console.print("\n  STEP 2: Upload & Verify")
        console.print("    [U] Upload last generated passport")
        console.print("\n  STEP 3: Connect")
        console.print("    [C] Connect to Border Police")
        console.print("\n  Other")
        console.print("    [A] Run ALL scenarios automatically")
        console.print("    [0] Exit\n")

        if HAS_RICH:
            choice = Prompt.ask("  Choice", default="1")
        else:
            choice = input("  Choice: ").strip() or "1"

        if choice == "0":
            console.print("  Goodbye.")
            break

        elif choice == "1":
            _last_generated = generate_clean_passport()

        elif choice in ("2", "3", "4", "5", "6"):
            defect_map = {"2": "tampered", "3": "expired", "4": "injected", "5": "wrong_key", "6": "sybil"}
            _last_generated = generate_bad_passport(defect_map[choice])

        elif choice.lower() == "u":
            if not _last_generated:
                console.print("  Generate a passport first (options 1-6).")
                continue
            upload_result = await upload_passport(_last_generated["passport"])
            display_verification_results(upload_result)
            if upload_result.get("id"):
                await approve_or_reject(upload_result["id"])

        elif choice.lower() == "c":
            if not _last_generated:
                console.print("  Generate a passport first (options 1-6).")
                continue
            await connect_to_border(
                _last_generated["passport"],
                _last_generated["keypair"],
            )

        elif choice.lower() == "a":
            await run_all_scenarios()

        else:
            console.print("  Invalid choice.")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n  Interrupted.")
