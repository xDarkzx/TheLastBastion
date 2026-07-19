"""
Bastion Protocol -- AgentSocket.

The developer-facing API for agent-to-agent communication.

Server:
    async def handle(conn):
        msg = await conn.recv()
        await conn.send({"status": "ok"})

    server = AgentSocket.listen(port=9100, passport=my_passport, signing_key=priv, verify_key=pub)
    server.on_connect(handle)
    await server.start()

Client:
    conn = await AgentSocket.connect("host:port", passport=my_passport, signing_key=priv, verify_key=pub)
    await conn.send({"task": "verify"})
    result = await conn.recv()
    await conn.close()

Hard dependencies: pynacl, msgpack.
"""

import asyncio
import hashlib
import logging
import time
import weakref
from dataclasses import dataclass, field
from typing import Any, Callable, Coroutine, Dict, List, Optional

from lastbastion.passport import AgentPassport
from lastbastion.protocol.frames import (
    BastionFrame,
    FrameType,
    FrameEncoder,
    FrameDecoder,
    ErrorCode,
    FRAME_HEADER_SIZE,
    SIGNATURE_SIZE,
    PASSPORT_HASH_SIZE,
    MAX_FRAME_SIZE,
    FRAME_TIMEOUT_SECONDS,
    PING_INTERVAL_SECONDS,
    PING_TIMEOUT_SECONDS,
    serialize_payload,
    deserialize_payload,
    compute_passport_hash,
)
from lastbastion.protocol.handshake import (
    HandshakeInitiator,
    HandshakeResponder,
    HandshakeResult,
    SessionKeys,
    DirectHandshakeInitiator,
    DirectHandshakeResponder,
    ResumptionResponder,
    build_resume,
    complete_resume,
)

logger = logging.getLogger("BASTION_SOCKET")

# Default max stream size: 256MB
DEFAULT_MAX_STREAM_SIZE = 256 * 1024 * 1024


def _resolve_host(host: str) -> str:
    """
    Rewrites the literal string "localhost" to "127.0.0.1".

    On Windows (and some other dual-stack configurations), resolving
    "localhost" through asyncio.open_connection() can take ~2 SECONDS before
    falling back from a slow/blocked IPv6 (::1) attempt to IPv4 -- measured
    directly: 2033ms for "localhost" vs 3ms for "127.0.0.1" on the same
    machine, same process, same everything else. That's not protocol cost,
    it's hostname resolution, and it's large enough to completely swamp any
    real handshake-latency measurement. Any other hostname/IP is left as-is.
    """
    return "127.0.0.1" if host == "localhost" else host


# ---------------------------------------------------------------------------
# Peer Info
# ---------------------------------------------------------------------------

@dataclass
class PeerInfo:
    """Information about the connected peer agent."""
    agent_id: str = ""
    agent_name: str = ""
    trust_score: float = 0.0
    trust_level: str = ""
    verdict: str = ""
    passport_id: str = ""
    passport_hash: bytes = b""


# ---------------------------------------------------------------------------
# Observability Hooks
# ---------------------------------------------------------------------------

@dataclass
class ProtocolMetrics:
    """Counters for protocol observability."""
    frames_sent: int = 0
    frames_received: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0
    errors: int = 0
    pings_sent: int = 0
    pongs_received: int = 0


# ---------------------------------------------------------------------------
# Agent Connection
# ---------------------------------------------------------------------------

class AgentConnection:
    """
    A single authenticated agent-to-agent connection.

    Provides send/recv with automatic encryption, signing, and verification.
    Safe for concurrent callers on the same connection: send()/send_stream()
    serialize against each other via _send_lock (held for the whole
    operation, not per-frame -- send_stream used to release and reacquire
    the lock between chunks, letting a concurrent send() interleave a frame
    into the middle of a stream), and recv()/recv_stream() serialize the
    same way via _recv_lock. Not thread-safe across OS threads -- this is
    an asyncio.Lock, which only serializes coroutines on the same event
    loop, not real threads.
    Created by AgentSocket -- not instantiated directly.
    """

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        encoder: FrameEncoder,
        decoder: FrameDecoder,
        session_keys: SessionKeys,
        peer: PeerInfo,
        local_passport: AgentPassport,
        max_stream_size: int = DEFAULT_MAX_STREAM_SIZE,
        on_frame_sent: Optional[Callable] = None,
        on_frame_received: Optional[Callable] = None,
        trusted_transport: bool = False,
    ):
        """
        trusted_transport: when True, DATA/PING/PONG/CLOSE frames skip NaCl
        SecretBox encryption entirely -- zero encryption, zero integrity/MAC
        on the payload. Encryption defends against a hostile network between
        two points; if the transport itself is one you control end-to-end
        (same host, a private network segment with no untrusted hop), there
        is no such network to defend against and the crypto is pure cost
        with no security benefit -- measured as ~60% of Bastion's per-message
        CPU cost. The handshake (identity proof, key pinning) is completely
        unaffected either way. This is opt-in and defaults False: it must be
        a deliberate choice about the transport, not an assumption.
        """
        self._reader = reader
        self._writer = writer
        self._encoder = encoder
        self._decoder = decoder
        self._session = session_keys
        self._trusted_transport = trusted_transport
        self._encrypt_func = None if trusted_transport else self._session.encrypt
        self._decrypt_func = None if trusted_transport else self._session.decrypt
        self.peer = peer
        self.local_passport = local_passport
        self._closed = False
        self._ping_task: Optional[asyncio.Task] = None
        self._send_lock = asyncio.Lock()
        self._recv_lock = asyncio.Lock()
        self._max_stream_size = max_stream_size
        self.metrics = ProtocolMetrics()
        self._last_activity = time.monotonic()
        self._last_ping_sent = time.monotonic()
        self._on_frame_sent = on_frame_sent
        self._on_frame_received = on_frame_received
        self._disable_nagle()

    def _disable_nagle(self) -> None:
        """
        Disables Nagle's algorithm (TCP_NODELAY) on the underlying socket.
        Frames are already explicitly length-prefixed and written as a single
        buffered write+drain, so there's nothing to gain from Nagle batching
        them with a future write -- only latency to lose on small messages.
        Best-effort: some transports (e.g. in tests) may not expose a real
        socket, so failures here are non-fatal.
        """
        try:
            import socket as _socket
            sock = self._writer.get_extra_info("socket")
            if sock is not None:
                sock.setsockopt(_socket.IPPROTO_TCP, _socket.TCP_NODELAY, 1)
        except (OSError, AttributeError):
            pass

    @property
    def is_closed(self) -> bool:
        return self._closed

    async def send(self, data: dict) -> None:
        """Send a DATA frame with a dict payload."""
        if self._closed:
            raise ConnectionError("Connection is closed")
        frame = self._encoder.encode_data(data, self._encrypt_func)
        await self._write_frame(frame)

    async def recv(self) -> dict:
        """Receive the next DATA frame payload as a dict."""
        while True:
            frame = await self._read_frame()
            if frame.msg_type == FrameType.DATA:
                return deserialize_payload(frame.payload)
            elif frame.msg_type == FrameType.PING:
                await self._send_pong()
            elif frame.msg_type == FrameType.PONG:
                continue  # Consumed by keepalive
            elif frame.msg_type == FrameType.CLOSE:
                # Bidirectional CLOSE: send CLOSE back
                try:
                    close_frame = self._encoder.encode_close(self._encrypt_func)
                    await self._write_frame_raw(close_frame)
                except Exception:
                    pass
                self._closed = True
                raise ConnectionError("Peer closed connection")
            elif frame.msg_type == FrameType.ERROR:
                self.metrics.errors += 1
                error_data = deserialize_payload(frame.payload)
                raise ConnectionError(
                    f"Peer error {error_data.get('code', '?')}: "
                    f"{error_data.get('message', 'unknown')}"
                )
            elif frame.msg_type == FrameType.DATA_ACK:
                continue  # ACK handling
            else:
                logger.warning(f"Unexpected frame type: 0x{frame.msg_type:02x}")

    async def send_stream(self, data: bytes, chunk_size: int = 1024 * 1024) -> None:
        """Send large binary data as a stream of chunks.

        Holds _send_lock for the WHOLE operation, not per-frame -- the old
        per-frame locking let a concurrent send()/send_stream() on the same
        connection interleave its frames into the middle of this stream,
        since the lock was released and reacquired between every chunk.
        Uses _write_frame_raw() (no locking) internally since the lock is
        already held for the duration; calling _write_frame() here would
        try to reacquire the same non-reentrant asyncio.Lock and deadlock.
        """
        if self._closed:
            raise ConnectionError("Connection is closed")

        import os
        stream_id = os.urandom(4)
        total_size = len(data)
        chunk_count = (total_size + chunk_size - 1) // chunk_size
        content_hash = hashlib.sha256(data).digest()

        async with self._send_lock:
            # STREAM_START
            start_payload = serialize_payload({
                "stream_id": stream_id,
                "total_size": total_size,
                "chunk_count": chunk_count,
                "content_hash": content_hash,
            })
            start_frame = self._encoder.encode(
                FrameType.STREAM_START, start_payload, self._encrypt_func
            )
            await self._write_frame_raw(start_frame)

            # STREAM_CHUNKs
            for i in range(chunk_count):
                offset = i * chunk_size
                chunk = data[offset:offset + chunk_size]
                chunk_payload = serialize_payload({
                    "stream_id": stream_id,
                    "chunk_index": i,
                    "data": chunk,
                })
                chunk_frame = self._encoder.encode(
                    FrameType.STREAM_CHUNK, chunk_payload, self._encrypt_func
                )
                await self._write_frame_raw(chunk_frame)

            # STREAM_END
            end_payload = serialize_payload({
                "stream_id": stream_id,
                "final_hash": content_hash,
            })
            end_frame = self._encoder.encode(
                FrameType.STREAM_END, end_payload, self._encrypt_func
            )
            await self._write_frame_raw(end_frame)

    async def recv_stream(self) -> bytes:
        """Receive a streamed payload. Returns reassembled bytes.

        Holds _recv_lock for the WHOLE operation (see send_stream's
        docstring for why) and uses _read_frame_raw() internally to avoid
        deadlocking on the already-held lock. Also validates every
        STREAM_CHUNK/STREAM_END's stream_id against the STREAM_START that
        opened this call -- previously chunks were placed by chunk_index
        alone with no check that they belonged to THIS stream at all, which
        combined with the per-frame locking bug meant two concurrent
        streams could silently interleave and corrupt each other's data
        with no exception raised.
        """
        async with self._recv_lock:
            # Wait for STREAM_START
            frame = await self._read_frame_raw()
            if frame.msg_type != FrameType.STREAM_START:
                raise ConnectionError(f"Expected STREAM_START, got 0x{frame.msg_type:02x}")

            start_data = deserialize_payload(frame.payload)
            stream_id = start_data["stream_id"]
            if isinstance(stream_id, list):
                stream_id = bytes(stream_id)
            expected_chunks = start_data["chunk_count"]
            expected_hash = start_data["content_hash"]
            total_size = start_data.get("total_size", 0)
            if isinstance(expected_hash, list):
                expected_hash = bytes(expected_hash)

            # Enforce stream size cap
            if total_size > self._max_stream_size:
                raise ConnectionError(
                    f"Stream too large: {total_size} bytes "
                    f"(max {self._max_stream_size})"
                )

            # Receive chunks
            chunks = [None] * expected_chunks
            for _ in range(expected_chunks):
                chunk_frame = await self._read_frame_raw()
                if chunk_frame.msg_type == FrameType.PING:
                    pong = self._encoder.encode_pong(self._encrypt_func)
                    async with self._send_lock:
                        await self._write_frame_raw(pong)
                    chunk_frame = await self._read_frame_raw()
                if chunk_frame.msg_type != FrameType.STREAM_CHUNK:
                    raise ConnectionError(f"Expected STREAM_CHUNK, got 0x{chunk_frame.msg_type:02x}")
                chunk_data = deserialize_payload(chunk_frame.payload)
                chunk_stream_id = chunk_data["stream_id"]
                if isinstance(chunk_stream_id, list):
                    chunk_stream_id = bytes(chunk_stream_id)
                if chunk_stream_id != stream_id:
                    raise ConnectionError(
                        f"STREAM_CHUNK belongs to a different stream "
                        f"({chunk_stream_id.hex()} != {stream_id.hex()})"
                    )
                idx = chunk_data["chunk_index"]
                chunk_bytes = chunk_data["data"]
                if isinstance(chunk_bytes, list):
                    chunk_bytes = bytes(chunk_bytes)
                chunks[idx] = chunk_bytes

            # Wait for STREAM_END
            end_frame = await self._read_frame_raw()
            if end_frame.msg_type != FrameType.STREAM_END:
                raise ConnectionError(f"Expected STREAM_END, got 0x{end_frame.msg_type:02x}")
            end_data = deserialize_payload(end_frame.payload)
            end_stream_id = end_data["stream_id"]
            if isinstance(end_stream_id, list):
                end_stream_id = bytes(end_stream_id)
            if end_stream_id != stream_id:
                raise ConnectionError(
                    f"STREAM_END belongs to a different stream "
                    f"({end_stream_id.hex()} != {stream_id.hex()})"
                )

            # Reassemble and verify hash
            assembled = b"".join(chunks)
            actual_hash = hashlib.sha256(assembled).digest()
            if actual_hash != expected_hash:
                raise ConnectionError("Stream hash mismatch -- data corrupted or tampered")

            return assembled

    async def close(self):
        """Clean bidirectional shutdown: send CLOSE, wait for CLOSE back."""
        if self._closed:
            return
        try:
            close_frame = self._encoder.encode_close(self._encrypt_func)
            await self._write_frame_raw(close_frame)
            # Wait briefly for peer's CLOSE response
            try:
                peer_close = await asyncio.wait_for(
                    self._read_frame_raw(), timeout=2.0
                )
                # Peer sent CLOSE back -- clean shutdown
            except (asyncio.TimeoutError, ConnectionError, Exception):
                pass  # Peer didn't respond, proceed with teardown
        except Exception:
            pass
        self._closed = True
        if self._ping_task:
            self._ping_task.cancel()
        self._session.destroy()
        self._writer.close()

    # How often the watchdog checks for a stalled connection. Deliberately
    # tighter than PING_INTERVAL_SECONDS -- this cadence only costs a cheap
    # background wakeup, unlike the old per-read wait_for it replaces, which
    # cost real overhead on every single frame.
    _WATCHDOG_CHECK_INTERVAL_SECONDS = 2.0

    def start_keepalive(self):
        """Start background PING/PONG + dead-connection watchdog loop."""
        self._ping_task = asyncio.ensure_future(self._keepalive_loop())

    async def _keepalive_loop(self):
        """
        Two jobs on one background loop:
        1. Watchdog: if no frame has arrived from the peer in longer than
           FRAME_TIMEOUT_SECONDS + PING_INTERVAL_SECONDS, force-close the
           connection. This is what replaced the old per-read
           asyncio.wait_for() timeout in _read_frame_raw() -- same bounded-
           time dead-peer guarantee, but checked periodically in the
           background instead of wrapping every single read.
        2. Keepalive: send a PING every PING_INTERVAL_SECONDS so an otherwise
           idle-but-healthy connection doesn't look stalled to the peer.
        """
        while not self._closed:
            await asyncio.sleep(self._WATCHDOG_CHECK_INTERVAL_SECONDS)
            if self._closed:
                break

            idle = time.monotonic() - self._last_activity
            if idle > FRAME_TIMEOUT_SECONDS + PING_INTERVAL_SECONDS:
                self._closed = True
                try:
                    self._writer.close()
                except Exception:
                    pass
                break

            if time.monotonic() - self._last_ping_sent >= PING_INTERVAL_SECONDS:
                try:
                    ping = self._encoder.encode_ping(self._encrypt_func)
                    await self._write_frame(ping)
                    self.metrics.pings_sent += 1
                    self._last_ping_sent = time.monotonic()
                except Exception:
                    self._closed = True
                    break

    async def _send_pong(self):
        """Respond to a PING."""
        pong = self._encoder.encode_pong(self._encrypt_func)
        await self._write_frame(pong)

    async def _write_frame(self, frame: BastionFrame):
        """Write a frame to the wire (with send lock)."""
        async with self._send_lock:
            await self._write_frame_raw(frame)

    async def _write_frame_raw(self, frame: BastionFrame):
        """Write a frame to the wire (no lock -- internal use)."""
        data = frame.to_bytes()
        self._writer.write(len(data).to_bytes(4, "big") + data)
        await self._writer.drain()
        self.metrics.frames_sent += 1
        self.metrics.bytes_sent += len(data) + 4
        if self._on_frame_sent:
            try:
                self._on_frame_sent(frame)
            except Exception:
                pass

    async def _read_frame(self) -> BastionFrame:
        """Read a frame from the wire with timeout enforcement (with recv lock)."""
        async with self._recv_lock:
            return await self._read_frame_raw()

    async def _read_length_and_body(self) -> bytes:
        """Reads the 4-byte length prefix then the frame body. No timeout of
        its own -- the caller wraps this whole thing in one asyncio.wait_for."""
        length_bytes = await self._reader.readexactly(4)
        frame_length = int.from_bytes(length_bytes, "big")

        if frame_length > MAX_FRAME_SIZE + FRAME_HEADER_SIZE + SIGNATURE_SIZE:
            raise ConnectionError(f"Frame too large: {frame_length}")

        return await self._reader.readexactly(frame_length)

    async def _read_frame_raw(self) -> BastionFrame:
        """
        Read a frame from the wire (no lock -- internal use).

        No per-read asyncio.wait_for() here -- measured at ~15-20us of real,
        avoidable overhead per call (task + timer setup), and it ran on every
        single frame read on both ends of every round trip. A hung/dead peer
        is instead caught by the watchdog in _keepalive_loop(), which
        periodically checks how long it's been since a frame last arrived and
        force-closes the connection if that exceeds the same timeout this
        used to enforce inline. Closing self._writer from that separate task
        reliably unblocks a read that's stuck here (verified: raises
        IncompleteReadError, the same exception this already handles) --
        same bounded-time dead-connection guarantee, without paying the
        wait_for tax on every single healthy read.
        """
        try:
            frame_data = await self._read_length_and_body()
        except (asyncio.IncompleteReadError, ConnectionError, OSError) as e:
            # Covers both a clean EOF (IncompleteReadError) and a forced
            # close from the watchdog, which platforms report differently --
            # e.g. ConnectionResetError (a ConnectionError subclass) on
            # Windows when the watchdog closes the socket out from under a
            # pending read. Same outcome either way: the connection is dead.
            self._closed = True
            raise ConnectionError("Connection lost during frame read") from e

        self._last_activity = time.monotonic()
        frame = self._decoder.decode(frame_data, self._decrypt_func)
        self.metrics.frames_received += 1
        self.metrics.bytes_received += len(frame_data) + 4
        if frame.msg_type == FrameType.PONG:
            self.metrics.pongs_received += 1
        if self._on_frame_received:
            try:
                self._on_frame_received(frame)
            except Exception:
                pass
        return frame


# ---------------------------------------------------------------------------
# AgentSocket -- The Public API
# ---------------------------------------------------------------------------

class AgentSocket:
    """
    Agent-to-agent communication socket.

    Two modes:
    - AgentSocket.listen() -- server, accepts incoming agent connections
    - AgentSocket.connect() -- client, connects to a remote agent
    """

    @staticmethod
    async def connect(
        host: str,
        passport: AgentPassport,
        signing_key: str,
        verify_key: str,
        port: int = 9100,
        max_stream_size: int = DEFAULT_MAX_STREAM_SIZE,
        on_frame_sent: Optional[Callable] = None,
        on_frame_received: Optional[Callable] = None,
    ) -> AgentConnection:
        """
        Connect to a remote agent and perform handshake.

        Args:
            host: Remote host (hostname or IP). Can include port as "host:port".
            passport: This agent's passport
            signing_key: Ed25519 private key for signing
            verify_key: Ed25519 public key for verifying peer's passport JWT (REQUIRED)
            port: Port number (default 9100, overridden if host contains port)
            max_stream_size: Maximum stream size in bytes (default 256MB)
            on_frame_sent: Optional callback(frame) for observability
            on_frame_received: Optional callback(frame) for observability

        Returns:
            Authenticated AgentConnection
        """
        # Parse host:port
        if ":" in host:
            parts = host.rsplit(":", 1)
            host = parts[0]
            port = int(parts[1])

        reader, writer = await asyncio.open_connection(_resolve_host(host), port)

        try:
            # Perform handshake
            initiator = HandshakeInitiator(passport, signing_key, verify_key)
            hello_frame = initiator.build_hello()

            # Send HELLO
            frame_bytes = hello_frame.to_bytes()
            writer.write(len(frame_bytes).to_bytes(4, "big") + frame_bytes)
            await writer.drain()

            # Receive HELLO_ACK
            length_bytes = await asyncio.wait_for(
                reader.readexactly(4), timeout=FRAME_TIMEOUT_SECONDS
            )
            ack_length = int.from_bytes(length_bytes, "big")
            ack_data = await asyncio.wait_for(
                reader.readexactly(ack_length), timeout=FRAME_TIMEOUT_SECONDS
            )
            ack_frame = BastionFrame.from_bytes(ack_data)

            # Complete handshake
            result = initiator.complete(ack_frame)
            result.finalize()  # Destroy ephemeral keys

            # Build connection objects
            passport_hash = compute_passport_hash(passport.passport_id)
            encoder = FrameEncoder(passport_hash, signing_key)
            decoder = FrameDecoder(result.peer_passport_hash, "")
            decoder._handshake_complete = True

            peer = PeerInfo(
                agent_id=result.peer_passport.agent_id,
                agent_name=result.peer_passport.agent_name,
                trust_score=result.peer_passport.trust_score,
                trust_level=result.peer_passport.trust_level,
                verdict=result.peer_passport.verdict,
                passport_id=result.peer_passport.passport_id,
                passport_hash=result.peer_passport_hash,
            )

            conn = AgentConnection(
                reader=reader,
                writer=writer,
                encoder=encoder,
                decoder=decoder,
                session_keys=result.session_keys,
                peer=peer,
                local_passport=passport,
                max_stream_size=max_stream_size,
                on_frame_sent=on_frame_sent,
                on_frame_received=on_frame_received,
            )
            conn.start_keepalive()
            return conn

        except Exception:
            writer.close()
            raise

    @staticmethod
    def listen(
        passport: AgentPassport,
        signing_key: str,
        verify_key: str,
        host: str = "0.0.0.0",
        port: int = 9100,
        min_trust_score: float = 0.0,
        max_stream_size: int = DEFAULT_MAX_STREAM_SIZE,
        on_frame_sent: Optional[Callable] = None,
        on_frame_received: Optional[Callable] = None,
    ) -> "AgentSocketServer":
        """
        Create a server that accepts incoming agent connections.

        Args:
            passport: This agent's passport
            signing_key: Ed25519 private key for signing
            verify_key: Ed25519 public key for verifying peer's passport JWT (REQUIRED)
            host: Bind address (default "0.0.0.0")
            port: Port number (default 9100)
            min_trust_score: Minimum trust score to accept connections
            max_stream_size: Maximum stream size in bytes (default 256MB)
            on_frame_sent: Optional callback(frame) for observability
            on_frame_received: Optional callback(frame) for observability

        Returns an AgentSocketServer -- call .on_connect(handler) then .start().
        """
        return AgentSocketServer(
            passport=passport,
            signing_key=signing_key,
            verify_key=verify_key,
            host=host,
            port=port,
            min_trust_score=min_trust_score,
            max_stream_size=max_stream_size,
            on_frame_sent=on_frame_sent,
            on_frame_received=on_frame_received,
        )


class AgentSocketServer:
    """
    Server that listens for incoming Bastion Protocol connections.

    Usage:
        server = AgentSocket.listen(port=9100, passport=p, signing_key=k, verify_key=v)
        server.on_connect(my_handler)
        await server.start()
    """

    def __init__(
        self,
        passport: AgentPassport,
        signing_key: str,
        verify_key: str,
        host: str = "0.0.0.0",
        port: int = 9100,
        min_trust_score: float = 0.0,
        max_stream_size: int = DEFAULT_MAX_STREAM_SIZE,
        on_frame_sent: Optional[Callable] = None,
        on_frame_received: Optional[Callable] = None,
    ):
        self.passport = passport
        self.signing_key = signing_key
        self.verify_key = verify_key
        self.host = host
        self.port = port
        self.min_trust_score = min_trust_score
        self._max_stream_size = max_stream_size
        self._handler = None
        self._server = None
        self._connections: List[AgentConnection] = []
        self._on_frame_sent = on_frame_sent
        self._on_frame_received = on_frame_received

    def on_connect(self, handler: Callable[[AgentConnection], Coroutine]):
        """Register a handler called for each new authenticated connection."""
        self._handler = handler

    @property
    def active_connections(self) -> int:
        """Count of currently active (non-closed) connections."""
        return sum(1 for c in self._connections if not c.is_closed)

    async def start(self):
        """Start listening. Blocks until server is closed."""
        if not self._handler:
            raise RuntimeError("No handler registered -- call .on_connect() first")

        self._server = await asyncio.start_server(
            self._handle_client, self.host, self.port
        )
        logger.info(f"Bastion Protocol server listening on {self.host}:{self.port}")

        async with self._server:
            await self._server.serve_forever()

    async def start_background(self):
        """Start listening in the background. Returns immediately."""
        if not self._handler:
            raise RuntimeError("No handler registered -- call .on_connect() first")

        self._server = await asyncio.start_server(
            self._handle_client, self.host, self.port
        )
        logger.info(f"Bastion Protocol server listening on {self.host}:{self.port}")

    async def stop(self):
        """Stop the server and close all connections."""
        if self._server:
            self._server.close()
            await self._server.wait_closed()
        for conn in self._connections:
            await conn.close()
        self._connections.clear()

    def _cleanup_closed(self):
        """Remove closed connections from the tracking list."""
        self._connections = [c for c in self._connections if not c.is_closed]

    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ):
        """Handle an incoming connection: handshake then delegate to handler."""
        conn = None
        try:
            # Clean up stale connections
            self._cleanup_closed()

            # Read HELLO
            length_bytes = await asyncio.wait_for(
                reader.readexactly(4), timeout=FRAME_TIMEOUT_SECONDS
            )
            hello_length = int.from_bytes(length_bytes, "big")
            hello_data = await asyncio.wait_for(
                reader.readexactly(hello_length), timeout=FRAME_TIMEOUT_SECONDS
            )
            hello_frame = BastionFrame.from_bytes(hello_data)

            if hello_frame.msg_type != FrameType.HELLO:
                writer.close()
                return

            # Process handshake
            responder = HandshakeResponder(
                self.passport, self.signing_key, self.verify_key, self.min_trust_score
            )
            ack_frame, result = responder.process_hello(hello_frame)

            # Send HELLO_ACK
            ack_bytes = ack_frame.to_bytes()
            writer.write(len(ack_bytes).to_bytes(4, "big") + ack_bytes)
            await writer.drain()

            result.finalize()  # Destroy ephemeral keys

            # Build connection
            passport_hash = compute_passport_hash(self.passport.passport_id)
            encoder = FrameEncoder(passport_hash, self.signing_key)
            decoder = FrameDecoder(result.peer_passport_hash, "")
            decoder._handshake_complete = True

            peer = PeerInfo(
                agent_id=result.peer_passport.agent_id,
                agent_name=result.peer_passport.agent_name,
                trust_score=result.peer_passport.trust_score,
                trust_level=result.peer_passport.trust_level,
                verdict=result.peer_passport.verdict,
                passport_id=result.peer_passport.passport_id,
                passport_hash=result.peer_passport_hash,
            )

            conn = AgentConnection(
                reader=reader,
                writer=writer,
                encoder=encoder,
                decoder=decoder,
                session_keys=result.session_keys,
                peer=peer,
                local_passport=self.passport,
                max_stream_size=self._max_stream_size,
                on_frame_sent=self._on_frame_sent,
                on_frame_received=self._on_frame_received,
            )
            conn.start_keepalive()
            self._connections.append(conn)

            # Delegate to user handler
            await self._handler(conn)

        except ValueError as e:
            logger.warning(f"Handshake rejected: {e}")
            writer.close()
        except asyncio.TimeoutError:
            logger.warning("Handshake timeout")
            writer.close()
        except Exception as e:
            logger.error(f"Connection error: {e}")
            writer.close()
        finally:
            # Clean up if connection was established but handler failed
            if conn and not conn.is_closed:
                try:
                    await conn.close()
                except Exception:
                    pass


# ---------------------------------------------------------------------------
# DirectAgentSocket -- DIRECT mode (no passport office) + session resumption
# ---------------------------------------------------------------------------
#
# Same developer-facing shape as AgentSocket, but:
#   - authentication is key-pinning (PeerTrustStore) instead of an
#     issuer-signed passport (see handshake.py's DIRECT mode section)
#   - session resumption is automatic when a ticket is supplied to connect():
#     resumption is attempted first, and on any rejection (expired/replayed/
#     unknown ticket) this transparently reconnects and falls back to a fresh
#     DIRECT handshake -- callers never need to handle that fallback manually
#
# Deliberately does NOT touch AgentConnection or the existing PASSPORT-mode
# AgentSocket/AgentSocketServer above -- those stay exactly as they were.

class DirectAgentSocket:
    """
    Agent-to-agent communication socket for DIRECT mode.

    Client:
        conn, ticket, secret = await DirectAgentSocket.connect(
            "host:port", agent_id="my-agent", public_key=pub, signing_key=priv,
            trust_store=store,
        )
        # store (ticket, secret) somewhere; next time, pass them back in to
        # skip the full handshake:
        conn, ticket, secret = await DirectAgentSocket.connect(
            "host:port", agent_id="my-agent", public_key=pub, signing_key=priv,
            trust_store=store, resume_ticket=ticket, resumption_secret=secret,
        )

    Server:
        server = DirectAgentSocket.listen(
            port=9100, agent_id="my-agent", public_key=pub, signing_key=priv,
            trust_store=store, ticket_key=ticket_key,  # omit ticket_key to disable resumption
        )
        server.on_connect(handle)
        await server.start()
    """

    @staticmethod
    async def connect(
        host: str,
        agent_id: str,
        public_key: str,
        signing_key: str,
        trust_store,
        port: int = 9100,
        tofu: bool = True,
        resume_ticket: Optional[bytes] = None,
        resumption_secret: Optional[bytes] = None,
        max_stream_size: int = DEFAULT_MAX_STREAM_SIZE,
        on_frame_sent: Optional[Callable] = None,
        on_frame_received: Optional[Callable] = None,
        trusted_transport: bool = False,
    ):
        """
        Connect using DIRECT mode.

        If resume_ticket AND resumption_secret are both provided, attempts
        session resumption first (skips the full X25519 handshake). On
        rejection (ticket expired/already used/unknown to this server), this
        automatically reconnects fresh with a full DIRECT handshake instead
        -- callers don't need to implement that fallback themselves.

        trusted_transport: opt-in, defaults False. When True, post-handshake
        DATA/PING/PONG/CLOSE frames skip NaCl SecretBox encryption entirely
        -- see AgentConnection's docstring for the tradeoff. Only set this
        for connections you know stay within a network you control end-to-
        end (e.g. same host, a private network segment with no untrusted
        hop) -- the handshake/identity verification is unaffected either
        way, only the ongoing traffic's confidentiality/integrity is. Must
        match on both ends of the connection (server's listen() call needs
        the same setting) or decode will simply fail on garbled payloads.

        Returns (connection, next_ticket, resumption_secret).
        next_ticket is None if the server isn't configured for resumption
        (no ticket_key). resumption_secret does NOT change across a ticket's
        rotation lineage -- store both alongside each other and pass the
        latest ticket back in on the next connect() call.
        """
        if ":" in host:
            parts = host.rsplit(":", 1)
            host = parts[0]
            port = int(parts[1])
        host = _resolve_host(host)

        if resume_ticket is not None and resumption_secret is not None:
            try:
                return await DirectAgentSocket._connect_resume(
                    host, port, signing_key, resume_ticket, resumption_secret,
                    max_stream_size, on_frame_sent, on_frame_received, trusted_transport,
                )
            except (ValueError, ConnectionError, OSError) as e:
                logger.info(f"Resumption failed ({e}), falling back to fresh DIRECT handshake")

        return await DirectAgentSocket._connect_fresh(
            host, port, agent_id, public_key, signing_key, trust_store, tofu,
            max_stream_size, on_frame_sent, on_frame_received, trusted_transport,
        )

    @staticmethod
    async def _connect_fresh(
        host, port, agent_id, public_key, signing_key, trust_store, tofu,
        max_stream_size, on_frame_sent, on_frame_received, trusted_transport=False,
    ):
        reader, writer = await asyncio.open_connection(host, port)
        try:
            initiator = DirectHandshakeInitiator(agent_id, public_key, signing_key, trust_store)
            hello_frame = initiator.build_hello()
            frame_bytes = hello_frame.to_bytes()
            writer.write(len(frame_bytes).to_bytes(4, "big") + frame_bytes)
            await writer.drain()

            length_bytes = await asyncio.wait_for(
                reader.readexactly(4), timeout=FRAME_TIMEOUT_SECONDS
            )
            ack_length = int.from_bytes(length_bytes, "big")
            ack_data = await asyncio.wait_for(
                reader.readexactly(ack_length), timeout=FRAME_TIMEOUT_SECONDS
            )
            ack_frame = BastionFrame.from_bytes(ack_data)

            if ack_frame.msg_type == FrameType.ERROR:
                error_data = deserialize_payload(ack_frame.payload)
                raise ValueError(f"HELLO rejected: {error_data.get('message', 'unknown')}")

            result = initiator.complete(ack_frame, tofu=tofu)
            result.finalize()

            passport_hash = compute_passport_hash(agent_id)
            # sign_data_frames=False: post-handshake authenticity comes from
            # NaCl SecretBox's authenticated encryption, not a per-frame
            # Ed25519 signature the receiver never verifies anyway (verify_key
            # is empty below) -- signing for real here was pure wasted crypto
            # work, measured as the dominant cost in DATA-frame throughput.
            encoder = FrameEncoder(passport_hash, signing_key, sign_data_frames=False)
            decoder = FrameDecoder(b"", "")
            decoder._handshake_complete = True

            peer = PeerInfo(
                agent_id=result.peer_agent_id,
                agent_name=result.peer_agent_id,
                trust_level="DIRECT",
                verdict="DIRECT_NEW" if result.trust_pin.is_new else "DIRECT_PINNED",
            )

            local_passport = AgentPassport(agent_id=agent_id, public_key=public_key)
            conn = AgentConnection(
                reader=reader,
                writer=writer,
                encoder=encoder,
                decoder=decoder,
                session_keys=result.session_keys,
                peer=peer,
                local_passport=local_passport,
                max_stream_size=max_stream_size,
                on_frame_sent=on_frame_sent,
                on_frame_received=on_frame_received,
                trusted_transport=trusted_transport,
            )
            conn.start_keepalive()
            return conn, result.session_ticket, result.resumption_secret

        except Exception:
            writer.close()
            raise

    @staticmethod
    async def _connect_resume(
        host, port, signing_key, ticket, resumption_secret,
        max_stream_size, on_frame_sent, on_frame_received, trusted_transport=False,
    ):
        import os as _os

        reader, writer = await asyncio.open_connection(host, port)
        try:
            client_nonce = _os.urandom(32)
            resume_frame = build_resume(ticket, client_nonce)
            frame_bytes = resume_frame.to_bytes()
            writer.write(len(frame_bytes).to_bytes(4, "big") + frame_bytes)
            await writer.drain()

            length_bytes = await asyncio.wait_for(
                reader.readexactly(4), timeout=FRAME_TIMEOUT_SECONDS
            )
            resp_length = int.from_bytes(length_bytes, "big")
            resp_data = await asyncio.wait_for(
                reader.readexactly(resp_length), timeout=FRAME_TIMEOUT_SECONDS
            )
            resp_frame = BastionFrame.from_bytes(resp_data)

            if resp_frame.msg_type == FrameType.ERROR:
                error_data = deserialize_payload(resp_frame.payload)
                raise ValueError(f"Resume rejected: {error_data.get('message', 'unknown')}")

            session_keys, next_ticket = complete_resume(resp_frame, client_nonce, resumption_secret)

            # RESUME_ACK carries only server_nonce + next_ticket, not the
            # peer's agent_id -- the caller already knows who they resumed
            # with (they supplied a ticket scoped to that specific peer).
            peer = PeerInfo(trust_level="DIRECT", verdict="RESUMED")

            encoder = FrameEncoder(b"\x00" * PASSPORT_HASH_SIZE, signing_key, sign_data_frames=False)
            decoder = FrameDecoder(b"", "")
            decoder._handshake_complete = True

            conn = AgentConnection(
                reader=reader,
                writer=writer,
                encoder=encoder,
                decoder=decoder,
                session_keys=session_keys,
                peer=peer,
                local_passport=None,
                max_stream_size=max_stream_size,
                on_frame_sent=on_frame_sent,
                on_frame_received=on_frame_received,
                trusted_transport=trusted_transport,
            )
            conn.start_keepalive()
            return conn, next_ticket, resumption_secret

        except Exception:
            writer.close()
            raise

    @staticmethod
    def listen(
        agent_id: str,
        public_key: str,
        signing_key: str,
        trust_store,
        host: str = "0.0.0.0",
        port: int = 9100,
        tofu: bool = True,
        ticket_key: Optional[bytes] = None,
        revocation_check: Optional[Callable] = None,
        max_stream_size: int = DEFAULT_MAX_STREAM_SIZE,
        on_frame_sent: Optional[Callable] = None,
        on_frame_received: Optional[Callable] = None,
        trusted_transport: bool = False,
    ) -> "DirectAgentSocketServer":
        """
        Create a server that accepts incoming DIRECT-mode connections.

        ticket_key: omit to run without resumption support (every connection
        does a full handshake). Pass one (crypto.load_or_create_symmetric_key)
        to let peers resume sessions.
        revocation_check: optional callable(agent_id) -> bool, forwarded to
        the ResumptionResponder used for resumed connections (see handshake.py
        -- resumed sessions skip full re-verification by design, so wire this
        if a revoked agent must be locked out before its tickets naturally expire).
        trusted_transport: opt-in, defaults False -- see DirectAgentSocket.connect's
        docstring. Must match what clients pass to connect(), or decode will
        simply fail on garbled payloads (one side encrypting, the other not).
        """
        return DirectAgentSocketServer(
            agent_id=agent_id,
            public_key=public_key,
            signing_key=signing_key,
            trust_store=trust_store,
            host=host,
            port=port,
            tofu=tofu,
            ticket_key=ticket_key,
            revocation_check=revocation_check,
            max_stream_size=max_stream_size,
            on_frame_sent=on_frame_sent,
            on_frame_received=on_frame_received,
            trusted_transport=trusted_transport,
        )


class DirectAgentSocketServer:
    """Server that listens for incoming DIRECT-mode Bastion Protocol connections."""

    def __init__(
        self,
        agent_id: str,
        public_key: str,
        signing_key: str,
        trust_store,
        host: str = "0.0.0.0",
        port: int = 9100,
        tofu: bool = True,
        ticket_key: Optional[bytes] = None,
        revocation_check: Optional[Callable] = None,
        max_stream_size: int = DEFAULT_MAX_STREAM_SIZE,
        on_frame_sent: Optional[Callable] = None,
        on_frame_received: Optional[Callable] = None,
        trusted_transport: bool = False,
    ):
        self.agent_id = agent_id
        self.public_key = public_key
        self.signing_key = signing_key
        self.trust_store = trust_store
        self.host = host
        self.port = port
        self.tofu = tofu
        self.ticket_key = ticket_key
        self.revocation_check = revocation_check
        self.trusted_transport = trusted_transport
        self._max_stream_size = max_stream_size
        self._handler = None
        self._server = None
        self._connections: List[AgentConnection] = []
        self._on_frame_sent = on_frame_sent
        self._on_frame_received = on_frame_received
        self._resumption_responder = (
            ResumptionResponder(ticket_key, revocation_check=revocation_check)
            if ticket_key is not None else None
        )

    def on_connect(self, handler: Callable[[AgentConnection], Coroutine]):
        self._handler = handler

    @property
    def active_connections(self) -> int:
        return sum(1 for c in self._connections if not c.is_closed)

    async def start(self):
        if not self._handler:
            raise RuntimeError("No handler registered -- call .on_connect() first")
        self._server = await asyncio.start_server(self._handle_client, self.host, self.port)
        logger.info(f"Bastion Protocol (DIRECT) server listening on {self.host}:{self.port}")
        async with self._server:
            await self._server.serve_forever()

    async def start_background(self):
        if not self._handler:
            raise RuntimeError("No handler registered -- call .on_connect() first")
        self._server = await asyncio.start_server(self._handle_client, self.host, self.port)
        logger.info(f"Bastion Protocol (DIRECT) server listening on {self.host}:{self.port}")

    async def stop(self):
        if self._server:
            self._server.close()
            await self._server.wait_closed()
        for conn in self._connections:
            await conn.close()
        self._connections.clear()

    def _cleanup_closed(self):
        self._connections = [c for c in self._connections if not c.is_closed]

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        conn = None
        try:
            self._cleanup_closed()

            length_bytes = await asyncio.wait_for(reader.readexactly(4), timeout=FRAME_TIMEOUT_SECONDS)
            first_length = int.from_bytes(length_bytes, "big")
            first_data = await asyncio.wait_for(reader.readexactly(first_length), timeout=FRAME_TIMEOUT_SECONDS)
            first_frame = BastionFrame.from_bytes(first_data)

            if first_frame.msg_type == FrameType.RESUME:
                conn = await self._handle_resume(reader, writer, first_frame)
            elif first_frame.msg_type == FrameType.HELLO:
                conn = await self._handle_hello(reader, writer, first_frame)
            else:
                writer.close()
                return

            if conn is None:
                writer.close()
                return

            conn.start_keepalive()
            self._connections.append(conn)
            await self._handler(conn)

        except ValueError as e:
            logger.warning(f"DIRECT handshake rejected: {e}")
            writer.close()
        except asyncio.TimeoutError:
            logger.warning("DIRECT handshake timeout")
            writer.close()
        except Exception as e:
            logger.error(f"DIRECT connection error: {e}")
            writer.close()
        finally:
            if conn and not conn.is_closed:
                try:
                    await conn.close()
                except Exception:
                    pass

    async def _handle_hello(self, reader, writer, hello_frame) -> Optional[AgentConnection]:
        responder = DirectHandshakeResponder(
            self.agent_id, self.public_key, self.signing_key, self.trust_store,
            ticket_key=self.ticket_key,
        )
        try:
            ack_frame, result = responder.process_hello(hello_frame, tofu=self.tofu)
        except ValueError as e:
            await self._send_error(writer, str(e))
            return None

        ack_bytes = ack_frame.to_bytes()
        writer.write(len(ack_bytes).to_bytes(4, "big") + ack_bytes)
        await writer.drain()
        result.finalize()

        passport_hash = compute_passport_hash(self.agent_id)
        encoder = FrameEncoder(passport_hash, self.signing_key, sign_data_frames=False)
        decoder = FrameDecoder(b"", "")
        decoder._handshake_complete = True

        peer = PeerInfo(
            agent_id=result.peer_agent_id,
            agent_name=result.peer_agent_id,
            trust_level="DIRECT",
            verdict="DIRECT_NEW" if result.trust_pin.is_new else "DIRECT_PINNED",
        )
        local_passport = AgentPassport(agent_id=self.agent_id, public_key=self.public_key)
        return AgentConnection(
            reader=reader, writer=writer, encoder=encoder, decoder=decoder,
            session_keys=result.session_keys, peer=peer, local_passport=local_passport,
            max_stream_size=self._max_stream_size,
            on_frame_sent=self._on_frame_sent, on_frame_received=self._on_frame_received,
            trusted_transport=self.trusted_transport,
        )

    async def _handle_resume(self, reader, writer, resume_frame) -> Optional[AgentConnection]:
        if self._resumption_responder is None:
            await self._send_error(writer, "Resumption not supported by this server")
            return None
        try:
            ack_frame, result = self._resumption_responder.process_resume(resume_frame)
        except ValueError as e:
            await self._send_error(writer, str(e))
            return None

        ack_bytes = ack_frame.to_bytes()
        writer.write(len(ack_bytes).to_bytes(4, "big") + ack_bytes)
        await writer.drain()

        peer = PeerInfo(agent_id=result.peer_agent_id, agent_name=result.peer_agent_id,
                         trust_level="DIRECT", verdict="RESUMED")

        encoder = FrameEncoder(b"\x00" * PASSPORT_HASH_SIZE, self.signing_key, sign_data_frames=False)
        decoder = FrameDecoder(b"", "")
        decoder._handshake_complete = True

        return AgentConnection(
            reader=reader, writer=writer, encoder=encoder, decoder=decoder,
            session_keys=result.session_keys, peer=peer, local_passport=None,
            max_stream_size=self._max_stream_size,
            on_frame_sent=self._on_frame_sent, on_frame_received=self._on_frame_received,
            trusted_transport=self.trusted_transport,
        )

    async def _send_error(self, writer, message: str):
        try:
            payload = serialize_payload({"code": int(ErrorCode.GENERIC), "message": message})
            encoder = FrameEncoder(b"\x00" * PASSPORT_HASH_SIZE, "")
            error_frame = encoder.encode(FrameType.ERROR, payload)
            data = error_frame.to_bytes()
            writer.write(len(data).to_bytes(4, "big") + data)
            await writer.drain()
        except Exception:
            pass
        writer.close()
