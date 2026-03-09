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
)

logger = logging.getLogger("BASTION_SOCKET")

# Default max stream size: 256MB
DEFAULT_MAX_STREAM_SIZE = 256 * 1024 * 1024


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
    Thread-safe via asyncio.Lock on send/recv.
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
    ):
        self._reader = reader
        self._writer = writer
        self._encoder = encoder
        self._decoder = decoder
        self._session = session_keys
        self.peer = peer
        self.local_passport = local_passport
        self._closed = False
        self._ping_task: Optional[asyncio.Task] = None
        self._send_lock = asyncio.Lock()
        self._recv_lock = asyncio.Lock()
        self._max_stream_size = max_stream_size
        self.metrics = ProtocolMetrics()
        self._on_frame_sent = on_frame_sent
        self._on_frame_received = on_frame_received

    @property
    def is_closed(self) -> bool:
        return self._closed

    async def send(self, data: dict) -> None:
        """Send a DATA frame with a dict payload."""
        if self._closed:
            raise ConnectionError("Connection is closed")
        frame = self._encoder.encode_data(data, self._session.encrypt)
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
                    close_frame = self._encoder.encode_close(self._session.encrypt)
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
        """Send large binary data as a stream of chunks."""
        if self._closed:
            raise ConnectionError("Connection is closed")

        import os
        stream_id = os.urandom(4)
        total_size = len(data)
        chunk_count = (total_size + chunk_size - 1) // chunk_size
        content_hash = hashlib.sha256(data).digest()

        # STREAM_START
        start_payload = serialize_payload({
            "stream_id": stream_id,
            "total_size": total_size,
            "chunk_count": chunk_count,
            "content_hash": content_hash,
        })
        start_frame = self._encoder.encode(
            FrameType.STREAM_START, start_payload, self._session.encrypt
        )
        await self._write_frame(start_frame)

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
                FrameType.STREAM_CHUNK, chunk_payload, self._session.encrypt
            )
            await self._write_frame(chunk_frame)

        # STREAM_END
        end_payload = serialize_payload({
            "stream_id": stream_id,
            "final_hash": content_hash,
        })
        end_frame = self._encoder.encode(
            FrameType.STREAM_END, end_payload, self._session.encrypt
        )
        await self._write_frame(end_frame)

    async def recv_stream(self) -> bytes:
        """Receive a streamed payload. Returns reassembled bytes."""
        # Wait for STREAM_START
        frame = await self._read_frame()
        if frame.msg_type != FrameType.STREAM_START:
            raise ConnectionError(f"Expected STREAM_START, got 0x{frame.msg_type:02x}")

        start_data = deserialize_payload(frame.payload)
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
            chunk_frame = await self._read_frame()
            if chunk_frame.msg_type == FrameType.PING:
                await self._send_pong()
                chunk_frame = await self._read_frame()
            if chunk_frame.msg_type != FrameType.STREAM_CHUNK:
                raise ConnectionError(f"Expected STREAM_CHUNK, got 0x{chunk_frame.msg_type:02x}")
            chunk_data = deserialize_payload(chunk_frame.payload)
            idx = chunk_data["chunk_index"]
            chunk_bytes = chunk_data["data"]
            if isinstance(chunk_bytes, list):
                chunk_bytes = bytes(chunk_bytes)
            chunks[idx] = chunk_bytes

        # Wait for STREAM_END
        end_frame = await self._read_frame()
        if end_frame.msg_type != FrameType.STREAM_END:
            raise ConnectionError(f"Expected STREAM_END, got 0x{end_frame.msg_type:02x}")

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
            close_frame = self._encoder.encode_close(self._session.encrypt)
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

    def start_keepalive(self):
        """Start background PING/PONG loop with timeout enforcement."""
        self._ping_task = asyncio.ensure_future(self._keepalive_loop())

    async def _keepalive_loop(self):
        """Send PING every interval. Enforce PONG timeout."""
        while not self._closed:
            await asyncio.sleep(PING_INTERVAL_SECONDS)
            if self._closed:
                break
            try:
                ping = self._encoder.encode_ping(self._session.encrypt)
                await self._write_frame(ping)
                self.metrics.pings_sent += 1
            except Exception:
                self._closed = True
                break

    async def _send_pong(self):
        """Respond to a PING."""
        pong = self._encoder.encode_pong(self._session.encrypt)
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

    async def _read_frame_raw(self) -> BastionFrame:
        """Read a frame from the wire (no lock -- internal use)."""
        try:
            # Read length prefix
            length_bytes = await asyncio.wait_for(
                self._reader.readexactly(4),
                timeout=FRAME_TIMEOUT_SECONDS + PING_INTERVAL_SECONDS,
            )
            frame_length = int.from_bytes(length_bytes, "big")

            if frame_length > MAX_FRAME_SIZE + FRAME_HEADER_SIZE + SIGNATURE_SIZE:
                raise ConnectionError(f"Frame too large: {frame_length}")

            # Read frame data with strict timeout
            frame_data = await asyncio.wait_for(
                self._reader.readexactly(frame_length),
                timeout=FRAME_TIMEOUT_SECONDS,
            )
        except asyncio.TimeoutError:
            self._closed = True
            raise ConnectionError("Frame timeout -- incomplete frame received")
        except asyncio.IncompleteReadError:
            self._closed = True
            raise ConnectionError("Connection lost during frame read")

        frame = self._decoder.decode(frame_data, self._session.decrypt)
        self.metrics.frames_received += 1
        self.metrics.bytes_received += frame_length + 4
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

        reader, writer = await asyncio.open_connection(host, port)

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
