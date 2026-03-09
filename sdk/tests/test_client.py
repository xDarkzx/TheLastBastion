"""
SDK Unit Tests — covers client methods, crypto, passport, and error handling.

Run: cd sdk && python -m pytest tests/ -v
"""

import asyncio
import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from lastbastion.client import LastBastionClient
from lastbastion.crypto import (
    generate_keypair,
    sign_bytes,
    verify_signature,
    create_jwt,
    verify_jwt,
    compute_hash,
)
from lastbastion.exceptions import (
    AuthenticationError,
    NotFoundError,
    RateLimitError,
    ValidationError,
    LastBastionError,
    PassportError,
)
from lastbastion.passport import AgentPassport, generate_runtime_fingerprint


# ---------------------------------------------------------------------------
# Crypto Tests
# ---------------------------------------------------------------------------

class TestCrypto:
    def test_generate_keypair(self):
        pub, priv = generate_keypair()
        assert len(pub) == 64  # 32 bytes hex
        assert len(priv) == 64  # 32 bytes hex
        assert pub != priv

    def test_generate_keypair_uniqueness(self):
        pub1, _ = generate_keypair()
        pub2, _ = generate_keypair()
        assert pub1 != pub2

    def test_sign_and_verify(self):
        pub, priv = generate_keypair()
        data = b"hello world"
        sig = sign_bytes(data, priv)
        assert verify_signature(data, sig, pub)

    def test_verify_wrong_key_fails(self):
        _, priv = generate_keypair()
        pub2, _ = generate_keypair()
        sig = sign_bytes(b"test data", priv)
        assert not verify_signature(b"test data", sig, pub2)

    def test_verify_tampered_data_fails(self):
        pub, priv = generate_keypair()
        sig = sign_bytes(b"original", priv)
        assert not verify_signature(b"tampered", sig, pub)

    def test_sign_empty_bytes(self):
        pub, priv = generate_keypair()
        sig = sign_bytes(b"", priv)
        assert verify_signature(b"", sig, pub)

    def test_sign_large_data(self):
        pub, priv = generate_keypair()
        data = b"x" * 100_000
        sig = sign_bytes(data, priv)
        assert verify_signature(data, sig, pub)


class TestJWT:
    def test_create_and_verify_jwt(self):
        pub, priv = generate_keypair()
        claims = {"sub": "agent-001", "role": "DATA_PROVIDER"}
        token = create_jwt(claims, priv)
        decoded = verify_jwt(token, pub)
        assert decoded["sub"] == "agent-001"
        assert decoded["role"] == "DATA_PROVIDER"

    def test_jwt_wrong_key_fails(self):
        _, priv = generate_keypair()
        pub2, _ = generate_keypair()
        token = create_jwt({"sub": "test"}, priv)
        with pytest.raises(ValueError, match="signature verification failed"):
            verify_jwt(token, pub2)

    def test_jwt_expired(self):
        pub, priv = generate_keypair()
        import time
        claims = {"sub": "test", "exp": int(time.time()) - 100}
        token = create_jwt(claims, priv)
        with pytest.raises(ValueError, match="expired"):
            verify_jwt(token, pub)

    def test_jwt_invalid_format(self):
        pub, _ = generate_keypair()
        with pytest.raises(ValueError, match="Invalid JWT"):
            verify_jwt("not.a.valid.jwt.token", pub)


class TestHash:
    def test_compute_hash(self):
        h = compute_hash("hello")
        assert len(h) == 64  # SHA-256 hex
        assert h == compute_hash("hello")  # deterministic

    def test_hash_different_inputs(self):
        assert compute_hash("a") != compute_hash("b")


# ---------------------------------------------------------------------------
# Passport Tests
# ---------------------------------------------------------------------------

class TestPassport:
    def test_create_passport(self):
        pub, priv = generate_keypair()
        passport = AgentPassport(
            passport_id="pass-001",
            agent_id="agent-001",
            agent_name="Test Agent",
            public_key=pub,
            trust_score=0.75,
            trust_level="VERIFIED",
            verdict="TRUSTED",
        )
        assert passport.agent_id == "agent-001"
        assert passport.trust_score == 0.75

    def test_passport_seal_and_verify(self):
        pub, priv = generate_keypair()
        passport = AgentPassport(
            passport_id="pass-002",
            agent_id="agent-002",
            agent_name="Test",
            public_key=pub,
            trust_score=0.80,
            trust_level="VERIFIED",
            verdict="TRUSTED",
        )
        passport.seal()
        assert passport.crypto_hash != ""
        assert passport.verify_integrity()

    def test_passport_tamper_detection(self):
        pub, priv = generate_keypair()
        passport = AgentPassport(
            passport_id="pass-003",
            agent_id="agent-003",
            agent_name="Test",
            public_key=pub,
            trust_score=0.80,
            trust_level="VERIFIED",
            verdict="TRUSTED",
        )
        passport.seal()
        # Tamper with the trust score
        passport.trust_score = 0.99
        assert not passport.verify_integrity()

    def test_passport_jwt_roundtrip(self):
        pub, priv = generate_keypair()
        passport = AgentPassport(
            passport_id="pass-004",
            agent_id="agent-004",
            agent_name="JWT Test",
            public_key=pub,
            trust_score=0.70,
            trust_level="VERIFIED",
            verdict="TRUSTED",
        )
        passport.seal()
        token = passport.to_jwt(priv)
        decoded = AgentPassport.from_jwt(token, pub)
        assert decoded.agent_id == "agent-004"
        assert decoded.trust_score == 0.70

    def test_runtime_fingerprint(self):
        fp = generate_runtime_fingerprint()
        assert isinstance(fp, str)
        assert len(fp) >= 16  # At least 16 hex chars


# ---------------------------------------------------------------------------
# Client Tests (mocked HTTP)
# ---------------------------------------------------------------------------

class TestClient:
    def test_client_init(self):
        client = LastBastionClient(
            api_key="key_id:secret_value",
            base_url="http://localhost:8000",
        )
        assert client._key_id == "key_id"
        assert client._key_secret == "secret_value"

    def test_client_init_no_key(self):
        client = LastBastionClient()
        assert client._key_id == ""
        assert client._key_secret == ""

    def test_generate_keypair_static(self):
        pub, priv = LastBastionClient.generate_keypair()
        assert len(pub) == 64
        assert len(priv) == 64


class TestClientResponses:
    def test_handle_401(self):
        client = LastBastionClient()
        resp = MagicMock()
        resp.status_code = 401
        with pytest.raises(AuthenticationError):
            client._handle_response(resp)

    def test_handle_404(self):
        client = LastBastionClient()
        resp = MagicMock()
        resp.status_code = 404
        with pytest.raises(NotFoundError):
            client._handle_response(resp)

    def test_handle_429(self):
        client = LastBastionClient()
        resp = MagicMock()
        resp.status_code = 429
        with pytest.raises(RateLimitError):
            client._handle_response(resp)

    def test_handle_422(self):
        client = LastBastionClient()
        resp = MagicMock()
        resp.status_code = 422
        resp.json.return_value = {"detail": "bad field"}
        with pytest.raises(ValidationError):
            client._handle_response(resp)

    def test_handle_500(self):
        client = LastBastionClient()
        resp = MagicMock()
        resp.status_code = 500
        with pytest.raises(LastBastionError):
            client._handle_response(resp)

    def test_handle_200(self):
        client = LastBastionClient()
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"verdict": "VERIFIED"}
        result = client._handle_response(resp)
        assert result["verdict"] == "VERIFIED"


# ---------------------------------------------------------------------------
# Protocol Message Construction Tests
# ---------------------------------------------------------------------------

class TestProtocolMessages:
    def test_challenge_data_binding(self):
        """Challenge nonce must be crypto-bound to agent_id."""
        pub, priv = generate_keypair()
        agent_id = "test-agent-001"
        nonce = "abc123"
        challenge_data = f"{agent_id}:{nonce}"
        sig = sign_bytes(challenge_data.encode(), priv)
        assert verify_signature(challenge_data.encode(), sig, pub)
        # Same nonce but different agent_id should fail
        wrong_challenge = f"other-agent:{nonce}"
        assert not verify_signature(wrong_challenge.encode(), sig, pub)

    def test_nonce_uniqueness(self):
        """Each nonce should be unique."""
        import uuid
        nonces = {uuid.uuid4().hex for _ in range(1000)}
        assert len(nonces) == 1000


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
