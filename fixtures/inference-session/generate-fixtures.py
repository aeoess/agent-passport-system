#!/usr/bin/env python3
"""
CTEF Synthetic Test Fixture Generator
为 a2aproject/A2A #1786 (CTEF v0.3.1) 生成 synthetic test vectors

遵循 aeoess/agent-passport-system/fixtures/bilateral-delegation/ 格式:
- 确定性 Ed25519 keypair（seed = SHA-256("ctef-synthetic-fixture-v1")）
- JCS canonical JSON (RFC 8785)
- 每个 vector 包含 input + canonical_bytes + sha256 + signature

测试场景:
1. valid-identity-claim — 正常身份声明
2. expired-validity-window — 过期的 validity_window (expected_verification: false)
3. rotated-key-claim — 密钥轮换后的声明
4. sequence-bound-continuity — 基于 sequence_bound 的连续性
5. cross-layer-identity-transport — 跨层（identity + transport）声明
6. sequence-gap — seq 从 1 跳到 5，测试 gap 检测
7. replay-same-sequence — 相同 sequence_number 出现两次，测试重放保护
"""

import json
import hashlib
import os
from datetime import datetime, timedelta, timezone

import jcs as _jcs
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

# 确定性 keypair
SEED_INPUT = "ctef-synthetic-fixture-v1"
SEED = hashlib.sha256(SEED_INPUT.encode()).digest()

private_key = Ed25519PrivateKey.from_private_bytes(SEED)
public_key = private_key.public_key()
PUBKEY_HEX = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw).hex()


def derive_session_id(vector_index: int) -> str:
    """
    Deterministic session_id per aeoess's spec:
    session_id = SHA-256(seed_bytes || b"session" || vector_index_be4)[:32]
    where seed_bytes = SHA-256("ctef-synthetic-fixture-v1")
    """
    return hashlib.sha256(
        SEED + b"session" + vector_index.to_bytes(4, "big")
    ).hexdigest()[:32]


def sign(data: bytes) -> str:
    return private_key.sign(data).hex()


def canonicalize_jcs(obj) -> bytes:
    """RFC 8785 JCS canonical JSON"""
    return _jcs.canonicalize(obj)


def make_vector(name: str, description: str, input_obj: dict,
                expected_verification: bool = True) -> dict:
    canonical_bytes = canonicalize_jcs(input_obj)
    return {
        "name": name,
        "description": description,
        "input": input_obj,
        "canonical_bytes_hex": canonical_bytes.hex(),
        "canonical_sha256": hashlib.sha256(canonical_bytes).hexdigest(),
        "ed25519_pubkey_hex": PUBKEY_HEX,
        "ed25519_signature_over_canonical_hex": sign(canonical_bytes),
        "expected_verification": expected_verification
    }


# 基准时间
BASE_TIME = datetime(2026, 4, 25, 0, 0, 0, tzinfo=timezone.utc)
def ts(offset_hours=0):
    return (BASE_TIME + timedelta(hours=offset_hours)).strftime("%Y-%m-%dT%H:%M:%SZ")


def generate_fixtures():
    vectors = []

    # 1: 有效身份声明
    vectors.append(make_vector(
        "valid-identity-claim",
        "Standard identity claim with Ed25519 key, valid validity_window, and sequence_bound continuity.",
        {
            "claim_type": "identity",
            "agent_id": "did:ctef:agent-001",
            "public_key_jwk": {
                "crv": "Ed25519",
                "kty": "OKP",
                "x": PUBKEY_HEX[:43]
            },
            "validity_window": {
                "not_before": ts(0),
                "not_after": ts(2),
                "window_seconds": 7200
            },
            "sequence_bound": {
                "session_id": derive_session_id(0),
                "sequence_number": 1,
                "monotonic": True
            },
            "metadata": {
                "layer": "identity",
                "version": "ctef-v0.3.1"
            }
        }
    ))

    # 2: 过期的 validity_window（应验证失败）
    vectors.append(make_vector(
        "expired-validity-window",
        "Identity claim with expired validity_window — must fail verification.",
        {
            "claim_type": "identity",
            "agent_id": "did:ctef:agent-001",
            "public_key_jwk": {
                "crv": "Ed25519",
                "kty": "OKP",
                "x": PUBKEY_HEX[:43]
            },
            "validity_window": {
                "not_before": ts(-3),
                "not_after": ts(-1),
                "window_seconds": 7200
            },
            "sequence_bound": {
                "session_id": derive_session_id(1),
                "sequence_number": 1,
                "monotonic": True
            },
            "metadata": {
                "layer": "identity",
                "version": "ctef-v0.3.1"
            }
        },
        expected_verification=False
    ))

    # 3: 密钥轮换
    vectors.append(make_vector(
        "rotated-key-claim",
        "Identity claim after key rotation — old key hash in rotation_attestation.",
        {
            "claim_type": "identity",
            "agent_id": "did:ctef:agent-001",
            "public_key_jwk": {
                "crv": "Ed25519",
                "kty": "OKP",
                "x": hashlib.sha256(SEED + b"rotated").hexdigest()[:43]
            },
            "rotation_attestation": {
                "previous_key_hash": hashlib.sha256(PUBKEY_HEX.encode()).hexdigest()[:32],
                "rotated_at": ts(0),
                "rotation_reason": "scheduled"
            },
            "validity_window": {
                "not_before": ts(0),
                "not_after": ts(2),
                "window_seconds": 7200
            },
            "sequence_bound": {
                "session_id": derive_session_id(2),
                "sequence_number": 2,
                "monotonic": True
            },
            "metadata": {
                "layer": "identity",
                "version": "ctef-v0.3.1"
            }
        }
    ))

    # 4: sequence_bound 连续性 (5-step monotonic sequence — one session_id per vector)
    vectors.append(make_vector(
        "sequence-bound-continuity",
        "Monotonic sequence chain across 5 steps — tests replay protection and ordering.",
        {
            "claim_type": "continuity",
            "agent_id": "did:ctef:agent-001",
            "sequence_chain": [
                {"hash": hashlib.sha256(f"step-{i}".encode()).hexdigest()[:16], "seq": i}
                for i in range(1, 6)
            ],
            "sequence_bound": {
                "gap_allowed": False,
                "monotonic": True,
                "sequence_number": 5,
                "session_id": derive_session_id(3)
            },
            "validity_window": {
                "not_before": ts(0),
                "not_after": ts(4),
                "window_seconds": 14400
            },
            "metadata": {
                "layer": "continuity",
                "version": "ctef-v0.3.1"
            }
        }
    ))

    # 5: 跨层 identity + transport
    vectors.append(make_vector(
        "cross-layer-identity-transport",
        "Combined identity + transport claim — tests inter-layer binding and per-layer validity_window.",
        {
            "claim_type": "compound",
            "agent_id": "did:ctef:agent-001",
            "layers": {
                "identity": {
                    "claim_type": "identity",
                    "public_key_jwk": {
                        "crv": "Ed25519",
                        "kty": "OKP",
                        "x": PUBKEY_HEX[:43]
                    },
                    "validity_window": {
                        "binding": "sequence_bound",
                        "not_after": ts(4),
                        "not_before": ts(0),
                        "window_seconds": 14400
                    }
                },
                "transport": {
                    "claim_type": "transport",
                    "encryption": "TLS-PSK",
                    "protocol": "tcp",
                    "rekey_interval_seconds": 3600,
                    "validity_window": {
                        "not_after": ts(1),
                        "not_before": ts(0),
                        "renewable": True,
                        "window_seconds": 3600
                    }
                }
            },
            "metadata": {
                "topology": "multi-node",
                "use_case": "distributed_inference",
                "version": "ctef-v0.3.1"
            },
            "sequence_bound": {
                "monotonic": True,
                "sequence_number": 1,
                "session_id": derive_session_id(4)
            }
        }
    ))

    # 6: sequence gap
    vectors.append(make_vector(
        "sequence-gap",
        "Sequence jumps from 1 to 5 (gap 2-4 missing) — tests gap detection.",
        {
            "claim_type": "continuity",
            "agent_id": "did:ctef:agent-001",
            "sequence_chain": [
                {"hash": hashlib.sha256(b"step-1").hexdigest()[:16], "seq": 1},
                {"hash": hashlib.sha256(b"step-5").hexdigest()[:16], "seq": 5}
            ],
            "sequence_bound": {
                "gap_allowed": False,
                "monotonic": True,
                "sequence_number": 5,
                "session_id": derive_session_id(5)
            },
            "validity_window": {
                "not_before": ts(0),
                "not_after": ts(2),
                "window_seconds": 7200
            },
            "metadata": {
                "expected_result": "GAP_DETECTED",
                "layer": "continuity",
                "version": "ctef-v0.3.1"
            }
        },
        expected_verification=False
    ))

    # 7: replay same sequence
    vectors.append(make_vector(
        "replay-same-sequence",
        "Same sequence_number appears twice — tests replay attack detection.",
        {
            "claim_type": "continuity",
            "agent_id": "did:ctef:agent-001",
            "sequence_chain": [
                {"hash": hashlib.sha256(b"step-3a").hexdigest()[:16], "seq": 3},
                {"hash": hashlib.sha256(b"step-3b").hexdigest()[:16], "seq": 3}
            ],
            "sequence_bound": {
                "gap_allowed": False,
                "monotonic": True,
                "sequence_number": 3,
                "session_id": derive_session_id(6)
            },
            "validity_window": {
                "not_before": ts(0),
                "not_after": ts(2),
                "window_seconds": 7200
            },
            "metadata": {
                "expected_result": "REPLAY_DETECTED",
                "layer": "continuity",
                "version": "ctef-v0.3.1"
            }
        },
        expected_verification=False
    ))

    fixture = {
        "version": "v1",
        "spec": "CTEF v0.3.1 — Cryptographic Agent Identity",
        "canonicalization": "JCS — RFC 8785 (jcs 0.2.1)",
        "seed_input": SEED_INPUT,
        "seed_sha256_hex": SEED.hex(),
        "session_id_derivation": {
            "algorithm": "SHA-256(seed_bytes || b'session' || vector_index_be4)[:32]",
            "note": "Per aeoess spec — every session_id traces back to seed via documented transformation",
            "seed_bytes_source": "SHA-256('ctef-synthetic-fixture-v1')",
            "vector_index_be4": "Vector's 0-based position as 4-byte big-endian unsigned integer"
        },
        "keypair": {
            "publicKeyHex": PUBKEY_HEX
        },
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "generator": "ctef_synthetic_fixture.py",
        "has_real_signatures": True,
        "vectors": vectors
    }
    return fixture


if __name__ == "__main__":
    import os
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    fixture = generate_fixtures()
    output_path = os.path.join(os.path.dirname(__file__), "inference-session-fixtures.json")

    with open(output_path, "w") as f:
        json.dump(fixture, f, indent=2, ensure_ascii=False)

    # 自检: canonical bytes + SHA-256 + Ed25519 signature verification
    pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(PUBKEY_HEX))
    for v in fixture["vectors"]:
        cb = canonicalize_jcs(v["input"])
        assert cb.hex() == v["canonical_bytes_hex"], f"{v['name']} canonical mismatch"
        assert hashlib.sha256(cb).hexdigest() == v["canonical_sha256"], f"{v['name']} sha256 mismatch"
        pub.verify(bytes.fromhex(v["ed25519_signature_over_canonical_hex"]), cb)

    print(f"✅ CTEF Synthetic Fixture v1")
    print(f"   文件: {output_path}")
    print(f"   Vectors: {len(fixture['vectors'])}")
    print(f"   JCS: RFC 8785 (jcs 0.2.1)")
    print(f"   签名: Ed25519 真实")
    print(f"   Pubkey: {PUBKEY_HEX[:32]}...")
    print(f"   自检: ✅ 全部通过 (canonical + SHA-256 + Ed25519 verify)")
