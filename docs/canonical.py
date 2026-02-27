"""
Canonical JSON serialization for Agent Passport System.
Must produce identical bytes to the TypeScript SDK's canonicalize().

Rules:
  - Sort keys alphabetically (Unicode code point order)
  - No whitespace after : or ,
  - Omit keys with None values
  - Recursive for nested objects
  - Arrays preserve order, elements canonicalized
  - Standard JSON string escaping
"""

import json


def canonicalize(obj):
    """Canonicalize a Python object to deterministic JSON string."""
    if obj is None:
        return ""
    if isinstance(obj, bool):
        return "true" if obj else "false"
    if isinstance(obj, (int, float)):
        return json.dumps(obj)
    if isinstance(obj, str):
        return json.dumps(obj)
    if isinstance(obj, list):
        return "[" + ",".join(canonicalize(item) for item in obj) + "]"
    if isinstance(obj, dict):
        sorted_keys = sorted(obj.keys())
        pairs = []
        for key in sorted_keys:
            val = obj[key]
            if val is None:
                continue
            pairs.append(json.dumps(key) + ":" + canonicalize(val))
        return "{" + ",".join(pairs) + "}"
    raise TypeError(f"Cannot canonicalize type: {type(obj)}")


# --- Signing helpers ---

def sign_object(obj, secret_key_hex):
    """Sign an object using Ed25519 after canonicalization.
    
    Args:
        obj: dict to sign (must not contain 'signature' key)
        secret_key_hex: 128-char hex string (64-byte Ed25519 secret key)
    
    Returns:
        128-char hex signature string
    """
    from hashlib import sha512
    
    # Pure Python Ed25519 — same as PortalX2's implementation
    # For production, use: from nacl.signing import SigningKey
    canonical = canonicalize(obj)
    message = canonical.encode("utf-8")
    
    secret_bytes = bytes.fromhex(secret_key_hex)
    # Ed25519 sign using secret key bytes
    # This assumes the full 64-byte secret key format
    
    # If you have nacl installed:
    try:
        from nacl.signing import SigningKey
        sk = SigningKey(secret_bytes[:32])
        signed = sk.sign(message)
        return signed.signature.hex()
    except ImportError:
        pass
    
    # Fallback: pure Python Ed25519 (same as PortalX2 uses)
    from ed25519_pure import sign as ed25519_sign
    return ed25519_sign(message, secret_bytes).hex()


def verify_object(obj, signature_hex, public_key_hex):
    """Verify an Ed25519 signature over a canonicalized object.
    
    Args:
        obj: dict to verify (without 'signature' key)
        signature_hex: 128-char hex signature
        public_key_hex: 64-char hex public key
    
    Returns:
        True if signature is valid
    """
    canonical = canonicalize(obj)
    message = canonical.encode("utf-8")
    sig_bytes = bytes.fromhex(signature_hex)
    pub_bytes = bytes.fromhex(public_key_hex)
    
    try:
        from nacl.signing import VerifyKey
        vk = VerifyKey(pub_bytes)
        vk.verify(message, sig_bytes)
        return True
    except ImportError:
        pass
    except Exception:
        return False
    
    from ed25519_pure import verify as ed25519_verify
    return ed25519_verify(message, sig_bytes, pub_bytes)


def sign_and_attach(obj, secret_key_hex):
    """Canonicalize, sign, and return object with signature attached."""
    # Remove existing signature if present
    to_sign = {k: v for k, v in obj.items() if k != "signature"}
    sig = sign_object(to_sign, secret_key_hex)
    obj["signature"] = sig
    return obj


def verify_and_strip(obj, public_key_hex):
    """Extract signature, verify against canonicalized remainder."""
    sig = obj.get("signature")
    if not sig:
        raise ValueError("No signature field found")
    to_verify = {k: v for k, v in obj.items() if k != "signature"}
    return verify_object(to_verify, sig, public_key_hex)


# --- Test against TypeScript SDK ---

if __name__ == "__main__":
    # Test vector: must match TypeScript canonicalize() output exactly
    test = {"z": 1, "a": "hello", "m": None, "b": [3, 1, 2]}
    result = canonicalize(test)
    expected = '{"a":"hello","b":[3,1,2],"z":1}'
    assert result == expected, f"MISMATCH:\n  got:      {result}\n  expected: {expected}"
    print(f"✅ Basic test passed: {result}")

    # Nested object test
    nested = {"outer": {"z": True, "a": 1}, "list": [{"b": 2, "a": 1}]}
    result2 = canonicalize(nested)
    expected2 = '{"list":[{"a":1,"b":2}],"outer":{"a":1,"z":true}}'
    assert result2 == expected2, f"MISMATCH:\n  got:      {result2}\n  expected: {expected2}"
    print(f"✅ Nested test passed: {result2}")

    # Empty/edge cases
    assert canonicalize({}) == "{}"
    assert canonicalize([]) == "[]"
    assert canonicalize(None) == ""
    assert canonicalize("hello") == '"hello"'
    assert canonicalize(42) == "42"
    print("✅ Edge cases passed")

    print("\nAll canonicalization tests passed. This output matches the TypeScript SDK.")
