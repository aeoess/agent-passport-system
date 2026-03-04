"""
Agent Passport System — Canonical Serialization (Python Reference)

Implements the canonical JSON serialization spec for cross-language
Ed25519 signature interoperability. See docs/CANONICAL-SPEC.md.

Usage:
    from aps_canonical import canonicalize, sign_canonical, verify_canonical

    data = {"z": 1, "a": "hello", "m": None}
    canonical = canonicalize(data)  # '{"a":"hello","z":1}'

    sig = sign_canonical(data, secret_key_hex)
    valid = verify_canonical(data, sig, public_key_hex)
"""

import json


def canonicalize(obj) -> str:
    """Canonical JSON serialization matching Node.js SDK."""
    if obj is None:
        return 'null'
    if isinstance(obj, bool):
        return 'true' if obj else 'false'
    if isinstance(obj, (int, float)):
        return json.dumps(obj)
    if isinstance(obj, str):
        return json.dumps(obj)
    if isinstance(obj, list):
        items = [canonicalize(item) for item in obj]
        return '[' + ','.join(items) + ']'
    if isinstance(obj, dict):
        sorted_keys = sorted(obj.keys())
        pairs = []
        for key in sorted_keys:
            val = obj[key]
            if val is None:
                continue
            pairs.append(json.dumps(key) + ':' + canonicalize(val))
        return '{' + ','.join(pairs) + '}'
    return json.dumps(obj)


def sign_canonical(data: dict, secret_key_hex: str) -> str:
    """Sign a dict using canonical serialization + Ed25519."""
    try:
        from nacl.signing import SigningKey
        obj = {k: v for k, v in data.items() if k != 'signature'}
        message = canonicalize(obj).encode('utf-8')
        sk = SigningKey(bytes.fromhex(secret_key_hex)[:32])
        signed = sk.sign(message)
        return signed.signature.hex()
    except ImportError:
        raise ImportError("pip install pynacl for Ed25519 signing")


def verify_canonical(data: dict, signature_hex: str, public_key_hex: str) -> bool:
    """Verify a signature over canonicalized dict using Ed25519."""
    try:
        from nacl.signing import VerifyKey
        obj = {k: v for k, v in data.items() if k != 'signature'}
        message = canonicalize(obj).encode('utf-8')
        vk = VerifyKey(bytes.fromhex(public_key_hex))
        try:
            vk.verify(message, bytes.fromhex(signature_hex))
            return True
        except Exception:
            return False
    except ImportError:
        raise ImportError("pip install pynacl for Ed25519 verification")


if __name__ == '__main__':
    tests = [
        ({'z': 1, 'a': 'hello', 'm': None, 'b': [3, 1, 2]},
         '{"a":"hello","b":[3,1,2],"z":1}'),
        ({'name': 'test', 'nested': {'z': True, 'a': False}},
         '{"name":"test","nested":{"a":false,"z":true}}'),
        ({'empty_array': [], 'num': 0, 'neg': -1},
         '{"empty_array":[],"neg":-1,"num":0}'),
        ({'a': 'quotes "inside"'},
         '{"a":"quotes \\"inside\\""}'),
        # F-PX2-001: null in arrays must produce valid JSON
        ([1, None, 3], '[1,null,3]'),
        ([None], '[null]'),
        (None, 'null'),
    ]
    print('Canonical serialization test vectors:')
    all_pass = True
    for i, (inp, expected) in enumerate(tests):
        result = canonicalize(inp)
        ok = result == expected
        if not ok:
            all_pass = False
        print(f'  {"✅" if ok else "❌"} Test {i}: {result}')
    print(f'\n{"All passed!" if all_pass else "FAILURES"}')