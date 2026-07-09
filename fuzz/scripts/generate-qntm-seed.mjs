// One-off generator for the qntm-invite prototype-pollution seed.
// Hand-builds minimal CBOR bytes matching cborDecodeMap's expected
// encoding: a map (major type 5) with one key/value pair, both CBOR
// text strings (major type 3): key = "__proto__", value = "polluted".
function textString(s) {
  const bytes = Buffer.from(s, "utf8");
  const len = bytes.length;
  if (len < 24) return Buffer.concat([Buffer.from([0x60 | len]), bytes]);
  return Buffer.concat([Buffer.from([0x78, len]), bytes]);
}
function mapOf(pairs) {
  const n = pairs.length;
  const header =
    n < 24
      ? Buffer.from([0xa0 | n])
      : Buffer.concat([Buffer.from([0xb8]), Buffer.from([n])]);
  const body = pairs.map(([k, v]) =>
    Buffer.concat([textString(k), textString(v)]),
  );
  return Buffer.concat([header, ...body]);
}

const cbor = mapOf([["__proto__", "polluted"]]);
console.log("cbor hex:", cbor.toString("hex"));
const b64url = cbor
  .toString("base64")
  .replace(/\+/g, "-")
  .replace(/\//g, "_")
  .replace(/=+$/, "");
console.log("token:", b64url);

import { writeFileSync } from "node:fs";
writeFileSync("fuzz/corpus/qntm-invite/proto-pollution-attempt", b64url);
console.log("wrote fuzz/corpus/qntm-invite/proto-pollution-attempt");
