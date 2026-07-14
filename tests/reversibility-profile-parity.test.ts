// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// Reversibility v0 profile digest: three-language parity (v4 section 4).
// The profile content digest is SHA-256 over a domain tag plus the JCS bytes of
// the authoritative content. TS, Python, and Go each canonicalize the SAME
// content with their own JCS and must reproduce the SAME digest byte-for-byte.
//
// The golden-digest assertion always runs. The live Python and Go checks run
// when the sibling SDKs and toolchains are present, and skip with a reason
// otherwise, so the suite is green everywhere while parity is enforced where the
// toolchains exist.
import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { mkdtempSync, writeFileSync, existsSync, copyFileSync, rmSync } from 'node:fs'
import { tmpdir, homedir } from 'node:os'
import { join } from 'node:path'
import {
  REVERSIBILITY_MAPPING_V0_DIGEST,
  REVERSIBILITY_PROFILE_V0_CONTENT,
} from '../src/core/reversibility-fold.js'

const GOLDEN_V0_DIGEST = 'sha256:23ef78e02e68e1b1fc94844cc9ccd7e7beae598fc612bddcdb12a9c2792ae322'
const PY_SDK = join(homedir(), 'agent-passport-python')
const GO_SDK = join(homedir(), 'agent-passport-go')

function have(cmd: string, args: string[]): boolean {
  try {
    execFileSync(cmd, args, { stdio: 'ignore' })
    return true
  } catch {
    return false
  }
}

const PY_HARNESS = `
import sys, json, hashlib
sys.path.insert(0, sys.argv[2])
from agent_passport.canonical import canonicalize
content = json.load(open(sys.argv[1]))
jcs = canonicalize(content)
pre = b"APS-REVERSIBILITY-PROFILE-V0" + b"\\x00" + jcs.encode("utf-8")
print("sha256:" + hashlib.sha256(pre).hexdigest())
`

const GO_HARNESS = `package main
import ( "crypto/sha256"; "encoding/hex"; "encoding/json"; "fmt"; "os"; "github.com/aeoess/agent-passport-go/jcs" )
func main() {
  b, _ := os.ReadFile(os.Args[1]); var v interface{}; json.Unmarshal(b, &v)
  c, err := jcs.Canonicalize(v); if err != nil { fmt.Fprintln(os.Stderr, err); os.Exit(1) }
  pre := append(append([]byte("APS-REVERSIBILITY-PROFILE-V0"), 0x00), []byte(c)...)
  sum := sha256.Sum256(pre); fmt.Println("sha256:" + hex.EncodeToString(sum[:]))
}
`

const GO_MOD = `module rvparity
go 1.22
require github.com/aeoess/agent-passport-go v0.0.0
replace github.com/aeoess/agent-passport-go => ${GO_SDK}
`

describe('reversibility v0 profile digest - three-language parity (v4 s4)', () => {
  it('TS reproduces the pinned golden digest', () => {
    // Any change to the authoritative profile content moves this and must be a
    // deliberate golden update.
    assert.equal(REVERSIBILITY_MAPPING_V0_DIGEST, GOLDEN_V0_DIGEST)
  })

  it('Python reproduces the same digest over the same content (or skips if the SDK is absent)', (t) => {
    if (!have('python3', ['--version']) || !existsSync(join(PY_SDK, 'src/agent_passport/canonical.py'))) {
      return t.skip('python3 or the agent-passport-python SDK is not available')
    }
    const dir = mkdtempSync(join(tmpdir(), 'rvparity-py-'))
    try {
      const contentPath = join(dir, 'content.json')
      const scriptPath = join(dir, 'pydigest.py')
      writeFileSync(contentPath, JSON.stringify(REVERSIBILITY_PROFILE_V0_CONTENT))
      writeFileSync(scriptPath, PY_HARNESS)
      const out = execFileSync('python3', [scriptPath, contentPath, join(PY_SDK, 'src')], { encoding: 'utf8' }).trim()
      assert.equal(out, REVERSIBILITY_MAPPING_V0_DIGEST)
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })

  it('Go reproduces the same digest over the same content (or skips if the SDK is absent)', (t) => {
    if (!have('go', ['version']) || !existsSync(join(GO_SDK, 'jcs/jcs.go'))) {
      return t.skip('go or the agent-passport-go SDK is not available')
    }
    const dir = mkdtempSync(join(tmpdir(), 'rvparity-go-'))
    try {
      const contentPath = join(dir, 'content.json')
      writeFileSync(contentPath, JSON.stringify(REVERSIBILITY_PROFILE_V0_CONTENT))
      writeFileSync(join(dir, 'main.go'), GO_HARNESS)
      writeFileSync(join(dir, 'go.mod'), GO_MOD)
      const goSum = join(GO_SDK, 'go.sum')
      if (existsSync(goSum)) copyFileSync(goSum, join(dir, 'go.sum'))
      const out = execFileSync('go', ['run', '.', contentPath], {
        cwd: dir,
        encoding: 'utf8',
        env: { ...process.env, GOFLAGS: '-mod=mod' },
      }).trim()
      assert.equal(out, REVERSIBILITY_MAPPING_V0_DIGEST)
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })
})
