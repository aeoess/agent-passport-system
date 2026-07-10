#!/usr/bin/env python3
# Copyright (c) 2026 Tymofii Pidlisnyi
# SPDX-License-Identifier: Apache-2.0
"""Deterministic generator for the aps-handle-en-v1 lexicon (2048 words).

Derivation source: the EFF Long Wordlist. Attribution: contains words derived from
the EFF Long Wordlist (https://www.eff.org/dice), Copyright Electronic Frontier
Foundation, licensed under the Creative Commons Attribution 3.0 license (CC-BY 3.0).
The BIP39 English list is used ONLY as a disjointness-check input; no BIP39 word
appears in the output lexicon (word handles must never look like wallet material).

Inputs (committed beside this script; do not edit):
  eff_large_wordlist_words.txt  7776 words, one per line (EFF long list, words only,
                                verified byte-identical across two independent
                                package-registry copies at vendor time)
  bip39_english.txt             2048 words (canonical BIP39 English; sha256 of the
                                file is the well-known 2f5eed53...dbda)

Pipeline (every step deterministic; rerunning reproduces the identical list):
  1. Keep EFF words matching ^[a-z]{4,8}$.
  2. Drop any word present in the BIP39 English list (full disjointness).
  3. Glyph-confusability classes (0O, 38, 5S, 6, 8B, Il1) are applied by mapping
     each word to a confusion skeleton: bigram collapses rn->m, vv->w, cl->d, then
     character collapses i->1, l->1, o->0, s->5, b->8. Words sharing a skeleton are
     a confusable pair; only one survives (shortest, then alphabetical).
  4. Near-homoglyph word pairs: any word within Damerau-Levenshtein distance 1
     (single substitution, adjacent transposition, single insert or delete) of an
     already-kept word is dropped. Processing order: length, then alphabetical.
  5. Unique 4-letter prefixes: first keeper per prefix wins (length, then alpha).
  6. Exactly 2048 selected by ascending sha256("aps-handle-en-v1:" + word), an
     unbiased deterministic subset; final list is sorted alphabetically.
  7. Assertions: 2048 words, all ^[a-z]{4,8}$, disjoint from BIP39, unique 4-letter
     prefixes, unique skeletons, no DL-1 pair inside the final set.

lexicon_id = "sha256:" + sha256 of the canonical text form ("\n".join(words) + "\n").

Usage:
  python3 generate_lexicon.py            # verify only (recompute, assert, print id)
  python3 generate_lexicon.py --emit     # also rewrite ../lexicon.ts and the Python
                                         # SDK lexicon at --py-path (default below)
"""

import hashlib
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
LEXICON_NAME = "aps-handle-en-v1"
PY_PATH_DEFAULT = os.path.expanduser(
    "~/agent-passport-python/src/agent_passport/v2/word_handles/lexicon.py")

ATTRIBUTION = ("Contains words derived from the EFF Long Wordlist "
               "(https://www.eff.org/dice), Copyright Electronic Frontier Foundation, "
               "licensed CC-BY 3.0.")


def skeleton(w):
    w = w.replace("rn", "m").replace("vv", "w").replace("cl", "d")
    return w.translate(str.maketrans({"i": "1", "l": "1", "o": "0", "s": "5", "b": "8"}))


def dl1(a, b):
    """True when a and b are within Damerau-Levenshtein distance 1
    (substitution, adjacent transposition, or single insert/delete)."""
    la, lb = len(a), len(b)
    if la == lb:
        diff = [i for i in range(la) if a[i] != b[i]]
        if len(diff) == 1:
            return True
        return (len(diff) == 2 and diff[1] == diff[0] + 1
                and a[diff[0]] == b[diff[1]] and a[diff[1]] == b[diff[0]])
    if abs(la - lb) == 1:
        longer, shorter = (a, b) if la > lb else (b, a)
        for i in range(len(longer)):
            if longer[:i] + longer[i + 1:] == shorter:
                return True
    return False


def build():
    eff = [l.strip() for l in open(os.path.join(HERE, "eff_large_wordlist_words.txt"))
           if l.strip()]
    bip = set(open(os.path.join(HERE, "bip39_english.txt")).read().split())
    assert len(eff) == 7776 and len(bip) == 2048

    base = [w for w in eff if re.fullmatch(r"[a-z]{4,8}", w) and w not in bip]

    groups = {}
    for w in sorted(base, key=lambda x: (len(x), x)):
        groups.setdefault(skeleton(w), []).append(w)
    skel_kept = sorted((g[0] for g in groups.values()), key=lambda x: (len(x), x))

    kept, by_len = [], {}
    for w in skel_kept:
        neighbors = by_len.get(len(w), []) + by_len.get(len(w) - 1, []) + by_len.get(len(w) + 1, [])
        if not any(dl1(w, c) for c in neighbors):
            kept.append(w)
            by_len.setdefault(len(w), []).append(w)

    seen, prefix_unique = set(), []
    for w in kept:  # already (len, alpha) ordered
        if w[:4] not in seen:
            seen.add(w[:4])
            prefix_unique.append(w)

    sel = sorted(prefix_unique,
                 key=lambda w: hashlib.sha256((LEXICON_NAME + ":" + w).encode()).hexdigest())[:2048]
    final = sorted(sel)

    # assertions
    assert len(final) == 2048
    assert all(re.fullmatch(r"[a-z]{4,8}", w) for w in final)
    assert not (set(final) & bip), "BIP39 overlap"
    assert len({w[:4] for w in final}) == 2048, "prefix collision"
    assert len({skeleton(w) for w in final}) == 2048, "skeleton collision"
    fby = {}
    for w in final:
        fby.setdefault(len(w), []).append(w)
    for w in final:
        for c in fby.get(len(w), []) + fby.get(len(w) - 1, []):
            assert c == w or not dl1(w, c), "DL1 pair in final set: %s / %s" % (w, c)
    canon = "\n".join(final) + "\n"
    lex_id = "sha256:" + hashlib.sha256(canon.encode()).hexdigest()
    return final, lex_id


def emit(final, lex_id):
    rows_ts = [", ".join("'%s'" % w for w in final[i:i + 8]) for i in range(0, 2048, 8)]
    ts = ["// Copyright (c) 2026 Tymofii Pidlisnyi",
          "// SPDX-License-Identifier: Apache-2.0",
          "// " + "=" * 66,
          "// Word handles: %s lexicon (2048 words), generated data file" % LEXICON_NAME,
          "// " + "=" * 66,
          "// " + ATTRIBUTION,
          "// Generated by lexicon-source/generate_lexicon.py; the pipeline, inputs,",
          "// and constraints (disjoint from BIP39 English, unique 4-letter prefixes,",
          "// glyph-confusability and near-homoglyph filtering, lowercase ascii 4-8)",
          "// are documented there. Do not edit this file by hand; regenerate instead.",
          "// The lexicon is versioned and swappable: records pin lexicon_id.",
          "",
          "export const LEXICON_NAME = '%s'" % LEXICON_NAME,
          "",
          "/** sha256 of the canonical word list text (one word per line, trailing newline). */",
          "export const LEXICON_ID =",
          "  '%s'" % lex_id,
          "",
          "export const WORDS: readonly string[] = ["]
    ts += ["  " + r + "," for r in rows_ts]
    ts += ["] as const", "",
           "/** Canonical text form of the lexicon; sha256 of this string equals LEXICON_ID. */",
           "export function canonicalWordlistText(): string {",
           "  return WORDS.join('\\n') + '\\n'",
           "}", ""]
    open(os.path.join(HERE, "..", "lexicon.ts"), "w").write("\n".join(ts))

    rows_py = [", ".join('"%s"' % w for w in final[i:i + 8]) for i in range(0, 2048, 8)]
    py = ['"""Word handles: %s lexicon (2048 words), generated data file.' % LEXICON_NAME,
          "",
          ATTRIBUTION,
          "",
          "Generated by agent-passport-system/src/v2/word_handles/lexicon-source/",
          "generate_lexicon.py; pipeline, inputs, and constraints (disjoint from BIP39",
          "English, unique 4-letter prefixes, glyph-confusability and near-homoglyph",
          "filtering, lowercase ascii 4-8) are documented there. Do not edit by hand;",
          "regenerate instead. The lexicon is versioned and swappable via lexicon_id.",
          '"""',
          "",
          'LEXICON_NAME = "%s"' % LEXICON_NAME,
          "",
          'LEXICON_ID = "%s"' % lex_id,
          "",
          "WORDS = ("]
    py += ["    " + r + "," for r in rows_py]
    py += [")", "", "",
           "def canonical_wordlist_text() -> str:",
           '    """Canonical text form of the lexicon; sha256 equals LEXICON_ID."""',
           '    return "\\n".join(WORDS) + "\\n"',
           ""]
    open(PY_PATH_DEFAULT, "w").write("\n".join(py))


if __name__ == "__main__":
    final, lex_id = build()
    print("words:", len(final))
    print("first/last:", final[0], final[-1])
    print("lexicon_id:", lex_id)
    if "--emit" in sys.argv:
        emit(final, lex_id)
        print("emitted ../lexicon.ts and", PY_PATH_DEFAULT)
