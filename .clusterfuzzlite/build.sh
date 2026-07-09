#!/bin/bash -eu

cd "$SRC/agent-passport-system"

# NODE_ENV is forced here because some environments default it to
# "production", which makes npm silently drop devDependencies (Jazzer.js,
# TypeScript) and produce a broken build.
export NODE_ENV=development
npm install --include=dev

# Jazzer.js loads compiled JS modules, not TypeScript directly. Compile the
# fuzz harnesses together with the source they import (see fuzz/tsconfig.json)
# into dist-fuzz/, preserving the same relative directory layout.
npx tsc -p fuzz/tsconfig.json

TARGETS="qntm-invite cedar-policy canonicalize canonicalize-jcs governance-block-html did-web-url verify-passport"

# Build one fuzzer binary per harness. compile_javascript_fuzzer copies the
# whole project directory into $OUT once and wraps each entry point with a
# script that invokes Jazzer.js against it.
for target in $TARGETS; do
  compile_javascript_fuzzer agent-passport-system "dist-fuzz/fuzz/targets/$target.js" --sync
done

# Ship each target's seed corpus alongside its fuzzer binary, per the
# <fuzzer_name>_seed_corpus.zip convention, so ClusterFuzzLite starts from
# real examples (including the two crash-reproducing regression seeds in
# fuzz/FINDINGS.md) instead of nothing.
for target in $TARGETS; do
  zip -j -q "$OUT/${target}_seed_corpus.zip" fuzz/corpus/"$target"/*
done
