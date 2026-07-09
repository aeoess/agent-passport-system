# ClusterFuzzLite copies the checked-out source directly during
# `docker build` (unlike full OSS-Fuzz, which git-clones inside the
# Dockerfile), so this image just needs the JS/TS builder base plus the
# repo contents and the build script.
# Base image pinned by digest (Scorecard Pinned-Dependencies). This is the
# current gcr.io/oss-fuzz-base/base-builder-javascript; refresh the digest to
# move to a newer base builder.
FROM gcr.io/oss-fuzz-base/base-builder-javascript@sha256:bf43c12b74dd236c330e3e8febc604548e414e5eca3504655e0470acc5a3549c

COPY . $SRC/agent-passport-system
COPY .clusterfuzzlite/build.sh $SRC/

WORKDIR $SRC/agent-passport-system
