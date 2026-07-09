# ClusterFuzzLite copies the checked-out source directly during
# `docker build` (unlike full OSS-Fuzz, which git-clones inside the
# Dockerfile), so this image just needs the JS/TS builder base plus the
# repo contents and the build script.
FROM gcr.io/oss-fuzz-base/base-builder-javascript

COPY . $SRC/agent-passport-system
COPY .clusterfuzzlite/build.sh $SRC/

WORKDIR $SRC/agent-passport-system
