#!/usr/bin/env bash
# Canonical-measurement runner for APS Runtime Passport spec §13.1 (bare-metal
# Linux x86_64) and §13.2 (AWS c7i.2xlarge).
#
# Run unattended on a fresh Linux box. Installs prerequisites, builds the
# verifier crate and TS SDK, runs L0/L1/L2/L3/L4 benchmarks, captures
# environment metadata, tars the results, prints the tar path.
#
# Env-tag string convention matches stream-C's configs/ and the new
# env_capture::capture() labels:
#   aws-c7i-gp3        for AWS EC2 c7i.2xlarge
#   bare-metal-linux   for bare-metal Linux x86_64
#
# The aps-bench Rust binary detects the environment internally via
# /sys/class/dmi and IMDSv2, so the bash side mostly logs and chooses
# whether to run L4.

set -euo pipefail

# ----------------------------------------------------------------------
# Configuration
# ----------------------------------------------------------------------

readonly REPO_URL="${APS_REPO_URL:-https://github.com/aeoess/agent-passport-system.git}"
readonly REPO_REF="${APS_REPO_REF:-main}"
readonly WORK_DIR="${APS_WORK_DIR:-$HOME/aps-canonical-run}"
readonly GATEWAY_PORT="${APS_GATEWAY_PORT:-3200}"
readonly GATEWAY_REPO_URL="${APS_GATEWAY_REPO_URL:-}"  # optional; if unset, L4 is skipped
# L4_SAMPLE_COUNT and L4_WARMUP_COUNT are re-asserted as env-prefix
# assignments to the l4-runner.ts subshell, so they must not be
# readonly. export so the npx child still sees them if the env-prefix
# block is ever dropped.
L4_SAMPLE_COUNT="${L4_SAMPLE_COUNT:-1000}"
L4_WARMUP_COUNT="${L4_WARMUP_COUNT:-100}"
export L4_SAMPLE_COUNT L4_WARMUP_COUNT
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
readonly TIMESTAMP

# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------

log() {
    printf '[%s] %s\n' "$(date -u +%H:%M:%S)" "$*" >&2
}

die() {
    log "FATAL: $*"
    exit 1
}

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

# ----------------------------------------------------------------------
# Environment detection (bash side; used for logging + L4 gating only).
# Source of truth for the result-JSON label is the Rust binary's own
# env_capture::capture(), which writes the label into each output file.
# ----------------------------------------------------------------------

detect_environment_tag() {
    local sys_vendor=""
    local hypervisor=""
    local instance_type=""

    if [[ -r /sys/class/dmi/id/sys_vendor ]]; then
        sys_vendor="$(tr -d '\n' < /sys/class/dmi/id/sys_vendor)"
    fi
    if [[ -r /sys/hypervisor/type ]]; then
        hypervisor="$(tr -d '\n' < /sys/hypervisor/type)"
    fi

    if [[ "$sys_vendor" == "Amazon EC2" ]]; then
        # IMDSv2 instance-type lookup. Required to be c7i.2xlarge for §13.2.
        local token
        token="$(curl -fsS -X PUT \
            -H 'X-aws-ec2-metadata-token-ttl-seconds: 60' \
            http://169.254.169.254/latest/api/token 2>/dev/null || true)"
        if [[ -z "$token" ]]; then
            die "IMDSv2 token request failed on EC2 host"
        fi
        instance_type="$(curl -fsS \
            -H "X-aws-ec2-metadata-token: $token" \
            http://169.254.169.254/latest/meta-data/instance-type 2>/dev/null || true)"
        if [[ "$instance_type" != "c7i.2xlarge" ]]; then
            die "§13.2 requires c7i.2xlarge; IMDSv2 reports: $instance_type"
        fi
        echo "aws-c7i-gp3"
        return
    fi

    if [[ -n "$hypervisor" ]] && [[ "$hypervisor" != "none" ]]; then
        die "hypervisor detected ($hypervisor); §13.1 requires bare metal"
    fi

    echo "bare-metal-linux"
}

# ----------------------------------------------------------------------
# Prerequisite install
# ----------------------------------------------------------------------

install_prereqs() {
    log "installing prerequisites"
    if command -v apt-get >/dev/null 2>&1; then
        sudo DEBIAN_FRONTEND=noninteractive apt-get update -y
        sudo DEBIAN_FRONTEND=noninteractive apt-get install -y \
            build-essential pkg-config libssl-dev sqlite3 libsqlite3-dev \
            git curl ca-certificates jq
    elif command -v dnf >/dev/null 2>&1; then
        # curl is omitted: AL2023 ships curl-minimal preinstalled and the
        # full curl package conflicts with it. curl-minimal is sufficient
        # for the IMDSv2 + healthz probes we do.
        sudo dnf install -y --allowerasing gcc gcc-c++ make pkgconf-pkg-config \
            openssl-devel sqlite sqlite-devel git jq tar gzip
    elif command -v yum >/dev/null 2>&1; then
        sudo yum install -y gcc gcc-c++ make pkgconfig openssl-devel \
            sqlite sqlite-devel git jq tar gzip
    else
        die "no supported package manager found (apt-get, dnf, yum)"
    fi

    if ! command -v rustc >/dev/null 2>&1; then
        log "installing Rust via rustup"
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
            | sh -s -- -y --default-toolchain stable
        # shellcheck disable=SC1091
        source "$HOME/.cargo/env"
    fi
    require_cmd cargo
    require_cmd rustc

    if ! command -v node >/dev/null 2>&1; then
        log "installing Node 24.x via NodeSource"
        if command -v apt-get >/dev/null 2>&1; then
            curl -fsSL https://deb.nodesource.com/setup_24.x | sudo -E bash -
            sudo DEBIAN_FRONTEND=noninteractive apt-get install -y nodejs
        elif command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then
            curl -fsSL https://rpm.nodesource.com/setup_24.x | sudo -E bash -
            if command -v dnf >/dev/null 2>&1; then
                sudo dnf install -y nodejs
            else
                sudo yum install -y nodejs
            fi
        fi
    fi
    require_cmd node
    require_cmd npm
}

# ----------------------------------------------------------------------
# Repo clone
# ----------------------------------------------------------------------

clone_repo() {
    local repo_dir="$1"
    if [[ -d "$repo_dir/.git" ]]; then
        log "repo already cloned at $repo_dir, fetching latest"
        git -C "$repo_dir" fetch origin --prune
        git -C "$repo_dir" checkout "$REPO_REF"
        git -C "$repo_dir" reset --hard "origin/$REPO_REF"
    else
        log "cloning $REPO_URL at $REPO_REF into $repo_dir"
        git clone --depth 50 --branch "$REPO_REF" --single-branch \
            "$REPO_URL" "$repo_dir"
    fi
}

# ----------------------------------------------------------------------
# Environment capture (system metadata supplementing aps-bench's own)
# ----------------------------------------------------------------------

write_env_capture() {
    local out_path="$1"
    local env_tag="$2"

    local cpu_model microcode kernel glibc node_ver rust_ver ram_kb hyper fs_type thermal
    cpu_model="$(grep -m1 'model name' /proc/cpuinfo | sed 's/.*: //')"
    microcode="$(grep -m1 'microcode' /proc/cpuinfo | sed 's/.*: //' || echo 'unknown')"
    kernel="$(uname -a)"
    glibc="$(getconf GNU_LIBC_VERSION 2>/dev/null || echo 'unknown')"
    node_ver="$(node --version)"
    rust_ver="$(rustc --version)"
    ram_kb="$(grep -m1 MemTotal /proc/meminfo | awk '{print $2}')"
    hyper="$(cat /sys/hypervisor/type 2>/dev/null || echo 'none')"
    fs_type="$(stat -f -c %T . 2>/dev/null || echo 'unknown')"
    thermal=""
    if [[ -r /sys/class/thermal/thermal_zone0/temp ]]; then
        thermal="$(cat /sys/class/thermal/thermal_zone0/temp)"
    fi

    jq -n \
        --arg env_tag "$env_tag" \
        --arg cpu "$cpu_model" \
        --arg microcode "$microcode" \
        --arg kernel "$kernel" \
        --arg glibc "$glibc" \
        --arg node_ver "$node_ver" \
        --arg rust_ver "$rust_ver" \
        --arg ram_kb "$ram_kb" \
        --arg hyper "$hyper" \
        --arg fs_type "$fs_type" \
        --arg thermal "$thermal" \
        --arg ts "$TIMESTAMP" \
        '{
            environment_tag: $env_tag,
            cpu_model: $cpu,
            microcode: $microcode,
            kernel: $kernel,
            glibc: $glibc,
            node_version: $node_ver,
            rust_version: $rust_ver,
            ram_kb: ($ram_kb | tonumber),
            hypervisor: $hyper,
            filesystem_type: $fs_type,
            thermal_zone0_milli_c: (if $thermal == "" then null else ($thermal | tonumber) end),
            timestamp_utc: $ts
        }' > "$out_path"
}

# ----------------------------------------------------------------------
# Build steps
# ----------------------------------------------------------------------

build_rust() {
    local repo_dir="$1"
    log "cargo build --release for verifier + benchmark harness"
    ( cd "$repo_dir" && cargo build --release -p aps-verifier-core )
    ( cd "$repo_dir" && cargo build --release -p aps-bench-prototype-1 )
}

build_ts_sdk() {
    local repo_dir="$1"
    log "npm install + napi build for aps-sdk-runtime"
    ( cd "$repo_dir/packages/aps-sdk-runtime" && npm install --no-audit --no-fund )
    ( cd "$repo_dir/packages/aps-sdk-runtime" && npm run build )
}

# ----------------------------------------------------------------------
# Benchmark execution. aps-bench uses positional args: L0 or L1, with an
# optional --concurrent flag for the sweep. No --config flag exists; the
# binary detects its environment via env_capture::capture().
# ----------------------------------------------------------------------

run_l0_l1() {
    local repo_dir="$1"
    log "running L0 (single-thread)"
    ( cd "$repo_dir" && cargo run --release --bin aps-bench -- L0 )
    log "running L1 (single-thread)"
    ( cd "$repo_dir" && cargo run --release --bin aps-bench -- L1 )
    log "running L0 concurrency sweep N=1..16"
    ( cd "$repo_dir" && cargo run --release --bin aps-bench -- L0 --concurrent )
    log "running L1 concurrency sweep N=1..16"
    ( cd "$repo_dir" && cargo run --release --bin aps-bench -- L1 --concurrent )
}

run_l2_l3() {
    local repo_dir="$1"
    local env_tag="$2"
    log "running L2/L3a/L3b1/L3b2 via TS bench runner"
    ( cd "$repo_dir/packages/aps-sdk-runtime" \
      && APS_RESULTS_ENV_TAG="$env_tag" npx tsx benchmarks/runner.ts )
}

run_l4() {
    local repo_dir="$1"
    local env_tag="$2"
    local gateway_repo_dir="$3"

    log "starting local gateway on :$GATEWAY_PORT"
    (   cd "$gateway_repo_dir" \
        && PORT="$GATEWAY_PORT" npx tsx src/server.ts \
            > /tmp/gateway-canonical.log 2>&1 & echo $! > /tmp/gateway-canonical.pid )
    sleep 2

    local healthy=0
    for _ in $(seq 1 30); do
        if curl -fs -m 2 "http://localhost:$GATEWAY_PORT/healthz" >/dev/null 2>&1; then
            healthy=1
            break
        fi
        sleep 1
    done
    if [[ "$healthy" != "1" ]]; then
        die "gateway never became healthy on :$GATEWAY_PORT (see /tmp/gateway-canonical.log)"
    fi

    log "seeding L4 test tenant"
    # shellcheck disable=SC1091
    L4_DB_PATH="$gateway_repo_dir/gateway.db" \
    L4_GATEWAY_URL="http://localhost:$GATEWAY_PORT" \
        source "$repo_dir/benchmarks/prototype-1/scripts/seed-l4-tenant.sh"
    # seed-l4-tenant.sh exports L4_API_KEY, L4_TENANT_ID, L4_AGENT_ID

    log "running L4 benchmark (sample=$L4_SAMPLE_COUNT warmup=$L4_WARMUP_COUNT)"
    (   cd "$repo_dir/packages/aps-sdk-runtime" \
      && L4_API_KEY="$L4_API_KEY" \
         L4_GATEWAY_URL="http://localhost:$GATEWAY_PORT" \
         L4_GATEWAY_LOC="$env_tag" \
         L4_AGENT_ID="$L4_AGENT_ID" \
         L4_SAMPLE_COUNT="$L4_SAMPLE_COUNT" \
         L4_WARMUP_COUNT="$L4_WARMUP_COUNT" \
         APS_RESULTS_ENV_TAG="$env_tag" \
         npx tsx benchmarks/l4-runner.ts )
}

cleanup_l4() {
    local gateway_repo_dir="$1"
    local tenant_name="${L4_TENANT_NAME:-l4-bench}"

    if [[ -f /tmp/gateway-canonical.pid ]]; then
        local pid
        pid="$(cat /tmp/gateway-canonical.pid)"
        if kill -0 "$pid" 2>/dev/null; then
            log "stopping local gateway pid=$pid"
            kill "$pid" || true
            sleep 1
        fi
        rm -f /tmp/gateway-canonical.pid
    fi

    if [[ -f "$gateway_repo_dir/gateway.db" ]]; then
        log "cleaning L4 test rows from gateway.db"
        sqlite3 "$gateway_repo_dir/gateway.db" \
            "DELETE FROM tenants WHERE name='$tenant_name';
             DELETE FROM agents WHERE agent_id='l4-bench-agent';
             DELETE FROM delegations WHERE parent_agent_id='l4-bench-agent';" \
            || true
    fi
}

# ----------------------------------------------------------------------
# Schema validation
# ----------------------------------------------------------------------

validate_schemas() {
    local results_dir="$1"
    local errors=0
    for f in L0.json L1.json L2.json L3a.json L3b1.json L3b2.json L4.json; do
        if [[ ! -f "$results_dir/$f" ]]; then
            log "schema validation: missing $f"
            errors=$((errors+1))
        fi
    done
    if [[ ! -f "$results_dir/env_capture.json" ]]; then
        log "schema validation: missing env_capture.json"
        errors=$((errors+1))
    fi
    if [[ $errors -gt 0 ]]; then
        die "schema validation failed: $errors missing file(s)"
    fi
    log "schema validation OK"
}

# ----------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------

main() {
    require_cmd date
    require_cmd uname

    log "APS canonical-measurement runner starting"

    install_prereqs
    require_cmd jq
    require_cmd git

    local env_tag
    env_tag="$(detect_environment_tag)"
    log "environment-tag = $env_tag"

    mkdir -p "$WORK_DIR"
    local repo_dir="$WORK_DIR/agent-passport-system"
    clone_repo "$repo_dir"

    local results_dir="$repo_dir/benchmarks/prototype-1/results/$env_tag"
    mkdir -p "$results_dir"

    write_env_capture "$results_dir/env_capture.json" "$env_tag"

    build_rust "$repo_dir"
    build_ts_sdk "$repo_dir"

    run_l0_l1 "$repo_dir"
    run_l2_l3 "$repo_dir" "$env_tag"

    if [[ -n "$GATEWAY_REPO_URL" ]]; then
        local gateway_repo_dir
        if [[ "$GATEWAY_REPO_URL" =~ ^file:// ]]; then
            gateway_repo_dir="${GATEWAY_REPO_URL#file://}"
        else
            gateway_repo_dir="$WORK_DIR/aeoess-gateway"
            if [[ ! -d "$gateway_repo_dir/.git" ]]; then
                log "cloning gateway repo for L4"
                git clone --depth 1 "$GATEWAY_REPO_URL" "$gateway_repo_dir"
            fi
        fi
        if [[ ! -d "$gateway_repo_dir/node_modules" ]]; then
            log "installing gateway npm dependencies"
            ( cd "$gateway_repo_dir" && npm install --no-audit --no-fund )
        fi
        trap 'cleanup_l4 "'"$gateway_repo_dir"'"' EXIT
        run_l4 "$repo_dir" "$env_tag" "$gateway_repo_dir"
    else
        log "APS_GATEWAY_REPO_URL not set; skipping L4. Set it to enable."
    fi

    validate_schemas "$results_dir"

    local tar_path
    tar_path="/tmp/aps-prototype-1-results-${env_tag}-${TIMESTAMP}.tar.gz"
    tar -czf "$tar_path" -C "$repo_dir/benchmarks/prototype-1/results" "$env_tag"
    log "results tar: $tar_path"
    echo "$tar_path"
}

main "$@"
