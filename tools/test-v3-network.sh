#!/usr/bin/env bash
set -euo pipefail

REPO_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
RUN_DIR=$(mktemp -d /tmp/gp-v3-network-test.XXXXXX)
BIN="$REPO_DIR/target/debug/gp-network"
BASE_PORT=${GP_V3_TEST_BASE_PORT:-19200}
PIDS=()

cleanup() {
  for pid in "${PIDS[@]}"; do
    kill "$pid" 2>/dev/null || true
  done
  wait 2>/dev/null || true
  case "$RUN_DIR" in
    /tmp/gp-v3-network-test.*) rm -rf -- "$RUN_DIR" ;;
  esac
}
trap cleanup EXIT INT TERM

start_node() {
  local name=$1
  local role=$2
  local port=$3
  shift 3
  mkdir -p "$RUN_DIR/$name"
  "$BIN" serve --role "$role" --listen "127.0.0.1:$port" \
    --data-dir "$RUN_DIR/$name" "$@" >"$RUN_DIR/$name.log" 2>&1 &
  PIDS+=("$!")
}

wait_http() {
  local url=$1
  local attempts=0
  until curl -fsS "$url" >/dev/null 2>&1; do
    attempts=$((attempts + 1))
    if (( attempts >= 100 )); then
      printf 'node did not become ready: %s\n' "$url" >&2
      return 1
    fi
    sleep 0.1
  done
}

wait_file() {
  local path=$1
  local attempts=0
  until [[ -s "$path" ]]; do
    attempts=$((attempts + 1))
    if (( attempts >= 100 )); then
      printf 'file did not become ready: %s\n' "$path" >&2
      return 1
    fi
    sleep 0.1
  done
}

cd "$REPO_DIR"
cargo build -p gp-network

start_node relay relay "$BASE_PORT" --relay-token relay-secret --admin-token admin-secret
for id in 1 2 3; do
  start_node "s$id" signer "$((BASE_PORT + 10 + id))" \
    --admin-token admin-secret --auto-approve
done
for id in 1 2 3 4 5; do
  start_node "g$id" guardian "$((BASE_PORT + 20 + id))" \
    --admin-token admin-secret --allow-insecure-demo-delay
done
for id in 1 2 3 4; do
  start_node "w$id" witness "$((BASE_PORT + 30 + id))" --admin-token admin-secret
done
wait_http "http://127.0.0.1:$BASE_PORT/v1/health"
for port in \
  "$((BASE_PORT + 11))" "$((BASE_PORT + 12))" "$((BASE_PORT + 13))" \
  "$((BASE_PORT + 21))" "$((BASE_PORT + 22))" "$((BASE_PORT + 23))" \
  "$((BASE_PORT + 24))" "$((BASE_PORT + 25))" \
  "$((BASE_PORT + 31))" "$((BASE_PORT + 32))" "$((BASE_PORT + 33))" \
  "$((BASE_PORT + 34))"; do
  wait_http "http://127.0.0.1:$port/v3/node-info"
done

"$BIN" setup-v3 \
  --secret 'live v3 rotation proof' \
  --relay "http://127.0.0.1:$BASE_PORT" \
  --relay-token relay-secret --admin-token admin-secret \
  --signer "http://127.0.0.1:$((BASE_PORT + 11))" \
  --signer "http://127.0.0.1:$((BASE_PORT + 12))" \
  --signer "http://127.0.0.1:$((BASE_PORT + 13))" \
  --guardian "http://127.0.0.1:$((BASE_PORT + 21))" \
  --guardian "http://127.0.0.1:$((BASE_PORT + 22))" \
  --guardian "http://127.0.0.1:$((BASE_PORT + 23))" \
  --witness "http://127.0.0.1:$((BASE_PORT + 31))" \
  --witness "http://127.0.0.1:$((BASE_PORT + 32))" \
  --witness "http://127.0.0.1:$((BASE_PORT + 33))" \
  --witness "http://127.0.0.1:$((BASE_PORT + 34))" \
  --signer-threshold 2 --guardian-threshold 2 --witness-fault-bound 1 \
  --delay-secs 2 --card "$RUN_DIR/card.json" --owner-control "$RUN_DIR/owner.json"

"$BIN" recover-v3 --card "$RUN_DIR/card.json" --output "$RUN_DIR/before.bin"
cmp -s "$RUN_DIR/before.bin" <(printf %s 'live v3 rotation proof')

# The guardian being replaced is deliberately unavailable. Rotation must be
# driven by the old threshold, never by cooperation from the failed member.
kill "${PIDS[4]}"
wait "${PIDS[4]}" 2>/dev/null || true
# With f=1, three of four witnesses must be sufficient for both activation and
# the fresh read that precedes the next rotation/recovery.
kill "${PIDS[12]}"
wait "${PIDS[12]}" 2>/dev/null || true

"$BIN" rotate-v3 --card "$RUN_DIR/card.json" --owner-control "$RUN_DIR/owner.json" \
  --remove-guardian 1 --replacement-guardian "http://127.0.0.1:$((BASE_PORT + 24))" \
  --rotation-control "$RUN_DIR/rotation-cancelled.json" \
  --relay-token relay-secret --admin-token admin-secret \
  >"$RUN_DIR/rotation-cancelled.log" 2>&1 &
CANCELLED_ROTATE_PID=$!
PIDS+=("$CANCELLED_ROTATE_PID")
wait_file "$RUN_DIR/rotation-cancelled.json"
"$BIN" cancel-rotation-v3 \
  --rotation-control "$RUN_DIR/rotation-cancelled.json" \
  --owner-control "$RUN_DIR/owner.json"
if wait "$CANCELLED_ROTATE_PID"; then
  printf '%s\n' 'owner-cancelled rotation unexpectedly completed' >&2
  exit 1
fi

"$BIN" rotate-v3 --card "$RUN_DIR/card.json" --owner-control "$RUN_DIR/owner.json" \
  --remove-guardian 1 --replacement-guardian "http://127.0.0.1:$((BASE_PORT + 24))" \
  --rotation-control "$RUN_DIR/rotation-1.json" \
  --relay-token relay-secret --admin-token admin-secret
"$BIN" rotate-v3 --card "$RUN_DIR/card.json" --owner-control "$RUN_DIR/owner.json" \
  --remove-guardian 2 --replacement-guardian "http://127.0.0.1:$((BASE_PORT + 25))" \
  --rotation-control "$RUN_DIR/rotation-2.json" \
  --relay-token relay-secret --admin-token admin-secret

"$BIN" discover-v3 --card "$RUN_DIR/card.json" | grep -q 'ACTIVE GUARDIAN EPOCH: 3'
"$BIN" recover-v3 --card "$RUN_DIR/card.json" --output "$RUN_DIR/after.bin"
cmp -s "$RUN_DIR/after.bin" <(printf %s 'live v3 rotation proof')
printf '%s\n' \
  'v3 live-network proof passed: recovery -> owner-cancel/retry -> guardian+witness outages -> two rotations -> recovery'
