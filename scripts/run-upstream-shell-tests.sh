#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN_PATH="$ROOT_DIR/target/debug/lpass"
UPSTREAM_BUILD_DIR="$ROOT_DIR/lastpass-cli/build"
UPSTREAM_TEST_DIR="$ROOT_DIR/lastpass-cli/test"
UPSTREAM_TEST_BIN="$UPSTREAM_BUILD_DIR/lpass-test"

cleanup_agent() {
  if [[ ! -x "$UPSTREAM_TEST_BIN" ]]; then
    return 0
  fi

  (
    cd "$UPSTREAM_TEST_DIR"
    export LPASS_HTTP_MOCK=1
    export LPASS_HOME="./.lpass"
    export LPASS_ASKPASS="./askpass.sh"
    "$UPSTREAM_TEST_BIN" login "user@example.com" >/dev/null 2>&1 || true
    "$UPSTREAM_TEST_BIN" logout --force >/dev/null 2>&1 || true
    rm -f "$LPASS_HOME/agent.sock" >/dev/null 2>&1 || true
  )
}
trap cleanup_agent EXIT

discover_test_names() {
  sed -n 's/^function \(test_[A-Za-z0-9_]*\).*/\1/p' "$UPSTREAM_TEST_DIR/tests"
}

run_test_case() {
  local test_name="$1"
  rm -rf "$UPSTREAM_TEST_DIR/.lpass"
  mkdir -p "$UPSTREAM_TEST_DIR/.lpass"
  printf '%s\n' "$$" > "$UPSTREAM_TEST_DIR/.lpass/uploader.pid"
  (cd "$UPSTREAM_TEST_DIR" && ./tests "$test_name")
}

cargo build --bin lpass --manifest-path "$ROOT_DIR/Cargo.toml"

mkdir -p "$UPSTREAM_BUILD_DIR"
ln -snf ../../target/debug/lpass "$UPSTREAM_TEST_BIN"

cd "$UPSTREAM_TEST_DIR"
export LPASS_HTTP_MOCK=1

if [[ $# -eq 0 ]]; then
  ret=0
  while IFS= read -r test_name; do
    [[ -n "$test_name" ]] || continue
    run_test_case "$test_name" || ret=1
  done < <(discover_test_names)
  exit "$ret"
fi

ret=0
for test_name in "$@"; do
  run_test_case "$test_name" || ret=1
done
exit "$ret"
