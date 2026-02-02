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

cargo build --bin lpass --manifest-path "$ROOT_DIR/Cargo.toml"

mkdir -p "$UPSTREAM_BUILD_DIR"
ln -snf ../../target/debug/lpass "$UPSTREAM_TEST_BIN"

cd "$UPSTREAM_TEST_DIR"
export LPASS_HTTP_MOCK=1

if [[ $# -eq 0 ]]; then
  ./tests
  exit $?
fi

ret=0
for test_name in "$@"; do
  ./tests "$test_name" || ret=1
done
exit "$ret"
