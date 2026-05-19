#!/usr/bin/env bash
# Cross-SDK test CLI helper for the OpenTDF Java SDK.
# Called by the xtest harness to check feature support and run encrypt/decrypt ops.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
JAR="${REPO_ROOT}/cmdline/target/cmdline.jar"

_jar_help() {
    java -jar "${JAR}" "$@" --help 2>&1 || true
}

case "${1:-}" in
  supports)
    feature="${2:-}"
    case "$feature" in
      mechanism-mlkem)
        # mlkem:768 is a valid --encap-key-type value; picocli lists it in the
        # encrypt help as a COMPLETION-CANDIDATE from KeyType.MLKEM768Key.toString()
        _jar_help encrypt | grep -q "mlkem:768"
        ;;
      *)
        exit 1
        ;;
    esac
    ;;
  encrypt)
    shift
    java -jar "${JAR}" encrypt "$@"
    ;;
  decrypt)
    shift
    java -jar "${JAR}" decrypt "$@"
    ;;
  *)
    echo "usage: $0 {supports <feature>|encrypt ...|decrypt ...}" >&2
    exit 1
    ;;
esac
