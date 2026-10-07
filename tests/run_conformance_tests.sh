#!/usr/bin/env bash
# Build and run the ngPost conformance test suite over the vendored yEnc
# encryption standards v1.2 fixtures. Builds in a per-user scratch directory
# (reused across runs) so the source tree stays clean.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${TMPDIR:-/tmp}/ngpost-conformance-$(id -u)"
mkdir -p "$BUILD_DIR"

cd "$BUILD_DIR"
qmake "$SCRIPT_DIR/ConformanceVectors.pro"
make -j2
# TEST_VECTORS_DIR is baked in at qmake time from the .pro location, so the
# binary reads the vendored fixtures inside the ngPost source tree regardless
# of the build directory.
./ConformanceVectors
