#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
#MISE description="Run E2E tests (requires root, containerd, btrfs)"
#MISE depends=["build"]
set -euo pipefail

echo "Running E2E tests..."
cd tests/e2e && go test -v -count=1 -parallel 1 -timeout 10m "$@" .
echo "✓ E2E tests passed"
