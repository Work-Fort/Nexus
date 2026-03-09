#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
#MISE description="Run all tests"
set -euo pipefail

echo "Running all tests..."
go test ./...
echo "✓ All tests passed"
