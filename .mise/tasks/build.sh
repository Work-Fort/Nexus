#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
#MISE description="Build all binaries (debug)"
#MISE depends=["build:deps"]
set -euo pipefail

GIT_SHORT_SHA=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")

echo "Building debug binaries..."
go build -ldflags="-X github.com/Work-Fort/Nexus/cmd.Version=dev-$GIT_SHORT_SHA" -o build/nexus .
go build -ldflags="-X main.Version=dev-$GIT_SHORT_SHA" -o build/nexusctl ./cmd/nexusctl/
go build -o build/nexus-netns ./cmd/nexus-netns/
go build -o build/nexus-cni-exec ./cmd/nexus-cni-exec/
go build -o build/nexus-quota ./cmd/nexus-quota/
go build -o build/nexus-btrfs ./cmd/nexus-btrfs/
go build -o build/nexus-dns ./cmd/nexus-dns/
echo "✓ Debug build complete"
