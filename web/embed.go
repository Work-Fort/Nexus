//go:build !ui

// SPDX-License-Identifier: GPL-3.0-or-later
package web

import "embed"

// Dist is empty when built without the "ui" tag. Use --ui-dir to serve
// from disk during development.
var Dist embed.FS
