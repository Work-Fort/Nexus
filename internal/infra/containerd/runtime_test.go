// SPDX-License-Identifier: GPL-3.0-or-later
package containerd

import (
	"github.com/Work-Fort/Nexus/internal/domain"
)

// Compile-time interface compliance check.
var _ domain.Runtime = (*Runtime)(nil)
