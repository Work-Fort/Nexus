// SPDX-License-Identifier: Apache-2.0
package containerd

import (
	"github.com/Work-Fort/Nexus/internal/domain"
)

// Compile-time interface compliance check.
var _ domain.Runtime = (*Runtime)(nil)
