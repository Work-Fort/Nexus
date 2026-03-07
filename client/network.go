// SPDX-License-Identifier: GPL-3.0-or-later
package client

import (
	"context"
	"net/http"
)

// ResetNetwork resets the network bridge and CNI state.
func (c *Client) ResetNetwork(ctx context.Context) error {
	return c.postExpectStatus(ctx, "/v1/network/reset", nil, http.StatusOK)
}
