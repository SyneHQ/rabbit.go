package transport

// RouteInfo is a routing snapshot, never a connection capability. Only the
// trusted issuer may bind an application's source revision to this exact route.
// Reconnect, restart or token revocation invalidates the snapshot.
type RouteInfo struct {
	Tenant          string `json:"tenant"`
	TokenID         string `json:"token_id"`
	TokenGeneration string `json:"token_generation"`
	TunnelID        string `json:"tunnel_id"`
	ControlOwner    string `json:"control_owner"`
}

func (r RouteInfo) Validate() error {
	if !textValue(r.Tenant, 128) || !textValue(r.TokenID, 128) || !hexValue(r.TokenGeneration, 64) ||
		!hexValue(r.TunnelID, 64) || !hexValue(r.ControlOwner, 64) {
		return ErrAuthority
	}
	return nil
}
