package server

import (
	"net"
	"net/netip"
	"strconv"

	"rabbit.go/transport"
)

// A named interface supports dynamic private pod addresses without wildcard
// exposure. Resolve it once at startup; address changes require a restart.
func privateBindAddress(listen, interfaceName string) (string, error) {
	host, port, err := net.SplitHostPort(listen)
	number, portErr := strconv.Atoi(port)
	if err != nil || portErr != nil || number < 1 || number > 65535 || strconv.Itoa(number) != port {
		return "", transport.ErrAuthority
	}
	if interfaceName != "" {
		if host != "" || len(interfaceName) > 64 {
			return "", transport.ErrAuthority
		}
		iface, err := net.InterfaceByName(interfaceName)
		if err != nil || iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			return "", transport.ErrAuthority
		}
		addresses, err := iface.Addrs()
		if err != nil {
			return "", transport.ErrAuthority
		}
		host, err = onePrivateInterfaceAddress(addresses)
		if err != nil {
			return "", err
		}
	}
	address, err := netip.ParseAddr(host)
	if err != nil || address.Zone() != "" || !(address.IsLoopback() || address.IsPrivate()) {
		return "", transport.ErrAuthority
	}
	return net.JoinHostPort(address.String(), port), nil
}

func onePrivateInterfaceAddress(addresses []net.Addr) (string, error) {
	var selected netip.Addr
	for _, address := range addresses {
		prefix, err := netip.ParsePrefix(address.String())
		if err != nil || !prefix.Addr().IsPrivate() || !prefix.Addr().IsGlobalUnicast() {
			continue
		}
		candidate := prefix.Addr().Unmap()
		if selected.IsValid() && candidate != selected {
			return "", transport.ErrAuthority
		}
		selected = candidate
	}
	if !selected.IsValid() {
		return "", transport.ErrAuthority
	}
	return selected.String(), nil
}
