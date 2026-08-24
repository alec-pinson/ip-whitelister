package main

import (
	"errors"
	"log"
	"net"
	"strings"
)

type IpType int

const (
	Undefined IpType = iota
	IpV4
	IpV6
)

// Supported values for a resource's ip_version field.
const (
	ipVersionV4   = "ipv4"
	ipVersionV6   = "ipv6"
	ipVersionBoth = "both"
)

// function to split an array of strings
func chunkList(array []string, count int) [][]string {
	lena := len(array)
	lenb := lena/count + 1
	b := make([][]string, lenb)

	for i := range b {
		start := i * count
		end := start + count
		if end > lena {
			end = lena
		}
		b[i] = array[start:end]
	}

	return b
}

// ipRange returns the first and last address of cidr. Bounds are computed with
// byte-wise mask arithmetic, so it works for IPv4 and IPv6 alike. It
// deliberately does not enumerate the range: an IPv6 /64 holds 1.8e19
// addresses, and no caller needs the full list. A bare address is its own first
// and last. An unparseable value returns an error rather than exiting.
func ipRange(cidr string) (first string, last string, err error) {
	if !strings.Contains(cidr, "/") {
		if _, err := ipVersion(cidr); err != nil {
			return "", "", err
		}
		return cidr, cidr, nil
	}

	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return "", "", err
	}

	firstIP := make(net.IP, len(network.IP))
	lastIP := make(net.IP, len(network.IP))
	for i := range network.IP {
		firstIP[i] = network.IP[i] & network.Mask[i]
		lastIP[i] = network.IP[i] | ^network.Mask[i]
	}
	return firstIP.String(), lastIP.String(), nil
}

// function to check if any of the users groups are in the resources groups list
func hasGroup(resourceGroups []string, userGroups []string) bool {
	if resourceGroups == nil {
		return true
	}
	for _, rg := range resourceGroups {
		for _, ug := range userGroups {
			if rg == ug {
				return true
			}
		}
	}
	return false
}

// matchesIpVersion reports whether ip is a parseable address (with or without a
// netmask) of the address family selected by a resource's ip_version. An empty
// want means ipv4, which is the default for every resource type except Front
// Door. Unparseable input never matches.
func matchesIpVersion(want, ip string) bool {
	t, err := ipVersion(ip)
	if err != nil {
		return false
	}
	switch want {
	case ipVersionV6:
		return t == IpV6
	case ipVersionBoth:
		return true
	default:
		return t == IpV4
	}
}

// ipVersion returns whether ip (with or without a netmask) is IPv4 or IPv6.
func ipVersion(ip string) (IpType, error) {
	parsed := net.ParseIP(deleteNetmask(ip))
	if parsed == nil {
		log.Printf("functions.ipVersion(): cannot parse ip '%s'", ip)
		return Undefined, errors.New("cannot parse ip '" + ip + "'")
	}
	if parsed.To4() != nil {
		return IpV4, nil
	}
	return IpV6, nil
}

// addNetmask appends the single-host netmask (/32 for IPv4, /128 for IPv6) when
// ip has none. IPs that already carry a netmask are returned unchanged.
func addNetmask(ip string) (string, error) {
	if strings.Contains(ip, "/") {
		return ip, nil
	}
	ipType, err := ipVersion(ip)
	if err != nil {
		return "", err
	}
	if ipType == IpV4 {
		return ip + "/32", nil
	}
	return ip + "/128", nil
}

// deleteNetmask strips any /netmask suffix, returning just the address.
func deleteNetmask(ip string) string {
	return strings.Split(ip, "/")[0]
}
