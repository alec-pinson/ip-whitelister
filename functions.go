package main

import (
	"encoding/binary"
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

// function to get ips in subnet range
func getIpList(cidr string) (first string, last string, all []string) {
	var ret []string
	if !strings.Contains(cidr, "/") {
		// single ip
		return cidr, cidr, []string{cidr}
	}
	// convert string to IPNet struct
	_, ipv4Net, err := net.ParseCIDR(cidr)
	if err != nil {
		log.Fatal("functions.getIpList():", err)
	}

	// convert IPNet struct mask and address to uint32
	// network is BigEndian
	mask := binary.BigEndian.Uint32(ipv4Net.Mask)
	start := binary.BigEndian.Uint32(ipv4Net.IP)

	// find the final address
	finish := (start & mask) | (mask ^ 0xffffffff)

	// loop through addresses as uint32
	for i := start; i <= finish; i++ {
		// convert back to net.IP
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, i)
		ret = append(ret, ip.String())
	}
	return ret[0], ret[len(ret)-1], ret
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

// isValidIpOrNetV4 reports whether ip is a parseable IPv4 address or IPv4 CIDR.
func isValidIpOrNetV4(ip string) bool {
	ipType, err := ipVersion(ip)
	return err == nil && ipType == IpV4
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
