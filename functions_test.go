package main

import (
	"testing"
)

func TestChunkList(t *testing.T) {

	lists := []struct {
		array   []string
		count   int
		success int
	}{
		{[]string{"list1"}, 1, 2},
		{[]string{"list1", "list2"}, 1, 3},
		{[]string{"list1", "list2", "list3"}, 1, 4},
		{[]string{"list1", "list2", "list3", "list4", "list5"}, 1, 6},
	}

	for _, f := range lists {
		length := len(chunkList(f.array, f.count))
		if length != f.success {
			t.Errorf("chunkList for %v was incorrect, got %v, want %v", f, length, f.success)
		}
	}

}

func TestIpRange(t *testing.T) {
	tests := []struct {
		cidr         string
		successFirst string
		successLast  string
	}{
		// IPv4 — same expectations the old getIpList test asserted
		{"10.0.0.0/31", "10.0.0.0", "10.0.0.1"},
		{"200.0.0.0/30", "200.0.0.0", "200.0.0.3"},
		{"10.0.0.1", "10.0.0.1", "10.0.0.1"},
		{"1.2.3.4/32", "1.2.3.4", "1.2.3.4"},
		{"10.0.0.0/24", "10.0.0.0", "10.0.0.255"},

		// IPv6 — the family the old implementation silently corrupted
		{"2a00:11c7:1234:b801::/64", "2a00:11c7:1234:b801::", "2a00:11c7:1234:b801:ffff:ffff:ffff:ffff"},
		{"2a00:11c7:1234:b801::1/128", "2a00:11c7:1234:b801::1", "2a00:11c7:1234:b801::1"},
		{"2a00:11c7:1234:b801::1", "2a00:11c7:1234:b801::1", "2a00:11c7:1234:b801::1"},
	}

	for _, f := range tests {
		first, last, err := ipRange(f.cidr)
		if err != nil {
			t.Errorf("ipRange(%q) returned unexpected error %v", f.cidr, err)
			continue
		}
		if first != f.successFirst {
			t.Errorf("ipRange(%q) first = %v, want %v", f.cidr, first, f.successFirst)
		}
		if last != f.successLast {
			t.Errorf("ipRange(%q) last = %v, want %v", f.cidr, last, f.successLast)
		}
	}
}

// TestIpRangeInvalid asserts a bad value returns an error rather than calling
// log.Fatal and taking the process down mid-reconcile, as getIpList did.
func TestIpRangeInvalid(t *testing.T) {
	for _, cidr := range []string{"not-an-ip", "10.0.0.0/99", "10.0.0.0/", ""} {
		if _, _, err := ipRange(cidr); err == nil {
			t.Errorf("ipRange(%q) should return an error", cidr)
		}
	}
}

func TestHasGroup(t *testing.T) {

	groups := []struct {
		resourceGroup []string
		userGroup     []string
		success       bool
	}{
		{[]string{"group1", "group2"}, []string{"group1", "group5"}, true},
		{[]string{"group5"}, []string{"group5", "group10"}, true},
		{[]string{"group1", "group2"}, []string{"group6", "group2"}, true},
		{[]string{"group1"}, []string{"group9", "group10", "group11"}, false},
		// a no-auth user has no groups -> group-scoped resources are skipped
		{[]string{"group1"}, nil, false},
		{[]string{"group1", "group2", "group3", "group4"}, []string{"group5"}, false},
		// a resource with no group restriction (nil) is open to everyone
		{nil, []string{"group1"}, true},
		{nil, nil, true},
	}

	for _, f := range groups {
		success := hasGroup(f.resourceGroup, f.userGroup)
		if success != f.success {
			t.Errorf("hasGroup for %v was incorrect, got %v, want %v", f, success, f.success)
		}
	}

}

func TestMatchesIpVersion(t *testing.T) {
	tests := []struct {
		want    string
		ip      string
		success bool
	}{
		// an empty want behaves as ipv4, which is the default for every
		// resource type except Front Door
		{"", "1.2.3.4", true},
		{"", "1.2.3.0/24", true},
		{"", "2a00:11c7:1234:b801::1", false},

		{"ipv4", "1.2.3.4", true},
		{"ipv4", "1.2.3.4/32", true},
		{"ipv4", "1.2.3.0/24", true},
		{"ipv4", "2a00:11c7:1234:b801::1", false},
		{"ipv4", "2a00:11c7:1234:b801::/64", false},

		{"ipv6", "2a00:11c7:1234:b801::1", true},
		{"ipv6", "2a00:11c7:1234:b801::1/128", true},
		{"ipv6", "2a00:11c7:1234:b801::/64", true},
		{"ipv6", "1.2.3.4", false},
		{"ipv6", "1.2.3.0/24", false},

		{"both", "1.2.3.4", true},
		{"both", "2a00:11c7:1234:b801::1", true},
		{"both", "1.2.3.0/24", true},
		{"both", "2a00:11c7:1234:b801::/64", true},

		// unparseable input is never a match, whatever the family
		{"ipv4", "not-an-ip", false},
		{"ipv6", "not-an-ip", false},
		{"both", "not-an-ip", false},
		{"", "not-an-ip", false},
	}

	for _, f := range tests {
		success := matchesIpVersion(f.want, f.ip)
		if success != f.success {
			t.Errorf("matchesIpVersion(%q, %q) = %v, want %v", f.want, f.ip, success, f.success)
		}
	}
}

func TestIpVersion(t *testing.T) {
	tests := []struct {
		ip      string
		version IpType
	}{
		{"12.12.12.12/32", IpV4},
		{"1.2.3.4", IpV4},
		{"1.2.3.0/24", IpV4},
		{"2a00:11c7:1234:b801:a16e:12af:5e42:1100/32", IpV6},
		{"2a00:11c7:1234:b801:a16e:12af:5e42:1100/128", IpV6},
		{"2a00:11c7:1234:b801:a16e:12af:42:11", IpV6},
	}

	for _, f := range tests {
		version, err := ipVersion(f.ip)
		if err != nil {
			t.Errorf("ipVersion for %v returned unexpected error %v", f, err)
		}
		if version != f.version {
			t.Errorf("ipVersion for %v was incorrect, got %v, want %v", f, version, f.version)
		}
	}

	if _, err := ipVersion("not-an-ip"); err == nil {
		t.Errorf("ipVersion for an unparseable value should return an error")
	}
}

func TestAddNetmask(t *testing.T) {
	tests := []struct {
		ip         string
		ipWithMask string
	}{
		{"12.12.12.12/32", "12.12.12.12/32"},
		{"1.2.3.4", "1.2.3.4/32"},
		{"1.2.3.0/24", "1.2.3.0/24"},
		{"2a00:11c7:1234:b801:a16e:12af:5e42:1100/32", "2a00:11c7:1234:b801:a16e:12af:5e42:1100/32"},
		{"2a00:11c7:1234:b801:a16e:12af:5e42:1111", "2a00:11c7:1234:b801:a16e:12af:5e42:1111/128"},
	}

	for _, f := range tests {
		ipWithMask, err := addNetmask(f.ip)
		if err != nil {
			t.Errorf("addNetmask for %v returned unexpected error %v", f, err)
		}
		if ipWithMask != f.ipWithMask {
			t.Errorf("addNetmask for %v was incorrect, got %v, want %v", f, ipWithMask, f.ipWithMask)
		}
	}
}

func TestAddNetmaskInvalid(t *testing.T) {
	// an unparseable address cannot have a netmask inferred and must error
	if _, err := addNetmask("not-an-ip"); err == nil {
		t.Errorf("addNetmask for an unparseable value should return an error")
	}
}

func TestDeleteNetmask(t *testing.T) {
	tests := []struct {
		ip            string
		ipWithoutMask string
	}{
		{"12.12.12.12/32", "12.12.12.12"},
		{"1.2.3.4", "1.2.3.4"},
		{"1.2.3.0/24", "1.2.3.0"},
		{"2a00:11c7:1234:b801:a16e:12af:5e42:1100/32", "2a00:11c7:1234:b801:a16e:12af:5e42:1100"},
		{"2a00:11c7:1234:b801:a16e:12af:5e42:1111", "2a00:11c7:1234:b801:a16e:12af:5e42:1111"},
	}

	for _, f := range tests {
		ipWithoutMask := deleteNetmask(f.ip)
		if ipWithoutMask != f.ipWithoutMask {
			t.Errorf("deleteNetmask for %v was incorrect, got %v, want %v", f, ipWithoutMask, f.ipWithoutMask)
		}
	}
}
