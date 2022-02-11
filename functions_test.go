package main

import (
	"reflect"
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

func TestGetIpList(t *testing.T) {
	tests := []struct {
		cidr         string
		successFirst string
		successLast  string
		successAll   []string
	}{
		{"10.0.0.0/31", "10.0.0.0", "10.0.0.1", []string{"10.0.0.0", "10.0.0.1"}},
		{"200.0.0.0/30", "200.0.0.0", "200.0.0.3", []string{"200.0.0.0", "200.0.0.1", "200.0.0.2", "200.0.0.3"}},
		{"10.0.0.1", "10.0.0.1", "10.0.0.1", []string{"10.0.0.1"}},
	}

	for _, f := range tests {
		first, last, all := getIpList(f.cidr)
		if first != f.successFirst {
			t.Errorf("getIpList for %v was incorrect, got %v, want %v", f, first, f.successFirst)
		}
		if last != f.successLast {
			t.Errorf("getIpList for %v was incorrect, got %v, want %v", f, last, f.successLast)
		}
		if !reflect.DeepEqual(all, f.successAll) {
			t.Errorf("getIpList for %v was incorrect, got %v, want %v", f, all, f.successAll)
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
		{[]string{"group1", "group2", "group3", "group4"}, []string{"group5"}, false},
	}

	for _, f := range groups {
		success := hasGroup(f.resourceGroup, f.userGroup)
		if success != f.success {
			t.Errorf("hasGroup for %v was incorrect, got %v, want %v", f, success, f.success)
		}
	}
}

func TestIsIpOrNetv4(t *testing.T) {
	tests := []struct {
		ip      string
		success bool
	}{
		{"12.12.12.12/32", true},
		{"1.2.3.4/32", true},
		{"1.2.3.4", true},
		{"2a00:11c7:1234:b801:a16e:12af:5e42:1100/32", false},
		{"2a00:11c7:1234:b801:a16e:12af:5e42:1111/32", false},
		{"2a00:11c7:1234:b801:a16e:12af:5e42:1111", false},
	}

	for _, f := range tests {
		success := isValidIpOrNetV4(f.ip)
		if success != f.success {
			t.Errorf("isValidIpOrNetV4 for %v was incorrect, got %v, want %v", f, success, f.success)
		}
	}
}

func TestAddNetmask(t *testing.T) {
	tests := []struct {
		ip         string
		ipWithMask string
	}{
		{"12.12.12.12/32", "12.12.12.12/32"},
		{"1.2.3.4", "1.2.3.4/32"},
		{"2a00:11c7:1234:b801:a16e:12af:5e42:1100/32", "2a00:11c7:1234:b801:a16e:12af:5e42:1100/32"},
		{"2a00:11c7:1234:b801:a16e:12af:5e42:1111", "2a00:11c7:1234:b801:a16e:12af:5e42:1111/128"},
	}

	for _, f := range tests {
		ipWithMask, _ := addNetmask(f.ip)
		if ipWithMask != f.ipWithMask {
			t.Errorf("addNetmask for %v was incorrect, got %v, want %v", f, ipWithMask, f.ipWithMask)
		}
	}
}

func TestDeleteNetmask(t *testing.T) {
	tests := []struct {
		ip            string
		ipWithoutMask string
	}{
		{"12.12.12.12/32", "12.12.12.12"},
		{"1.2.3.4", "1.2.3.4"},
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

func TestIpVersion(t *testing.T) {
	tests := []struct {
		ip        string
		ipVersion IpType
	}{
		{"12.12.12.12/32", IpV4},
		{"1.2.3.4", IpV4},
		{"1.2.3.0/24", IpV4},
		{"2a00:11c7:1234:b801:a16e:12af:5e42:1100/32", IpV6},
		{"2a00:11c7:1234:b801:a16e:12af:5e42:1100/128", IpV6},
		{"2a00:11c7:1234:b801:a16e:12af:42:11", IpV6},
	}

	for _, f := range tests {
		ipVer, err := ipVersion(f.ip)
		if err != nil {
			t.Errorf("ipVersion for %v was incorrect, got error %v, want %v", f, err, f.ipVersion)
		}
		if ipVer != f.ipVersion {
			t.Errorf("ipVersion for %v was incorrect, got %v, want %v", f, ipVer, f.ipVersion)
		}
	}
}
