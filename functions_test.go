package main

import "testing"

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

func TestIsIpv4(t *testing.T) {

	tests := []struct {
		ip      string
		success bool
	}{
		{"12.12.12.12/32", true},
		{"1.2.3.4/32", true},
		{"2a00:11c7:1234:b801:a16e:12af:5e42:1100/32", false},
		{"2a00:11c7:1234:b801:a16e:12af:5e42:1111/32", false},
	}

	for _, f := range tests {
		success := isIpv4(f.ip)
		if success != f.success {
			t.Errorf("isIpv4 for %v was incorrect, got %v, want %v", f, success, f.success)
		}
	}

}
