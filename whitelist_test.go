package main

import (
	"testing"
)

func TestAdd(t *testing.T) {
	users := []struct {
		name       string
		employeeId string
		ip         string
		cidr       string
		success    bool
	}{
		{"test user1", "111111", "10.0.0.1", "10.0.0.1/32", true},
		{"test user2", "111112", "10.0.0.2", "10.0.0.2/32", true},
		{"test user3", "111113", "10.0.0.3", "10.0.0.3/32", true},
		{"test user4", "111114", "200.0.0.4", "200.0.0.4/32", false},
		{"test user5", "111115", "200.0.0.5", "200.0.0.5/32", false},
	}

	c.IPWhiteList = append(c.IPWhiteList, "85.0.0.0/24")
	c.IPWhiteList = append(c.IPWhiteList, "200.0.0.0/24")

	var testRedisInstance = CreateTestRedis(t)
	var rc RedisConfiguration
	rc.Host = testRedisInstance.Host
	rc.Port = testRedisInstance.Port
	rc.Token = testRedisInstance.Token

	ret := r.connect(rc)

	if ret == true {
		for _, f := range users {
			var testUser User
			testUser.key = f.name
			testUser.employeeId = f.employeeId
			testUser.ip = f.ip
			testUser.cidr = f.cidr

			ret = w.add(&testUser)
			if ret != f.success {
				t.Errorf("user_test.TestAddFail(): Add IP that already exists in `ip_whitelist` range '%v', got '%v', want '%v'", f, ret, f.success)
			}
		}
	}

	DeleteTestRedis(t, testRedisInstance)
}

func TestDelete(t *testing.T) {
	users := []struct {
		name       string
		employeeId string
		ip         string
		cidr       string
		success    bool
	}{
		{"test user1", "111111", "10.0.0.1", "10.0.0.1/32", true},
		{"test user2", "111112", "10.0.0.2", "10.0.0.2/32", true},
		{"test user3", "111113", "10.0.0.3", "10.0.0.3/32", true},
		{"test user4", "111114", "10.0.0.4", "10.0.0.4/32", true},
		{"test user5", "111115", "10.0.0.5", "10.0.0.5/32", true},
	}

	var testRedisInstance = CreateTestRedis(t)
	var rc RedisConfiguration
	rc.Host = testRedisInstance.Host
	rc.Port = testRedisInstance.Port
	rc.Token = testRedisInstance.Token

	ret := r.connect(rc)

	if ret == true {
		for _, f := range users {
			var testUser User
			testUser.key = f.name + f.employeeId
			testUser.name = f.name
			testUser.employeeId = f.employeeId
			testUser.ip = f.ip
			testUser.cidr = f.cidr

			ret = w.add(&testUser)
			if ret == true {
				ret = w.delete(&testUser)
				if ret != f.success {
					t.Errorf("user_test.TestAddFail(): Add IP that already exists in `ip_whitelist` range '%v', got '%v', want '%v'", f, ret, f.success)
				}
			}
		}
	}

	DeleteTestRedis(t, testRedisInstance)
}

func TestInRange(t *testing.T) {
	tests := []struct {
		w         Whitelist
		ip        string
		whitelist []string
		success   bool
	}{
		// not in the (empty) static whitelist
		{Whitelist{map[string]string{"alecpinson123456": "123.123.123.123/32"}}, "12.12.12.12/32", []string{}, false},
		// covered by a static CIDR range
		{Whitelist{map[string]string{"alecpinson123456": "123.123.123.123/32"}}, "1.2.3.4/32", []string{"1.2.3.0/24"}, true},
		// ipv6 is not matched against an ipv4 range
		{Whitelist{map[string]string{"alecpinson123456": "123.123.123.123/32"}}, "2a00:11c7:1234:b801:a16e:12af:5e42:1100/32", []string{"1.2.3.0/24"}, false},
		// ipv6 with an empty static whitelist
		{Whitelist{map[string]string{"alecpinson123456": "123.123.123.123/32"}}, "2a00:11c7:1234:b801:a16e:12af:5e42:1111/32", []string{}, false},
		// a bare (non-CIDR) static whitelist entry that exactly matches
		{Whitelist{map[string]string{"alecpinson123456": "123.123.123.123/32"}}, "203.0.113.5", []string{"203.0.113.5"}, true},
		// a bare static whitelist entry that does not match
		{Whitelist{map[string]string{"alecpinson123456": "123.123.123.123/32"}}, "203.0.113.6", []string{"203.0.113.5"}, false},
	}

	for _, f := range tests {
		success := f.w.inRange(f.ip, f.whitelist)
		if success != f.success {
			t.Errorf("inRange for %v was incorrect, got %v, want %v", f, success, f.success)
		}
	}
}

func TestAddDualStack(t *testing.T) {
	var testRedisInstance = CreateTestRedis(t)
	var rc RedisConfiguration
	rc.Host = testRedisInstance.Host
	rc.Port = testRedisInstance.Port
	rc.Token = testRedisInstance.Token
	defer DeleteTestRedis(t, testRedisInstance)

	c.TTL = 24
	c.IPWhiteList = nil
	c.IpResolution = IpResolution{}
	defer func() { c.IpResolution = IpResolution{} }()

	if !r.connect(rc) {
		t.Fatal("could not connect to test redis")
	}

	v4 := &User{key: "dualstackuser", ip: "203.0.113.7", cidr: "203.0.113.7/32"}
	v6 := &User{key: "dualstackuser", ip: "2a00:11c7:1234:b801::1", cidr: "2a00:11c7:1234:b801::1/128"}

	if !w.add(v4) {
		t.Fatal("adding the ipv4 address failed")
	}
	if !w.add(v6) {
		t.Fatal("adding the ipv6 address failed")
	}

	list := r.getWhitelist()
	if got := list["dualstackuser"]; got != "203.0.113.7/32" {
		t.Errorf("ipv4 entry = %q, want %q", got, "203.0.113.7/32")
	}
	if got := list["dualstackuser"+redisKeySuffixV6]; got != "2a00:11c7:1234:b801::1/128" {
		t.Errorf("ipv6 entry = %q, want %q", got, "2a00:11c7:1234:b801::1/128")
	}
}

func TestAddSkipsDisabledFamily(t *testing.T) {
	var testRedisInstance = CreateTestRedis(t)
	var rc RedisConfiguration
	rc.Host = testRedisInstance.Host
	rc.Port = testRedisInstance.Port
	rc.Token = testRedisInstance.Token
	defer DeleteTestRedis(t, testRedisInstance)

	c.TTL = 24
	c.IPWhiteList = nil
	disabled := false
	c.IpResolution = IpResolution{IPv6: IpFamilyResolution{Enabled: &disabled}}
	defer func() { c.IpResolution = IpResolution{} }()

	if !r.connect(rc) {
		t.Fatal("could not connect to test redis")
	}

	v6 := &User{key: "disabledfamilyuser", ip: "2a00:11c7:1234:b801::2", cidr: "2a00:11c7:1234:b801::2/128"}
	if w.add(v6) {
		t.Error("add() should refuse an address whose family is disabled")
	}
	if got := r.getWhitelist()["disabledfamilyuser"+redisKeySuffixV6]; got != "" {
		t.Errorf("disabled family should not be stored, got %q", got)
	}
}
