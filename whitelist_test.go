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
	ips := []struct {
		w         Whitelist
		ip        string
		whitelist []string
		success   bool
	}{
		{Whitelist{map[string]string{"alecpinson123456": "123.123.123.123/32"}}, "12.12.12.12/32", []string{}, false},
		{Whitelist{map[string]string{"alecpinson123456": "123.123.123.123/32"}}, "1.2.3.4/32", []string{"1.2.3.0/24"}, true},
		{Whitelist{map[string]string{"alecpinson123456": "123.123.123.123/32"}}, "2a00:11c7:1234:b801:a16e:12af:5e42:1100/32", []string{"1.2.3.0/24"}, false},
		{Whitelist{map[string]string{"alecpinson123456": "123.123.123.123/32"}}, "2a00:11c7:1234:b801:a16e:12af:5e42:1111/32", []string{}, false},
	}

	for _, i := range ips {
		success := i.w.inRange(i.ip, i.whitelist)
		if success != i.success {
			t.Errorf("inRange for %v was incorrect, got %v, want %v", i, success, i.success)
		}
	}
}
