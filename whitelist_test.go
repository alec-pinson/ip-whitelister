package main

import "testing"

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
