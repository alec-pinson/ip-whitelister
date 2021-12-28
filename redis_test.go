package main

import (
	"log"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
)

type TestRedisInstance struct {
	Pool     dockertest.Pool
	Resource dockertest.Resource
	Host     string
	Port     int
	Token    string
}

func CreateTestRedis(t *testing.T) TestRedisInstance {
	pool, err := dockertest.NewPool("")
	if err != nil {
		t.Errorf("redis_test.TestConnect(): Could not connect to docker: %s", err)
	}

	path, err := os.Getwd()
	if err != nil {
		log.Println("redis_test.TestConnect(): ", err)
	}

	// resource, err := pool.Run("redis", "6.2.6-alpine", nil)
	resource, err := pool.RunWithOptions(&dockertest.RunOptions{
		Name:         "redis",
		Repository:   "redis",
		Tag:          "6.2.6-alpine",
		ExposedPorts: []string{"6379/tcp"},
		Mounts:       []string{path + "/config:/usr/local/etc/redis"},
		Cmd:          []string{"redis-server", "/usr/local/etc/redis/redis.conf"},
	}, func(config *docker.HostConfig) {
		config.AutoRemove = true
	})
	if err != nil {
		t.Errorf("redis_test.TestConnect(): could not start resource: %s", err)
	}
	// defer pool.Purge(resource)

	dockerPort, err := strconv.Atoi(resource.GetPort("6379/tcp"))
	if err != nil {
		t.Errorf("redis_test.TestConnect(): failed to get redis container port")
	}

	// need time for docker container to start
	time.Sleep(5 * time.Second)

	var testRedisInstance TestRedisInstance
	testRedisInstance.Host = "localhost"
	testRedisInstance.Port = dockerPort
	testRedisInstance.Token = "my-sup3r-comp1ic4t3d-s3cr3t-t0k3n"
	testRedisInstance.Pool = *pool
	testRedisInstance.Resource = *resource

	return testRedisInstance
}

func DeleteTestRedis(t *testing.T, tr TestRedisInstance) {
	if err := tr.Pool.Purge(&tr.Resource); err != nil {
		t.Errorf("redis_test.DeleteTestRedis(): Could not purge resource: %s", err)
	}
}

func TestConnect(t *testing.T) {
	var testRedisInstance = CreateTestRedis(t)
	var rc RedisConfiguration
	rc.Host = testRedisInstance.Host
	rc.Port = testRedisInstance.Port
	rc.Token = testRedisInstance.Token

	ret := r.connect(rc)

	if ret != 0 {
		t.Error("redis.connect(): failed to connect, got 'failed connection', want 'successful connection'")
	}

	// wrong hostname
	rc.Host = "nonexiststenthostname"
	rc.Port = testRedisInstance.Port
	rc.Token = testRedisInstance.Token

	ret = r.connect(rc)
	if ret != 1 {
		t.Errorf("redis.connect(): connect for '%v:%v', got 'success', want 'fail'", rc.Host, rc.Port)
	}

	// wrong port
	rc.Host = testRedisInstance.Host
	rc.Port = 12345
	rc.Token = testRedisInstance.Token

	ret = r.connect(rc)
	if ret != 1 {
		t.Errorf("redis.connect(): connect for '%v:%v', got 'success', want 'fail'", rc.Host, rc.Port)
	}

	// wrong password
	rc.Host = testRedisInstance.Host
	rc.Port = testRedisInstance.Port
	rc.Token = "wrongpassword!"

	ret = r.connect(rc)
	if ret != 1 {
		t.Errorf("redis.connect(): connect for '%v:%v' pw: %v, got 'success', want 'fail'", rc.Host, rc.Port, rc.Token)
	}

	DeleteTestRedis(t, testRedisInstance)
}

func TestAddIp(t *testing.T) {
	users := []struct {
		user    string
		cidr    string
		success int
	}{
		{"testuser111111", "10.0.0.1/32", 0},
		{"testuser111112", "10.0.0.2/32", 0},
		{"testuser111113", "10.0.0.3/32", 0},
		{"testuser111114", "10.0.0.4/32", 0},
		{"testuser111115", "10.0.0.5/32", 0},
	}

	var testRedisInstance = CreateTestRedis(t)
	var rc RedisConfiguration
	rc.Host = testRedisInstance.Host
	rc.Port = testRedisInstance.Port
	rc.Token = testRedisInstance.Token
	ret := r.connect(rc)
	if ret == 0 {
		for _, f := range users {
			ret = r.addIp(f.user, f.cidr)
			if ret != f.success {
				t.Errorf("redis.addIp(): Add user ip %v, got '%v', want '%v'", f, ret, f.success)
			}
		}
	}

	DeleteTestRedis(t, testRedisInstance)
}

func TestDeleteIp(t *testing.T) {
	users := []struct {
		user    string
		cidr    string
		success int
	}{
		{"testuser111111", "10.0.0.1/32", 0},
		{"testuser111112", "10.0.0.2/32", 0},
		{"testuser111113", "10.0.0.3/32", 0},
		{"testuser111114", "10.0.0.4/32", 0},
		{"testuser111115", "10.0.0.5/32", 0},
	}

	var testRedisInstance = CreateTestRedis(t)
	var rc RedisConfiguration
	rc.Host = testRedisInstance.Host
	rc.Port = testRedisInstance.Port
	rc.Token = testRedisInstance.Token
	ret := r.connect(rc)
	if ret == 0 {
		for _, f := range users {
			ret = r.addIp(f.user, f.cidr)
			if ret == f.success {
				ret = r.deleteIp(f.user)
				if ret != 0 {
					t.Errorf("redis.deleteIp(): Delete user ip %v, want '%v', got '%v'", f, ret, f.success)
				}
			}
		}
	}

	DeleteTestRedis(t, testRedisInstance)
}

func TestGetWhitelist(t *testing.T) {
	users := []struct {
		user string
		cidr string
	}{
		{"testuser111111", "10.0.0.1/32"},
		{"testuser111112", "10.0.0.2/32"},
		{"testuser111113", "10.0.0.3/32"},
		{"testuser111114", "10.0.0.4/32"},
		{"testuser111115", "10.0.0.5/32"},
	}

	var testRedisInstance = CreateTestRedis(t)
	var rc RedisConfiguration
	rc.Host = testRedisInstance.Host
	rc.Port = testRedisInstance.Port
	rc.Token = testRedisInstance.Token
	ret := r.connect(rc)
	if ret == 0 {
		for _, f := range users {
			ret = r.addIp(f.user, f.cidr)
			if ret == 0 {
				ret := r.getWhitelist()
				if ret[f.user] != f.cidr {
					t.Errorf("redis.getWhitelist(): Get whitelist %v, got '%v', want '%v'", f, f.cidr, ret[f.user])
				}
			}
		}
	}

	DeleteTestRedis(t, testRedisInstance)
}
