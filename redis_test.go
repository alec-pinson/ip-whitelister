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

func testRedis(t *testing.T) TestRedisInstance {
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

func testRedisCleanup(t *testing.T, tr TestRedisInstance) {
	if err := tr.Pool.Purge(&tr.Resource); err != nil {
		t.Errorf("redis_test.testRedisCleanup(): Could not purge resource: %s", err)
	}
}

func TestConnect(t *testing.T) {
	var testRedisInstance = testRedis(t)
	var rc RedisConfiguration
	rc.Host = testRedisInstance.Host
	rc.Port = testRedisInstance.Port
	rc.Token = testRedisInstance.Token

	ret := r.connect(rc)

	if ret != 0 {
		t.Error()
	}

	testRedisCleanup(t, testRedisInstance)
}

func TestAddIp(t *testing.T) {
	var testRedisInstance = testRedis(t)
	var rc RedisConfiguration
	rc.Host = testRedisInstance.Host
	rc.Port = testRedisInstance.Port
	rc.Token = testRedisInstance.Token
	r.connect(rc)
	ret := r.addIp("testuser11111", "10.0.0.1/32")
	if ret != 0 {
		t.Errorf("redis_test.TestAddIp(): Failed to add IP")
	}

	testRedisCleanup(t, testRedisInstance)
}

func TestDeleteIp(t *testing.T) {
	var testRedisInstance = testRedis(t)
	var rc RedisConfiguration
	rc.Host = testRedisInstance.Host
	rc.Port = testRedisInstance.Port
	rc.Token = testRedisInstance.Token
	r.connect(rc)
	r.addIp("testuser11111", "10.0.0.1/32")
	ret := r.deleteIp("testuser11111")
	if ret != 0 {
		t.Errorf("redis_test.TestDeleteIp(): Failed to delete IP")
	}

	testRedisCleanup(t, testRedisInstance)
}

func TestGetWhitelist(t *testing.T) {
	var testRedisInstance = testRedis(t)
	var rc RedisConfiguration
	rc.Host = testRedisInstance.Host
	rc.Port = testRedisInstance.Port
	rc.Token = testRedisInstance.Token
	r.connect(rc)
	r.addIp("testuser11111", "10.0.0.1/32")
	ret := r.getWhitelist()
	if ret["testuser11111"] != "10.0.0.1/32" {
		t.Errorf("redis_test.TestGetWhitelist(): Failed to get whitelist")
	}

	testRedisCleanup(t, testRedisInstance)
}
