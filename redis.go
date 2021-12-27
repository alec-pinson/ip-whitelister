package main

/*
- Host
- Port
- Token
- Connection
- func addIp
- func deleteIp
- func setIpExpiry
- func getWhitelist
- func keepAlive
*/

import (
	"log"
	"strconv"
	"time"

	"github.com/gomodule/redigo/redis"
)

type RedisConfiguration struct {
	Host       string `yaml:"host"`
	Port       int    `yaml:"port"`
	Token      string `yaml:"token"`
	Connection redis.Conn
}

func (r *RedisConfiguration) connect(rc RedisConfiguration) {
	if rc.Host == "" || rc.Port == 0 || rc.Token == "" {
		log.Fatal("redis.connect(): no redis database configuration was found")
	}

	log.Println("redis.connect(): connecting to redis database '" + c.Redis.Host + ":" + strconv.Itoa(c.Redis.Port) + "'")

	c, err := redis.Dial("tcp", rc.Host+":"+strconv.Itoa(rc.Port))
	if err != nil {
		log.Fatalf("redis.connect(): %v ", err)
	}

	_, err = c.Do("AUTH", rc.Token)
	if err != nil {
		log.Fatalf("redis.connect(): %v ", err)
	}

	r.Connection = c
	go r.keepAlive()
	log.Println("redis.connect(): connected")
}

// add ip
func (r RedisConfiguration) addIp(user string, ip string) {
	_, err := r.Connection.Do("SET", user, ip)
	if err != nil {
		log.Fatal(err)
	}

	// expire this key in x hours
	r.setIpExpiry(user)
}

// set ttl on ip
func (r RedisConfiguration) setIpExpiry(user string) {
	_, err := r.Connection.Do("EXPIRE", user, strconv.Itoa(whitelistTTL*3600))
	if err != nil {
		log.Fatal(err)
	}
}

// delete ip
func (r RedisConfiguration) deleteIp(user string) {
	_, err := r.Connection.Do("DEL", user)
	if err != nil {
		log.Fatal(err)
	}
}

// get whitelist
func (r RedisConfiguration) getWhitelist() map[string]string {
	wl := make(map[string]string)

	redisResponse1 := time.Now()

	keysI, err := redis.Values(r.Connection.Do("KEYS", "*"))
	if err != nil {
		log.Fatal("redis.getWhitelist(): ", err)
	}
	if len(keysI) == 0 {
		return wl
	}
	values, err := redis.Strings(r.Connection.Do("MGET", keysI[:]...))
	if err != nil {
		log.Fatal("redis.getWhitelist(): ", err)
	}
	keys, err := redis.Strings(keysI, err)
	if err != nil {
		log.Fatal("redis.getWhitelist(): ", err)
	}

	log.Println("redis.getWhitelist(): ## current ip whitelist ##")
	for index, key := range keys {
		ip := values[index]
		log.Println("redis.getWhitelist(): " + key + " : " + ip)
		wl[key] = ip
	}
	log.Println("redis.getWhitelist(): ##                      ##")

	redisResponse2 := time.Now()
	log.Println("redis.getWhitelist(): response time:", redisResponse2.Sub(redisResponse1))

	return wl
}

func (r RedisConfiguration) keepAlive() {
	// run every 5 minutes
	for range time.Tick(time.Minute * 5) {
		_, err := redis.Strings(r.Connection.Do("KEYS", "*"))
		if err != nil {
			log.Fatal("redis.keepAlive(): ", err)
		}
	}
}
