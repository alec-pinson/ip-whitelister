package main

import (
	"encoding/json"
	"log"
	"sort"
	"strconv"
	"time"

	"github.com/gomodule/redigo/redis"
)

type RedisConfiguration struct {
	Host            string       `yaml:"host"`
	Port            int          `yaml:"port"`
	Token           string       `yaml:"token"`
	Connection      []redis.Conn // db0 (used for whitelist), db1 (used for groups cache), db2 (used for api spam prevention)
	Running         []bool       // concurrency check
	CurrentDatabase int
}

var redisDBCount int = 3

// connect
func (r *RedisConfiguration) connect(rc RedisConfiguration) bool {
	if rc.Host == "" || rc.Port == 0 || rc.Token == "" {
		log.Print("redis.connect(): no redis database configuration was found")
		return false
	}

	r.Connection = make([]redis.Conn, redisDBCount)
	r.Running = make([]bool, redisDBCount)

	log.Println("redis.connect(): connecting to redis database '" + rc.Host + ":" + strconv.Itoa(rc.Port) + "'")

	for db := 0; db <= (redisDBCount - 1); db++ {
		c, err := redis.Dial("tcp", rc.Host+":"+strconv.Itoa(rc.Port))
		if err != nil {
			log.Printf("redis.connect(): %v ", err)
			return false
		}

		_, err = c.Do("AUTH", rc.Token)
		if err != nil {
			log.Printf("redis.connect(): %v ", err)
			return false
		}

		_, err = c.Do("SELECT", db)
		if err != nil {
			log.Fatal("redis.connect():", err)
			return false
		}

		r.Running[db] = false
		r.Connection[db] = c
	}

	go r.keepAlive()
	log.Println("redis.connect(): connected")
	return true
}

// exec
func (r RedisConfiguration) exec(db int, commandName string, args ...interface{}) (reply interface{}, err error) {
	r.wait(db)
	r.Running[db] = true
	reply, err = r.Connection[db].Do(commandName, args[:]...)
	r.Running[db] = false
	return reply, err
}

// wait
func (r RedisConfiguration) wait(db int) {
	// redigo library doesn't support concurrency so we need to run single commands at a time
	for ok := true; ok; ok = r.Running[db] {
		// command currently running
	}
}

// add ip
func (r RedisConfiguration) addIp(user string, ip string) bool {
	_, err := r.exec(0, "SET", user, ip)
	if err != nil {
		log.Fatal("redis.addIp():", err)
		return false
	}

	// expire this key in x hours
	return r.setIpExpiry(user)
}

// set ttl on ip
func (r RedisConfiguration) setIpExpiry(user string) bool {
	_, err := r.exec(0, "EXPIRE", user, strconv.Itoa(c.TTL*3600))
	if err != nil {
		log.Fatal("redis.setIpExpiry():", err)
		return false
	}
	return true
}

// delete ip
func (r RedisConfiguration) deleteIp(user string) bool {
	_, err := r.exec(0, "DEL", user)
	if err != nil {
		log.Fatal("redis.deleteIp():", err)
		return false
	}
	return true
}

// get whitelist
func (r RedisConfiguration) getWhitelist() map[string]string {
	wl := make(map[string]string)

	redisResponse1 := time.Now()

	keysI, err := redis.Values(r.exec(0, "KEYS", "*"))
	if err != nil {
		log.Fatal("redis.getWhitelist(): ", err)
	}
	if len(keysI) == 0 {
		return wl
	}
	values, err := redis.Strings(r.exec(0, "MGET", keysI[:]...))
	if err != nil {
		log.Fatal("redis.getWhitelist(): ", err)
	}
	keys, err := redis.Strings(keysI, err)
	if err != nil {
		log.Fatal("redis.getWhitelist(): ", err)
	}

	for index, key := range keys {
		ip := values[index]
		wl[key] = ip
	}

	log.Println("redis.getWhitelist(): ## current ip whitelist ##")
	sort.Strings(keys)
	for _, key := range keys {
		log.Println("redis.getWhitelist(): " + key + " : " + wl[key])
	}
	log.Println("redis.getWhitelist(): ##                      ##")

	redisResponse2 := time.Now()
	log.Println("redis.getWhitelist(): response time:", redisResponse2.Sub(redisResponse1))

	return wl
}

// add group
func (r RedisConfiguration) addGroups(user string, groups []string) bool {
	jsonGroups, err := json.Marshal(groups)
	if err != nil {
		log.Print("redis.addGroups():", err)
		return false
	}
	_, err = r.exec(1, "SET", user, jsonGroups)
	if err != nil {
		log.Fatal("redis.addGroups():", err)
		return false
	}

	// expire this key in x hours
	return r.setGroupExpiry(user)
}

// set group expiry
func (r RedisConfiguration) setGroupExpiry(user string) bool {
	_, err := r.exec(1, "EXPIRE", user, strconv.Itoa(c.TTL*3600+10))
	if err != nil {
		log.Fatal("redis.setGroupExpiry():", err)
		return false
	}
	return true
}

// get groups
func (r RedisConfiguration) getGroups(user string) []string {
	var g []string

	redisResponse1 := time.Now()

	keysI, err := redis.Values(r.exec(1, "KEYS", user))
	if err != nil {
		log.Print("redis.getGroups(): ", err)
		return g
	}
	if len(keysI) == 0 {
		return g
	}
	value, err := redis.String(r.exec(1, "GET", user))
	if err != nil {
		log.Print("redis.getGroups(): ", err)
		return g
	}
	if err := json.Unmarshal([]byte(value), &g); err != nil {
		log.Println("redis.getGroups():", err)
		return g
	}

	redisResponse2 := time.Now()
	if c.Debug {
		log.Println("redis.getGroups(): response time:", redisResponse2.Sub(redisResponse1))
	}

	return g
}

// user caused api call
func (r RedisConfiguration) apiCalled(user string) {
	// all user to cause api calls every 60 seconds
	_, err := redis.String(r.exec(2, "SETEX", user, 60, "."))
	if err != nil {
		log.Fatal("redis.apiCalled():", err)
	}
}

// can user call api
func (r RedisConfiguration) canCallApi(user string) bool {
	exists, err := redis.Int(r.exec(2, "EXISTS", user))
	if err != nil {
		log.Fatal("redis.canCallApi():", err)
		return false
	}
	if exists == 1 {
		return false
	} else {
		return true
	}
}

// keep alive
func (r RedisConfiguration) keepAlive() {
	// run every 5 minutes
	for range time.Tick(time.Minute * 5) {
		for db := 0; db <= (redisDBCount - 1); db++ {
			_, err := redis.Strings(r.exec(db, "KEYS", "1"))
			if err != nil {
				log.Fatal("redis.keepAlive(): ", err)
			}
		}
	}
}
