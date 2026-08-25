package main

import (
	"log"
	"net"
	"os"
	"strings"
	"time"
)

type Whitelist struct {
	List map[string]string // key = alecpinson123456, value = 123.123.123.123/32
}

func (*Whitelist) init() {
	// load config
	c.load()

	// connect to redis database
	if !r.connect(c.Redis) {
		os.Exit(1)
	}

	// enable ttl check on whitelisted ips
	go w.ttl()

	// initialize authentication
	go h.init(c.Auth)

	// update resources on startup
	w.updateResources()

	// initialize http
	h.start()
}

func (w *Whitelist) add(u *User) bool {
	w.List = r.getWhitelist()

	if w.inRange(u.ip, c.IPWhiteList) {
		return false
	}

	t, err := ipVersion(u.cidr)
	if err != nil {
		log.Printf("whitelist.add(): %v", err)
		return false
	}
	if !c.IpResolution.enabledFor(t) {
		log.Println("whitelist.add(): ip_resolution is disabled for this address family, skipping " + u.ip)
		return false
	}
	// the groups cache and api throttle stay keyed per user; only the address
	// itself is stored per family
	key := redisKey(u.key, t)

	ret := r.addGroups(u.key, u.groups)
	if !ret {
		return ret
	}

	if w.List[key] != u.cidr {
		// need to update list
		if w.List[key] == "" {
			log.Println("whitelist.add(): no current whitelist for '" + key + "' was found, adding ip " + u.ip)
		} else {
			log.Println("whitelist.add(): updating whitelist for '" + key + "' from " + w.List[key] + " to " + u.ip)
		}
		ret = r.addIp(key, u.cidr)
		if !ret {
			return ret
		}
		r.apiCalled(u.key)
		go w.updateResources()
		return true
	} else {
		// ip already whitelisted ... renew redis expiry time though
		log.Println("whitelist.add(): no changes required for '" + key + "', ip already set to " + u.ip)
		if r.canCallApi(u.key) {
			r.apiCalled(u.key)
			go w.updateResources()
		}
		return r.setIpExpiry(key)
	}
}

func (w *Whitelist) delete(u *User) bool {
	// a user may hold one entry per address family
	for _, t := range []IpType{IpV4, IpV6} {
		if !r.deleteIp(redisKey(u.key, t)) {
			return false
		}
	}
	w.updateResources()
	log.Println("whitelist.delete(): whitelisting for '" + u.key + "' removed.")
	return true
}

// trigger removal of ips due to ttl
func (*Whitelist) ttl() {
	// run every hour, might need increasing in future
	for range time.Tick(time.Hour * 1) {
		w.updateResources()
	}
}

func (*Whitelist) updateResources() bool {
	if c.Auth.TenantId == "notreal-not-real-not-notreal" {
		return false
	}
	w.List = r.getWhitelist()
	for _, fd := range a.FrontDoor {
		fd.update()
	}
	for _, st := range a.StorageAccount {
		st.update()
	}
	for _, kv := range a.KeyVault {
		kv.update()
	}
	for _, pg := range a.PostgresServer {
		pg.update()
	}
	for _, rc := range a.RedisCache {
		rc.update()
	}
	for _, cd := range a.CosmosDb {
		cd.update()
	}
	if unifiEnabled(c.Unifi) {
		for _, nl := range u.NetworkList {
			nl.update()
		}
	}
	return true
}

func (*Whitelist) inRange(ip string, whitelist []string) bool {
	netIp := net.ParseIP(strings.Split(ip, "/")[0])
	for _, v := range whitelist {
		if strings.Contains(v, "/") {
			// cidr, parse it
			_, subnet, _ := net.ParseCIDR(v)
			if subnet.Contains(netIp) {
				// ip has already been whitelisted
				if c.Debug {
					log.Printf("whitelist.inRange(): IPAddress value %v overlaps with already whitelisted value %v", ip, v)
				}
				return true
			}
		} else {
			// single ip
			if v == ip {
				// ip has already been whitelisted
				if c.Debug {
					log.Printf("whitelist.inRange(): IPAddress value %v overlaps with already whitelisted value %v", ip, v)
				}
				return true
			}
		}
	}
	return false
}
