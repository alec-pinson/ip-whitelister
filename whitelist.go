package main

import (
	"log"
	"net"
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
	r.connect(c.Redis)

	// enable ttl check on whitelisted ips
	go w.ttl()

	// update resources on startup
	w.updateResources()

	// initialize http/authentication
	h.init(c.Auth)
}

func (w *Whitelist) add(u *User) bool {
	w.List = r.getWhitelist()

	if w.inRange(u.ip, c.IPWhiteList) {
		return false
	}

	if w.List[u.key] != u.cidr {
		// need to update list
		if w.List[u.key] == "" {
			log.Println("whitelist.add(): no current whitelist for '" + u.key + "' was found, adding ip " + u.ip)
		} else {
			log.Println("whitelist.add(): updating whitelist for '" + u.key + "' from " + w.List[u.key] + " to " + u.ip)
		}
		ret := r.addIp(u.key, u.cidr)
		if !ret {
			return ret
		}
		ret = r.addGroups(u.key, u.groups)
		if !ret {
			return ret
		}
		w.updateResources()
		return true
	} else {
		// ip already whitelisted ... renew redis expiry time though
		log.Println("whitelist.add(): no changes required for '" + u.key + "', ip already set to " + u.ip)
		return r.setIpExpiry(u.key)
	}
}

func (w *Whitelist) delete(u *User) bool {
	ret := r.deleteIp(u.key)
	if !ret {
		return ret
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
					log.Printf("whitelist.add(): IPAddress value %v overlaps with already whitelisted value %v", ip, v)
				}
				return true
			}
		} else {
			// single ip
			if v == ip {
				// ip has already been whitelisted
				if c.Debug {
					log.Printf("whitelist.add(): IPAddress value %v overlaps with already whitelisted value %v", ip, v)
				}
			}
		}
	}
	return false
}
