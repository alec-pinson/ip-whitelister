package main

import (
	"log"
	"net"
	"time"
)

/*
- func init
- func get
- func add
- func delete
- func ttl
- func updateResources
*/

type Whitelist struct {
	List map[string]string // key = alecpinson123456, value = 123.123.123.123/32
}

func (*Whitelist) init() {
	// load config
	c.load()

	// connect to redis database
	r.connect(c.Redis)

	// initialize http/authentication
	h.init(c.Auth)

	// enable ttl check on whitelisted ips
	go w.ttl()
}

func (w *Whitelist) add(u *User) bool {
	w.List = r.getWhitelist()

	// first check ip not in range of config.IPWhiteList
	// convert client ip to net.IP
	clientIp := net.ParseIP(u.ip)
	var alreadyWhitelisted = false
	for _, v := range c.IPWhiteList {
		// cidr, parse it
		_, subnet, _ := net.ParseCIDR(v)
		if subnet.Contains(clientIp) {
			// ip has already been whitelisted
			alreadyWhitelisted = true
			log.Printf("whitelist.add(): IPAddress value %v overlaps with already whitelisted value %v", u.ip, v)
			return false
		}
	}

	if w.List[u.key] != u.cidr && alreadyWhitelisted == false {
		// need to update list
		if w.List[u.key] == "" {
			log.Println("whitelist.add(): no current whitelist for '" + u.key + "' was found, adding ip " + u.ip)
		} else {
			log.Println("whitelist.add(): updating whitelist for '" + u.key + "' from " + w.List[u.key] + " to " + u.ip)
		}
		r.addIp(u.key, u.cidr)
		w.updateResources()
		return true
	} else {
		// ip already whitelisted ... renew redis expiry time though
		log.Println("whitelist.add(): no changes required for '" + u.key + "', ip already set to " + u.ip)
		r.addIp(u.key, u.cidr)
		return true
	}
}

func (w *Whitelist) delete(u *User) bool {
	r.deleteIp(u.key)
	w.updateResources()
	log.Println("whitelist.delete(): whitelisting for " + u.name + " removed.")
	return true
}

// trigger removal of ips due to ttl
func (*Whitelist) ttl() {
	w.List = r.getWhitelist()
	w.updateResources()

	// run every hour
	for range time.Tick(time.Hour * 1) {
		w.List = r.getWhitelist()
		w.updateResources()
	}
}

func (*Whitelist) updateResources() {
	// azure frontdoor
	for _, fd := range a.FrontDoor {
		fd.update()
	}
}
