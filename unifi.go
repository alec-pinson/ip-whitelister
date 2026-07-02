package main

import (
	"log"
	"strings"
)

// Unifi is the aggregate of all configured UniFi provider resources.
type Unifi struct {
	NetworkList []UnifiNetworkList
}

// UnifiNetworkList maps to one UniFi Network List (firewall address-group) that
// the app keeps in sync with the current whitelist.
type UnifiNetworkList struct {
	Name        string   // the Network List / firewall group name
	Group       []string // optional AzureAD group filter
	IPWhiteList []string // optional per-list static entries
	client      unifiClient
}

// unifiFirewallGroup is the UniFi REST representation of a Network List.
type unifiFirewallGroup struct {
	ID        string   `json:"_id"`
	Name      string   `json:"name"`
	GroupType string   `json:"group_type"`
	Members   []string `json:"group_members"`
}

// unifiClient is the transport seam so update() is testable without a live gateway.
type unifiClient interface {
	getFirewallGroup(name string) (unifiFirewallGroup, error)
	updateFirewallGroup(g unifiFirewallGroup) error
}

// UnifiConfiguration holds the single UniFi gateway connection + credentials.
// TODO(batch-b): replaced by config.go / real client
type UnifiConfiguration struct {
	Host, Site, Username, Password string
}

// newUnifiClient builds the real unifiClient implementation.
// TODO(batch-b): replaced by config.go / real client
func newUnifiClient(UnifiConfiguration) unifiClient { return nil }

// sameMembers reports whether a and b contain the same elements (order-insensitive,
// duplicates counted). Used to decide whether a network list needs updating.
func sameMembers(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := make(map[string]int)
	for _, v := range a {
		seen[v]++
	}
	for _, v := range b {
		seen[v]--
	}
	for _, n := range seen {
		if n != 0 {
			return false
		}
	}
	return true
}

// buildMembers computes the desired address-group members for this list:
// qualifying dynamic whitelist IPs plus the static (global + per-list) entries.
func (nl *UnifiNetworkList) buildMembers(list map[string]string, getGroups func(string) []string) []string {
	members := []string{}
	// dynamic whitelist
	for key, ip := range list {
		if !w.inRange(ip, nl.IPWhiteList) && isValidIpOrNetV4(ip) {
			if hasGroup(nl.Group, getGroups(key)) {
				members = append(members, ip)
			} else if c.Debug {
				log.Print("unifi.UnifiNetworkList.buildMembers(): user '"+key+"' is not part of any of the groups ", nl.Group, " required for network list '"+nl.Name+"'")
			}
		}
	}
	// static whitelist (global + per-list)
	for _, ip := range append(c.IPWhiteList, nl.IPWhiteList...) {
		if isValidIpOrNetV4(ip) {
			members = append(members, ip)
		}
	}
	return members
}

func (*UnifiNetworkList) new(nl UnifiNetworkList) {
	u.NetworkList = append(u.NetworkList, nl)
	log.Println("unifi.UnifiNetworkList.new(): network list added '" + nl.Name + "'")
}

func (nl *UnifiNetworkList) update() int {
	log.Print("unifi.UnifiNetworkList.update(): updating '" + nl.Name + "'")

	members := nl.buildMembers(w.List, r.getGroups)

	g, err := nl.client.getFirewallGroup(nl.Name)
	if err != nil {
		log.Print("unifi.UnifiNetworkList.update():", err)
		return 1
	}

	if sameMembers(g.Members, members) {
		if c.Debug {
			log.Print("unifi.UnifiNetworkList.update(): no changes required for '" + nl.Name + "'")
		}
		return 0
	}

	g.Members = members
	if err := nl.client.updateFirewallGroup(g); err != nil {
		log.Print("unifi.UnifiNetworkList.update():", err)
		return 1
	}

	log.Print("unifi.UnifiNetworkList.update(): updated '" + nl.Name + "'")
	return 0
}

// unifiEnabled reports whether UniFi syncing should run. It is disabled when no
// host is configured or the host is the sample placeholder, so the dummy config
// never touches a real gateway.
func unifiEnabled(cfg UnifiConfiguration) bool {
	return cfg.Host != "" && !strings.Contains(cfg.Host, "notreal")
}
