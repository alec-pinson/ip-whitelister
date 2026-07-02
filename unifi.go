package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"time"
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

// unifiApplicationClient is the MVP unifiClient implementation, talking to the
// legacy UniFi Network Application API (login + REST firewallgroup endpoints).
type unifiApplicationClient struct {
	cfg  UnifiConfiguration
	http *http.Client
}

// newUnifiClient builds the real unifiClient implementation. TLS verification is
// intentionally skipped (InsecureSkipVerify) because UniFi gateways ship
// self-signed certificates.
func newUnifiClient(cfg UnifiConfiguration) unifiClient {
	jar, _ := cookiejar.New(nil)
	return &unifiApplicationClient{
		cfg: cfg,
		http: &http.Client{
			Timeout: 30 * time.Second,
			Jar:     jar,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		},
	}
}

func (uc *unifiApplicationClient) base() string {
	return strings.TrimRight(uc.cfg.Host, "/") + "/proxy/network/api/s/" + uc.cfg.Site + "/rest/firewallgroup"
}

// login authenticates against the gateway and returns the CSRF token. The token
// is returned (not stored on the struct) so concurrent update() calls sharing
// this client don't clobber each other's token — a data race that caused
// intermittent 403s. The session cookie lives in the shared cookiejar, which is
// safe for concurrent use.
func (uc *unifiApplicationClient) login() (string, error) {
	body, _ := json.Marshal(map[string]string{"username": uc.cfg.Username, "password": uc.cfg.Password})
	req, err := http.NewRequest(http.MethodPost, strings.TrimRight(uc.cfg.Host, "/")+"/api/auth/login", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := uc.http.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unifi login failed: status %d", resp.StatusCode)
	}
	return resp.Header.Get("X-CSRF-Token"), nil
}

func (uc *unifiApplicationClient) getFirewallGroup(name string) (unifiFirewallGroup, error) {
	// GET only needs the session cookie from the jar, not the CSRF token.
	if _, err := uc.login(); err != nil {
		return unifiFirewallGroup{}, err
	}
	req, err := http.NewRequest(http.MethodGet, uc.base(), nil)
	if err != nil {
		return unifiFirewallGroup{}, err
	}
	resp, err := uc.http.Do(req)
	if err != nil {
		return unifiFirewallGroup{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return unifiFirewallGroup{}, fmt.Errorf("unifi getFirewallGroup failed: status %d", resp.StatusCode)
	}
	var out struct {
		Data []unifiFirewallGroup `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return unifiFirewallGroup{}, err
	}
	for _, g := range out.Data {
		if g.Name == name {
			return g, nil
		}
	}
	return unifiFirewallGroup{}, fmt.Errorf("unifi network list '%s' not found", name)
}

func (uc *unifiApplicationClient) updateFirewallGroup(g unifiFirewallGroup) error {
	csrf, err := uc.login()
	if err != nil {
		return err
	}
	body, _ := json.Marshal(g)
	req, err := http.NewRequest(http.MethodPut, uc.base()+"/"+g.ID, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", csrf)
	resp, err := uc.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unifi updateFirewallGroup failed: status %d", resp.StatusCode)
	}
	return nil
}

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
