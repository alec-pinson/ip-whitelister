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
	"sync"
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

	// mu serialises authenticated requests and guards csrf. The session is
	// reused across update() calls: UniFi rate-limits back-to-back logins with a
	// 403, so we log in once (lazily) and only re-authenticate when the session
	// expires. Serialising also stops concurrent update()s rotating the token
	// mid-flight.
	mu   sync.Mutex
	csrf string // cached CSRF token for the live session; "" means logged out
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

// login authenticates against the gateway and caches the session's CSRF token.
// The session cookie is stored in the client's cookiejar. Callers must hold uc.mu.
func (uc *unifiApplicationClient) login() error {
	body, _ := json.Marshal(map[string]string{"username": uc.cfg.Username, "password": uc.cfg.Password})
	req, err := http.NewRequest(http.MethodPost, strings.TrimRight(uc.cfg.Host, "/")+"/api/auth/login", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := uc.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unifi login failed: status %d", resp.StatusCode)
	}
	uc.csrf = resp.Header.Get("X-CSRF-Token")
	return nil
}

// authedDo performs an authenticated request against the gateway, reusing the
// existing session so we don't trip UniFi's login rate limit (which 403s
// back-to-back logins). It logs in lazily on first use, refreshes the rotating
// CSRF token from each response, and re-authenticates once if the session has
// expired (401) or the token is stale (403). uc.mu serialises requests so a
// concurrent update() can't rotate the token out from under an in-flight call.
func (uc *unifiApplicationClient) authedDo(method, url string, body []byte) (*http.Response, error) {
	uc.mu.Lock()
	defer uc.mu.Unlock()

	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		if uc.csrf == "" {
			if err := uc.login(); err != nil {
				return nil, err
			}
		}
		req, err := http.NewRequest(method, url, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		req.Header.Set("X-CSRF-Token", uc.csrf)
		resp, err := uc.http.Do(req)
		if err != nil {
			return nil, err
		}
		if t := resp.Header.Get("X-CSRF-Token"); t != "" {
			uc.csrf = t
		}
		// Session expired or token stale: drop it and re-login on the retry.
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			resp.Body.Close()
			uc.csrf = ""
			lastErr = fmt.Errorf("unifi %s: status %d", method, resp.StatusCode)
			continue
		}
		return resp, nil
	}
	return nil, lastErr
}

func (uc *unifiApplicationClient) getFirewallGroup(name string) (unifiFirewallGroup, error) {
	resp, err := uc.authedDo(http.MethodGet, uc.base(), nil)
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
	body, _ := json.Marshal(g)
	resp, err := uc.authedDo(http.MethodPut, uc.base()+"/"+g.ID, body)
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
// Members are de-duplicated (first occurrence wins, order preserved): two users
// behind the same public IP, or an IP present in both the static and dynamic
// sets, must not produce a duplicate entry. UniFi normalises group_members to a
// set, so a duplicate would make sameMembers() never match and force a PUT on
// every reconcile.
func (nl *UnifiNetworkList) buildMembers(list map[string]string, getGroups func(string) []string) []string {
	members := []string{}
	seen := make(map[string]struct{})
	add := func(ip string) {
		ip = unifiMember(ip)
		if _, ok := seen[ip]; ok {
			return
		}
		seen[ip] = struct{}{}
		members = append(members, ip)
	}
	// dynamic whitelist
	for key, ip := range list {
		if !w.inRange(ip, nl.IPWhiteList) && isValidIpOrNetV4(ip) {
			if hasGroup(nl.Group, getGroups(key)) {
				add(ip)
			} else if c.Debug {
				log.Print("unifi.UnifiNetworkList.buildMembers(): user '"+key+"' is not part of any of the groups ", nl.Group, " required for network list '"+nl.Name+"'")
			}
		}
	}
	// static whitelist (global + per-list)
	for _, ip := range append(c.IPWhiteList, nl.IPWhiteList...) {
		if isValidIpOrNetV4(ip) {
			add(ip)
		}
	}
	return members
}

// unifiMember formats an address for a UniFi firewall group. UniFi stores single
// hosts as bare IPs — its UI rejects a /32 suffix ("enter single host addresses
// without the subnet mask") — so we strip a /32 while leaving real subnets (e.g.
// /24) untouched. Matching UniFi's stored form also keeps sameMembers() stable,
// so an unchanged whitelist doesn't force a PUT on every reconcile.
func unifiMember(ip string) string {
	return strings.TrimSuffix(ip, "/32")
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
