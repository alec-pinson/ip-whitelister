package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gomodule/redigo/redis"
)

var errFakeUnifi = errors.New("fake unifi error")

// fakeRedisConn is a minimal no-op redigo redis.Conn. buildMembers() calls
// r.getGroups() incidentally (its result is only consulted when nl.Group is
// non-nil), and RedisConfiguration.exec() panics on the zero-value r.Connection
// (nil slice / nil interface) rather than erroring gracefully. These unit tests
// don't want a real Redis (that's covered by the docker-backed suite), so we
// stub just enough of r's Redis connection for exec() to fail cleanly instead
// of panicking.
type fakeRedisConn struct{}

func (fakeRedisConn) Close() error { return nil }
func (fakeRedisConn) Err() error   { return nil }
func (fakeRedisConn) Do(commandName string, args ...interface{}) (reply interface{}, err error) {
	return nil, errors.New("fakeRedisConn: no real redis in unit test")
}
func (fakeRedisConn) Send(commandName string, args ...interface{}) error { return nil }
func (fakeRedisConn) Flush() error                                       { return nil }
func (fakeRedisConn) Receive() (reply interface{}, err error)            { return nil, nil }

// stubRedis wires r up with fakeRedisConn so update() -> buildMembers() ->
// r.getGroups() doesn't panic when no real Redis is connected.
func stubRedis() {
	r.Running = make([]bool, redisDBCount)
	r.Connection = make([]redis.Conn, redisDBCount)
	for i := range r.Connection {
		r.Connection[i] = fakeRedisConn{}
	}
}

func TestSameMembers(t *testing.T) {
	cases := []struct {
		name string
		a, b []string
		want bool
	}{
		{"both empty", []string{}, []string{}, true},
		{"same order", []string{"1.1.1.1/32", "2.2.2.2/32"}, []string{"1.1.1.1/32", "2.2.2.2/32"}, true},
		{"different order", []string{"1.1.1.1/32", "2.2.2.2/32"}, []string{"2.2.2.2/32", "1.1.1.1/32"}, true},
		{"different length", []string{"1.1.1.1/32"}, []string{"1.1.1.1/32", "2.2.2.2/32"}, false},
		{"different content", []string{"1.1.1.1/32"}, []string{"3.3.3.3/32"}, false},
		{"duplicates matter", []string{"1.1.1.1/32", "1.1.1.1/32"}, []string{"1.1.1.1/32", "2.2.2.2/32"}, false},
	}
	for _, tc := range cases {
		if got := sameMembers(tc.a, tc.b); got != tc.want {
			t.Errorf("%s: sameMembers(%v, %v) = %v, want %v", tc.name, tc.a, tc.b, got, tc.want)
		}
	}
}

func TestBuildMembers(t *testing.T) {
	// buildMembers reads globals c (static whitelist / debug) and w (inRange).
	c.Debug = false
	c.IPWhiteList = []string{"9.9.9.9/32"} // global static, added to every list

	getGroups := func(user string) []string {
		switch user {
		case "alice":
			return []string{"group-a"}
		case "bob":
			return []string{"group-b"}
		}
		return nil
	}

	nl := UnifiNetworkList{
		Name:        "ip-whitelister",
		Group:       []string{"group-a"},    // only group-a users qualify
		IPWhiteList: []string{"8.8.8.8/32"}, // per-list static
	}

	list := map[string]string{
		"alice": "1.1.1.1/32", // in group-a  -> included
		"bob":   "2.2.2.2/32", // not in group-a -> excluded
		"carol": "10.0.0.0/8", // carol has no groups; nl.Group is set -> excluded
	}

	got := nl.buildMembers(list, getGroups)

	want := map[string]bool{
		"1.1.1.1": true, // alice, group match (host -> bare)
		"8.8.8.8": true, // per-list static
		"9.9.9.9": true, // global static
	}
	if len(got) != len(want) {
		t.Fatalf("buildMembers returned %v, want keys %v", got, want)
	}
	for _, m := range got {
		if !want[m] {
			t.Errorf("unexpected member %q in %v", m, got)
		}
	}
}

// TestBuildMembersStripsHostMask asserts single hosts are emitted as bare IPs
// (UniFi stores /32 hosts without the mask and rejects the /32 suffix in its UI),
// while real subnets keep their mask.
func TestBuildMembersStripsHostMask(t *testing.T) {
	c.Debug = false
	c.IPWhiteList = []string{"9.9.9.9/32", "85.0.0.0/24"} // host + real subnet
	getGroups := func(string) []string { return nil }
	nl := UnifiNetworkList{Name: "l", Group: nil}
	list := map[string]string{"alice": "1.1.1.1/32"}
	got := nl.buildMembers(list, getGroups)
	want := map[string]bool{
		"1.1.1.1":     true, // dynamic host -> bare
		"9.9.9.9":     true, // static host -> bare
		"85.0.0.0/24": true, // real subnet -> unchanged
	}
	if len(got) != len(want) {
		t.Fatalf("buildMembers = %v, want keys %v", got, want)
	}
	for _, m := range got {
		if !want[m] {
			t.Errorf("unexpected member %q in %v (want bare hosts, subnets kept)", m, got)
		}
	}
}

func TestBuildMembersNilGroupIncludesEveryone(t *testing.T) {
	c.Debug = false
	c.IPWhiteList = nil
	getGroups := func(string) []string { return nil }
	nl := UnifiNetworkList{Name: "open", Group: nil} // nil group -> hasGroup returns true
	list := map[string]string{"alice": "1.1.1.1/32", "bad": "not-an-ip"}
	got := nl.buildMembers(list, getGroups)
	if len(got) != 1 || got[0] != "1.1.1.1" {
		t.Errorf("buildMembers = %v, want [1.1.1.1] (host -> bare, invalid IP skipped)", got)
	}
}

func TestBuildMembersDeduplicates(t *testing.T) {
	c.Debug = false
	// same IP appears as a global static, a per-list static, and two users
	c.IPWhiteList = []string{"5.5.5.5/32"}
	getGroups := func(string) []string { return nil }
	nl := UnifiNetworkList{Name: "dup", Group: nil, IPWhiteList: []string{"5.5.5.5/32"}}
	list := map[string]string{
		"alice": "1.1.1.1/32", // shared public IP (e.g. same office NAT)
		"bob":   "1.1.1.1/32", // shared public IP
	}
	got := nl.buildMembers(list, getGroups)
	if len(got) != 2 {
		t.Fatalf("buildMembers = %v, want 2 unique members", got)
	}
	seen := map[string]int{}
	for _, m := range got {
		seen[m]++
	}
	if seen["1.1.1.1"] != 1 || seen["5.5.5.5"] != 1 {
		t.Errorf("expected each of 1.1.1.1 and 5.5.5.5 exactly once, got %v", got)
	}
}

type fakeUnifiClient struct {
	group       unifiFirewallGroup
	getErr      error
	putErr      error
	updated     *unifiFirewallGroup
	updateCalls int
}

func (f *fakeUnifiClient) getFirewallGroup(name string) (unifiFirewallGroup, error) {
	return f.group, f.getErr
}

func (f *fakeUnifiClient) updateFirewallGroup(g unifiFirewallGroup) error {
	f.updateCalls++
	f.updated = &g
	return f.putErr
}

func TestUpdateNoChange(t *testing.T) {
	stubRedis()
	c.Debug = false
	c.IPWhiteList = nil
	w.List = map[string]string{"alice": "1.1.1.1/32"}
	// UniFi stores single hosts bare, so the existing group has no /32 — the built
	// member (also bare) must match it, producing no change.
	fake := &fakeUnifiClient{group: unifiFirewallGroup{ID: "abc", Name: "l", GroupType: "address-group", Members: []string{"1.1.1.1"}}}
	nl := UnifiNetworkList{Name: "l", client: fake}
	// getGroups via Redis is bypassed: buildMembers uses r.getGroups in update(),
	// so stub the whitelist to a single entry whose group check passes (nil Group).
	if ret := nl.update(); ret != 0 {
		t.Fatalf("update() = %d, want 0", ret)
	}
	if fake.updateCalls != 0 {
		t.Errorf("updateFirewallGroup called %d times, want 0 (no change)", fake.updateCalls)
	}
}

func TestUpdateChange(t *testing.T) {
	stubRedis()
	c.Debug = false
	c.IPWhiteList = nil
	w.List = map[string]string{"alice": "2.2.2.2/32"}
	fake := &fakeUnifiClient{group: unifiFirewallGroup{ID: "abc", Name: "l", GroupType: "address-group", Members: []string{"1.1.1.1"}}}
	nl := UnifiNetworkList{Name: "l", client: fake}
	if ret := nl.update(); ret != 0 {
		t.Fatalf("update() = %d, want 0", ret)
	}
	if fake.updateCalls != 1 {
		t.Fatalf("updateFirewallGroup called %d times, want 1", fake.updateCalls)
	}
	if fake.updated.ID != "abc" || len(fake.updated.Members) != 1 || fake.updated.Members[0] != "2.2.2.2" {
		t.Errorf("PUT body = %+v, want id=abc members=[2.2.2.2]", *fake.updated)
	}
}

func TestUpdateGetError(t *testing.T) {
	w.List = map[string]string{}
	fake := &fakeUnifiClient{getErr: errFakeUnifi}
	nl := UnifiNetworkList{Name: "l", client: fake}
	if ret := nl.update(); ret != 1 {
		t.Errorf("update() = %d, want 1 on get error", ret)
	}
}

func TestUpdatePutError(t *testing.T) {
	stubRedis()
	c.IPWhiteList = nil
	w.List = map[string]string{"alice": "2.2.2.2/32"}
	fake := &fakeUnifiClient{
		group:  unifiFirewallGroup{ID: "abc", Members: []string{"1.1.1.1/32"}},
		putErr: errFakeUnifi,
	}
	nl := UnifiNetworkList{Name: "l", client: fake}
	if ret := nl.update(); ret != 1 {
		t.Errorf("update() = %d, want 1 on put error", ret)
	}
}

// TestUnifiApplicationClientReusesSession is the regression test for the
// double-login 403: two full get+update cycles must share ONE login, because
// UniFi rate-limits back-to-back logins. It also checks the rotating CSRF token
// from the GET response is carried into the PUT.
func TestUnifiApplicationClientReusesSession(t *testing.T) {
	var loginHits, putHits int
	var putBody unifiFirewallGroup
	var putCSRF string

	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		switch {
		case req.URL.Path == "/api/auth/login":
			loginHits++
			rw.Header().Set("X-CSRF-Token", "csrf-login")
			rw.WriteHeader(http.StatusOK)
		case req.Method == http.MethodGet && strings.HasSuffix(req.URL.Path, "/rest/firewallgroup"):
			// UniFi rotates the CSRF token per response; the freshest one on the
			// GET response must be used for the subsequent PUT.
			rw.Header().Set("X-CSRF-Token", "csrf-get")
			_ = json.NewEncoder(rw).Encode(map[string]interface{}{
				"data": []unifiFirewallGroup{{
					ID: "abc", Name: "ip-whitelister", GroupType: "address-group",
					Members: []string{"1.1.1.1"},
				}},
			})
		case req.Method == http.MethodPut && strings.Contains(req.URL.Path, "/rest/firewallgroup/abc"):
			putHits++
			putCSRF = req.Header.Get("X-CSRF-Token")
			_ = json.NewDecoder(req.Body).Decode(&putBody)
			_ = json.NewEncoder(rw).Encode(map[string]interface{}{"data": []unifiFirewallGroup{}})
		default:
			rw.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	client := newUnifiClient(UnifiConfiguration{Host: srv.URL, Site: "default", Username: "u", Password: "p"})

	// Two independent update cycles, as separate whitelist events would trigger.
	for i := 0; i < 2; i++ {
		g, err := client.getFirewallGroup("ip-whitelister")
		if err != nil {
			t.Fatalf("cycle %d getFirewallGroup error: %v", i, err)
		}
		if g.ID != "abc" || len(g.Members) != 1 || g.Members[0] != "1.1.1.1" {
			t.Fatalf("cycle %d getFirewallGroup = %+v, want id=abc members=[1.1.1.1]", i, g)
		}
		g.Members = []string{"2.2.2.2"}
		if err := client.updateFirewallGroup(g); err != nil {
			t.Fatalf("cycle %d updateFirewallGroup error: %v", i, err)
		}
	}

	if loginHits != 1 {
		t.Errorf("login hits = %d, want 1 (session reused across both cycles; a 2nd login is the 403 bug)", loginHits)
	}
	if putHits != 2 {
		t.Errorf("PUT hits = %d, want 2", putHits)
	}
	if putCSRF != "csrf-get" {
		t.Errorf("PUT X-CSRF-Token = %q, want %q (freshest token from GET response)", putCSRF, "csrf-get")
	}
	if putBody.ID != "abc" || len(putBody.Members) != 1 || putBody.Members[0] != "2.2.2.2" {
		t.Errorf("PUT body = %+v, want id=abc members=[2.2.2.2]", putBody)
	}
}

// TestUnifiApplicationClientReloginsOnSessionExpiry covers session expiry: when a
// request comes back 401, the client drops the stale session, logs in again, and
// retries — so a long-lived process recovers without a restart.
func TestUnifiApplicationClientReloginsOnSessionExpiry(t *testing.T) {
	var loginHits, getHits int

	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		switch {
		case req.URL.Path == "/api/auth/login":
			loginHits++
			rw.Header().Set("X-CSRF-Token", "csrf-login")
			rw.WriteHeader(http.StatusOK)
		default: // GET firewallgroup: first call 401 (expired), then succeeds
			getHits++
			if getHits == 1 {
				rw.WriteHeader(http.StatusUnauthorized)
				return
			}
			_ = json.NewEncoder(rw).Encode(map[string]interface{}{
				"data": []unifiFirewallGroup{{ID: "abc", Name: "l", Members: []string{}}},
			})
		}
	}))
	defer srv.Close()

	client := newUnifiClient(UnifiConfiguration{Host: srv.URL, Site: "default"})
	if _, err := client.getFirewallGroup("l"); err != nil {
		t.Fatalf("getFirewallGroup error: %v", err)
	}
	if loginHits != 2 {
		t.Errorf("login hits = %d, want 2 (initial login + re-login after 401)", loginHits)
	}
	if getHits != 2 {
		t.Errorf("GET hits = %d, want 2 (retried after re-login)", getHits)
	}
}

func TestUnifiApplicationClientGroupNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/api/auth/login" {
			rw.WriteHeader(http.StatusOK)
			return
		}
		_ = json.NewEncoder(rw).Encode(map[string]interface{}{"data": []unifiFirewallGroup{}})
	}))
	defer srv.Close()
	client := newUnifiClient(UnifiConfiguration{Host: srv.URL, Site: "default"})
	if _, err := client.getFirewallGroup("missing"); err == nil {
		t.Error("expected error for missing network list, got nil")
	}
}

func TestUnifiEnabled(t *testing.T) {
	cases := []struct {
		host string
		want bool
	}{
		{"", false},
		{"https://notreal.gateway", false},
		{"https://192.168.1.1", true},
	}
	for _, tc := range cases {
		if got := unifiEnabled(UnifiConfiguration{Host: tc.host}); got != tc.want {
			t.Errorf("unifiEnabled(host=%q) = %v, want %v", tc.host, got, tc.want)
		}
	}
}
