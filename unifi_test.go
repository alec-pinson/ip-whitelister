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
		"1.1.1.1/32": true, // alice, group match
		"8.8.8.8/32": true, // per-list static
		"9.9.9.9/32": true, // global static
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

func TestBuildMembersNilGroupIncludesEveryone(t *testing.T) {
	c.Debug = false
	c.IPWhiteList = nil
	getGroups := func(string) []string { return nil }
	nl := UnifiNetworkList{Name: "open", Group: nil} // nil group -> hasGroup returns true
	list := map[string]string{"alice": "1.1.1.1/32", "bad": "not-an-ip"}
	got := nl.buildMembers(list, getGroups)
	if len(got) != 1 || got[0] != "1.1.1.1/32" {
		t.Errorf("buildMembers = %v, want [1.1.1.1/32] (invalid IP skipped)", got)
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
	if seen["1.1.1.1/32"] != 1 || seen["5.5.5.5/32"] != 1 {
		t.Errorf("expected each of 1.1.1.1/32 and 5.5.5.5/32 exactly once, got %v", got)
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
	fake := &fakeUnifiClient{group: unifiFirewallGroup{ID: "abc", Name: "l", GroupType: "address-group", Members: []string{"1.1.1.1/32"}}}
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
	fake := &fakeUnifiClient{group: unifiFirewallGroup{ID: "abc", Name: "l", GroupType: "address-group", Members: []string{"1.1.1.1/32"}}}
	nl := UnifiNetworkList{Name: "l", client: fake}
	if ret := nl.update(); ret != 0 {
		t.Fatalf("update() = %d, want 0", ret)
	}
	if fake.updateCalls != 1 {
		t.Fatalf("updateFirewallGroup called %d times, want 1", fake.updateCalls)
	}
	if fake.updated.ID != "abc" || len(fake.updated.Members) != 1 || fake.updated.Members[0] != "2.2.2.2/32" {
		t.Errorf("PUT body = %+v, want id=abc members=[2.2.2.2/32]", *fake.updated)
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

func TestUnifiApplicationClientGetAndUpdate(t *testing.T) {
	var loginHits, putHits int
	var putBody unifiFirewallGroup

	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		switch {
		case req.URL.Path == "/api/auth/login":
			loginHits++
			rw.Header().Set("X-CSRF-Token", "csrf123")
			rw.WriteHeader(http.StatusOK)
		case req.Method == http.MethodGet && strings.HasSuffix(req.URL.Path, "/rest/firewallgroup"):
			_ = json.NewEncoder(rw).Encode(map[string]interface{}{
				"data": []unifiFirewallGroup{{
					ID: "abc", Name: "ip-whitelister", GroupType: "address-group",
					Members: []string{"1.1.1.1/32"},
				}},
			})
		case req.Method == http.MethodPut && strings.Contains(req.URL.Path, "/rest/firewallgroup/abc"):
			putHits++
			if req.Header.Get("X-CSRF-Token") != "csrf123" {
				t.Errorf("PUT missing X-CSRF-Token header")
			}
			_ = json.NewDecoder(req.Body).Decode(&putBody)
			_ = json.NewEncoder(rw).Encode(map[string]interface{}{"data": []unifiFirewallGroup{}})
		default:
			rw.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	client := newUnifiClient(UnifiConfiguration{Host: srv.URL, Site: "default", Username: "u", Password: "p"})

	g, err := client.getFirewallGroup("ip-whitelister")
	if err != nil {
		t.Fatalf("getFirewallGroup error: %v", err)
	}
	if g.ID != "abc" || len(g.Members) != 1 || g.Members[0] != "1.1.1.1/32" {
		t.Fatalf("getFirewallGroup = %+v, want id=abc members=[1.1.1.1/32]", g)
	}

	g.Members = []string{"2.2.2.2/32"}
	if err := client.updateFirewallGroup(g); err != nil {
		t.Fatalf("updateFirewallGroup error: %v", err)
	}
	if putHits != 1 {
		t.Errorf("PUT hits = %d, want 1", putHits)
	}
	if putBody.ID != "abc" || len(putBody.Members) != 1 || putBody.Members[0] != "2.2.2.2/32" {
		t.Errorf("PUT body = %+v, want id=abc members=[2.2.2.2/32]", putBody)
	}
	if loginHits < 1 {
		t.Errorf("expected at least one login, got %d", loginHits)
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
