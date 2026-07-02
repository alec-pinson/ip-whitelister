# UniFi Network List Provider Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add UniFi as a whitelist provider that syncs whitelisted IPs into a UniFi Network List (firewall address-group) which a port-forward references via "From: List".

**Architecture:** Follows the existing Azure provider pattern — a `Unifi` aggregate of `UnifiNetworkList` resources, each with a `new()`/`update()` method, wired through `config.load()`'s `cloud→type` switch and iterated in `Whitelist.updateResources()`. The reconcile logic is transport-agnostic behind a small `unifiClient` interface (MVP impl = legacy Network Application API), so it is unit-testable without a live gateway. IPv4 only.

**Tech Stack:** Go 1.23, standard library (`net/http`, `net/http/cookiejar`, `crypto/tls`, `encoding/json`, `net/http/httptest`). No new dependencies.

---

## Background for the implementer (read first)

The app keeps Redis as the source of truth for who is currently whitelisted and
reconciles cloud resources *to* it. Each provider resource has an idempotent
`update()` that pushes the current IP set. UniFi's twist: a **Network List** in
the UniFi UI is a firewall **address-group** (`group_type: "address-group"`) — a
named list of IPs/CIDRs. A port-forward rule's "From: List" option points at one.
So restricting a forward's source IPs == editing that address-group's members.

Existing helpers you will reuse (do not reimplement):
- `w.inRange(ip string, whitelist []string) bool` — is `ip` already covered by a static entry (`whitelist.go`).
- `isValidIpOrNetV4(ip string) bool` — IPv4 address/CIDR check (`functions.go`).
- `hasGroup(resourceGroups, userGroups []string) bool` — AzureAD group filter; returns true when `resourceGroups == nil` (`functions.go`).
- `r.getWhitelist() map[string]string` and `r.getGroups(user string) []string` — Redis reads (`redis.go`).

Package is flat `package main`. Globals live in `main.go`:
`var ( c Configuration; r RedisConfiguration; h Authentication; w Whitelist; a Azure )`.
You will add `u Unifi`.

Run all tests with: `go test ./...`
(The Redis-backed tests spin up a docker container and take ~60s; the UniFi tests
added here do NOT need Redis or docker.)

---

## File Structure

- **Create `unifi.go`** — `Unifi` aggregate, `UnifiNetworkList` resource, `unifiClient` interface, `unifiFirewallGroup` DTO, pure helpers (`buildMembers`, `sameMembers`, `unifiEnabled`), `new()`, `update()`, and the real `unifiApplicationClient` (login + REST).
- **Create `unifi_test.go`** — unit tests for the pure helpers, `update()` (via a fake client), and the real client (via `httptest`).
- **Modify `config.go`** — `UnifiConfiguration` struct, `Unifi` field on `Configuration`, site default + env overrides, `u.NetworkList = nil` reset, and the `case "unifi"` load branch.
- **Modify `whitelist.go`** — add the UniFi loop + guard to `updateResources()`.
- **Modify `config/config.yaml`** — sample `unifi:` block + `networklist` resource (placeholder host).
- **Modify `README.md`** — document the UniFi provider + env vars.

---

## Task 1: Pure helper `sameMembers`

Order-insensitive multiset comparison used by `update()` to decide whether a PUT is needed.

**Files:**
- Create: `unifi.go`
- Test: `unifi_test.go`

- [ ] **Step 1: Write the failing test**

Create `unifi_test.go`:

```go
package main

import "testing"

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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -run TestSameMembers ./...`
Expected: FAIL — `undefined: sameMembers`

- [ ] **Step 3: Write minimal implementation**

Create `unifi.go`:

```go
package main

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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test -run TestSameMembers ./...`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add unifi.go unifi_test.go
git commit -m "feat: add sameMembers helper for unifi provider"
```

---

## Task 2: Types + `buildMembers`

Define the provider types and the pure function that computes the desired member set from the whitelist.

**Files:**
- Modify: `unifi.go`
- Test: `unifi_test.go`

- [ ] **Step 1: Write the failing test**

Add to `unifi_test.go`:

```go
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
		Group:       []string{"group-a"},       // only group-a users qualify
		IPWhiteList: []string{"8.8.8.8/32"},    // per-list static
	}

	list := map[string]string{
		"alice": "1.1.1.1/32", // in group-a  -> included
		"bob":   "2.2.2.2/32", // not in group-a -> excluded
		"carol": "10.0.0.0/8",  // carol static-covered below? no -> included (nil groups but nl.Group set -> excluded)
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -run TestBuildMembers ./...`
Expected: FAIL — `undefined: UnifiNetworkList`

- [ ] **Step 3: Write minimal implementation**

Add to `unifi.go` (below the `package main` line, above `sameMembers`):

```go
import "log"

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
```

Note: `log` is now imported; keep the existing file compiling (the `import "log"`
line must sit in a normal import block — merge with any future imports).

- [ ] **Step 4: Run test to verify it passes**

Run: `go test -run TestBuildMembers ./...`
Expected: PASS (both `TestBuildMembers` and `TestBuildMembersNilGroupIncludesEveryone`)

- [ ] **Step 5: Commit**

```bash
git add unifi.go unifi_test.go
git commit -m "feat: add unifi types and buildMembers reconcile logic"
```

---

## Task 3: `new()` and `update()` with a fake client

Wire the reconcile: fetch the group, diff, PUT only on change.

**Files:**
- Modify: `unifi.go`, `main.go`
- Test: `unifi_test.go`

- [ ] **Step 1: Add the global and write the failing test**

Add `u Unifi` to the global `var (...)` block in `main.go`:

```go
var (
	c Configuration
	r RedisConfiguration
	h Authentication
	w Whitelist
	a Azure
	u Unifi
)
```

Add to `unifi_test.go`:

```go
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
```

Add the sentinel error near the top of `unifi_test.go` (after the imports):

```go
import "errors"

var errFakeUnifi = errors.New("fake unifi error")
```

(Merge the `errors` import with the existing `testing` import in that file.)

Note: `update()` calls `r.getGroups` for the real path, but these tests use IPs
whose inclusion does not depend on group membership because `nl.Group` is nil
(`hasGroup(nil, ...)` returns true) — so `r.getGroups` is never consulted for a
decision. `r.getGroups` on a disconnected Redis returns an empty slice without
panicking; with a nil `nl.Group` the result is ignored.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -run 'TestUpdate' ./...`
Expected: FAIL — `nl.update undefined` / `undefined: UnifiNetworkList.new`

- [ ] **Step 3: Write minimal implementation**

Add to `unifi.go`:

```go
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test -run 'TestUpdate' ./...`
Expected: PASS (all four TestUpdate* cases)

- [ ] **Step 5: Commit**

```bash
git add unifi.go unifi_test.go main.go
git commit -m "feat: add unifi network list new() and update() reconcile"
```

---

## Task 4: The `unifiEnabled` guard

Pure predicate that gates the UniFi loop so a placeholder/empty host never touches a real gateway (mirrors the Azure `notreal-...` tenant guard).

**Files:**
- Modify: `unifi.go`
- Test: `unifi_test.go`

- [ ] **Step 1: Write the failing test**

Add to `unifi_test.go`:

```go
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -run TestUnifiEnabled ./...`
Expected: FAIL — `undefined: unifiEnabled` and `undefined: UnifiConfiguration`

(`UnifiConfiguration` is defined in Task 5. If running this task in isolation
fails to compile on that symbol, do Task 5 Step 3's struct definition first — the
two tasks are adjacent. Ordering note repeated here so out-of-order readers aren't
blocked.)

- [ ] **Step 3: Write minimal implementation**

Add to `unifi.go` (add `"strings"` to the import block):

```go
// unifiEnabled reports whether UniFi syncing should run. It is disabled when no
// host is configured or the host is the sample placeholder, so the dummy config
// never touches a real gateway.
func unifiEnabled(cfg UnifiConfiguration) bool {
	return cfg.Host != "" && !strings.Contains(cfg.Host, "notreal")
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test -run TestUnifiEnabled ./...`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add unifi.go unifi_test.go
git commit -m "feat: add unifiEnabled guard"
```

---

## Task 5: Config plumbing

Add the `unifi:` config block, env overrides, site default, reset-on-reload, and the `case "unifi"` load branch that constructs each list's client.

**Files:**
- Modify: `config.go`
- Test: `config_test.go`

- [ ] **Step 1: Write the failing test**

Add to `config_test.go`:

```go
import "os" // merge with existing imports in config_test.go

func TestUnifiConfigLoad(t *testing.T) {
	t.Setenv("UNIFI_USERNAME", "envuser")
	t.Setenv("UNIFI_PASSWORD", "envpass")

	ret := c.load()

	if ret.Unifi.Host == "" {
		t.Error("Failed to load config, missing config.unifi.host")
	}
	if ret.Unifi.Site != "default" {
		t.Errorf("expected unifi.site default 'default', got %q", ret.Unifi.Site)
	}
	if ret.Unifi.Username != "envuser" || ret.Unifi.Password != "envpass" {
		t.Errorf("UNIFI_USERNAME/PASSWORD env overrides not applied: %+v", ret.Unifi)
	}
	found := false
	for _, nl := range u.NetworkList {
		if nl.Name == "ip-whitelister" {
			found = true
			if nl.client == nil {
				t.Error("network list client was not constructed")
			}
		}
	}
	if !found {
		t.Error("expected a unifi networklist resource named 'ip-whitelister' to be loaded")
	}
}
```

(This test depends on the sample-config changes in Task 7. If you run it before
Task 7, it will fail on the missing `unifi:` block — that is expected; Task 7
adds the sample config. Recommended order: do Task 5 Steps 1–3 to add the code,
then Task 7 to add the sample config, then re-run this test at Task 7 Step 4.)

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -run TestUnifiConfigLoad ./...`
Expected: FAIL — `ret.Unifi undefined (type *Configuration has no field Unifi)`

- [ ] **Step 3: Write minimal implementation**

In `config.go`, add the config struct (below `Defaults`):

```go
// UnifiConfiguration holds the single UniFi gateway connection + credentials.
type UnifiConfiguration struct {
	Host     string `yaml:"host"`
	Site     string `yaml:"site"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}
```

Add the field to `Configuration`:

```go
	Unifi       UnifiConfiguration      `yaml:"unifi"`
```

In `config.load()`, just after the `if c.TTL == 0 { c.TTL = 24 }` block, add the
site default + env overrides (placed BEFORE the resource loop so the constructed
clients capture the final credentials):

```go
	if c.Unifi.Site == "" {
		c.Unifi.Site = "default"
	}
	if os.Getenv("UNIFI_USERNAME") != "" {
		c.Unifi.Username = os.Getenv("UNIFI_USERNAME")
	}
	if os.Getenv("UNIFI_PASSWORD") != "" {
		c.Unifi.Password = os.Getenv("UNIFI_PASSWORD")
	}
```

Add `u.NetworkList = nil` to the "empty resources first" reset block (alongside
the `a.* = nil` lines):

```go
	u.NetworkList = nil
```

Add the `case "unifi"` branch to the `switch strings.ToLower(resource.Cloud)`
statement (as a sibling of `case "azure"`):

```go
		case "unifi":
			switch strings.ToLower(resource.Type) {
			case "networklist":
				var nl UnifiNetworkList
				nl.Name = resource.Name
				nl.Group = resource.Group
				nl.IPWhiteList = resource.IPWhiteList
				nl.client = newUnifiClient(c.Unifi)
				nl.new(nl)
			default:
				log.Fatalln("config.load(): unsupported " + resource.Cloud + " resource type '" + resource.Type + "'")
			}
```

(`os` is already imported in `config.go`. `newUnifiClient` is added in Task 6 —
if compiling now, temporarily stub it as `func newUnifiClient(UnifiConfiguration) unifiClient { return nil }`
at the bottom of `unifi.go` and replace it in Task 6. Cleaner: do Task 6 before
compiling Task 5.)

- [ ] **Step 4: Run test to verify it passes** (after Task 6 + Task 7 are done)

Run: `go test -run TestUnifiConfigLoad ./...`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add config.go config_test.go
git commit -m "feat: load unifi config block and networklist resources"
```

---

## Task 6: Real client `unifiApplicationClient` (legacy Network Application API)

Login (cookie + CSRF) then GET/PUT the firewall group. Tested with `httptest`.

**Files:**
- Modify: `unifi.go`
- Test: `unifi_test.go`

- [ ] **Step 1: Write the failing test**

Add to `unifi_test.go` (merge new imports into the file's import block):

```go
import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
)

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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -run TestUnifiApplicationClient ./...`
Expected: FAIL — `undefined: newUnifiClient`

- [ ] **Step 3: Write minimal implementation**

Add to `unifi.go` (merge imports: `bytes`, `crypto/tls`, `encoding/json`,
`fmt`, `net/http`, `net/http/cookiejar`, `time`, plus existing `log`, `strings`):

```go
type unifiApplicationClient struct {
	cfg  UnifiConfiguration
	http *http.Client
	csrf string
}

// newUnifiClient builds the MVP legacy-Application-API client. TLS verification is
// skipped because UniFi gateways ship self-signed certificates.
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

func (uc *unifiApplicationClient) getFirewallGroup(name string) (unifiFirewallGroup, error) {
	if err := uc.login(); err != nil {
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
	if err := uc.login(); err != nil {
		return err
	}
	body, _ := json.Marshal(g)
	req, err := http.NewRequest(http.MethodPut, uc.base()+"/"+g.ID, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", uc.csrf)
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test -run TestUnifiApplicationClient ./...`
Expected: PASS (both cases)

- [ ] **Step 5: Run the full non-Redis unifi suite + build**

Run: `go build ./... && go test -run 'Unifi|SameMembers|BuildMembers|TestUpdate' ./...`
Expected: build OK, all PASS

- [ ] **Step 6: Commit**

```bash
git add unifi.go unifi_test.go
git commit -m "feat: add unifi legacy Application API client (login + firewallgroup GET/PUT)"
```

---

## Task 7: Wire `updateResources()` + sample config

Add the guarded UniFi loop to the reconcile driver and the sample config that the config-load test depends on.

**Files:**
- Modify: `whitelist.go`, `config/config.yaml`
- Test: `config_test.go` (from Task 5)

- [ ] **Step 1: Add the UniFi loop to `updateResources()`**

In `whitelist.go`, inside `updateResources()`, after the `for _, cd := range a.CosmosDb { cd.update() }` loop and before `return true`, add:

```go
	if unifiEnabled(c.Unifi) {
		for _, nl := range u.NetworkList {
			nl.update()
		}
	}
```

- [ ] **Step 2: Add the sample `unifi:` block + resource to `config/config.yaml`**

After the `redis:` block (and before `resources:`), add:

```yaml
# UniFi gateway for the 'unifi' provider (single gateway).
# Username/Password can also be set via env vars UNIFI_USERNAME / UNIFI_PASSWORD.
# Host contains 'notreal' so the sample config never touches a real gateway.
unifi:
  host: https://notreal.gateway
  site: default
  username: ip-whitelister
  password: notrealnotrealnotreal
```

Add a resource entry to the `resources:` list (as a sibling of the azure entries):

```yaml
  - cloud: unifi
    type: networklist
    name: ip-whitelister # the UniFi Network List to keep in sync
```

- [ ] **Step 3: Run the config-load test**

Run: `go test -run TestUnifiConfigLoad ./...`
Expected: PASS

- [ ] **Step 4: Run the full suite**

Run: `go test ./...`
Expected: PASS (Redis-backed tests included; ~60s)

- [ ] **Step 5: Commit**

```bash
git add whitelist.go config/config.yaml
git commit -m "feat: run unifi network list sync in updateResources and add sample config"
```

---

## Task 8: Documentation

Document the provider and its env vars in the README.

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Add a UniFi section to `README.md`**

Find the section documenting resource configuration / providers and add:

```markdown
### UniFi (Network List / port-forward whitelisting)

The `unifi` provider keeps a UniFi **Network List** (a firewall address-group) in
sync with the current whitelist. Point a port-forward rule's **From: List** at
that Network List and its allowed source IPs will track whitelisted users.

Configure the single gateway once, then add a `networklist` resource per list:

```yaml
unifi:
  host: https://192.168.1.1   # gateway base URL
  site: default               # UniFi site name
  username: ip-whitelister    # dedicated local account (see below)
  password: changeme

resources:
  - cloud: unifi
    type: networklist
    name: ip-whitelister      # the Network List to manage
    group:                    # optional: only whitelist users in these AzureAD groups
      - <group-object-id>
    ip_whitelist:             # optional: per-list static entries
      - 1.2.3.4/32
```

Credentials can be injected via environment variables (recommended):
`UNIFI_USERNAME`, `UNIFI_PASSWORD` (these override the YAML values, matching
`CLIENT_SECRET` / `REDIS_TOKEN`).

Notes:
- Use a dedicated limited local UniFi account, not your main admin login.
- Create the Network List and the port-forward "From: List" reference once in the
  UniFi UI; the app only manages the list's members.
- IPv4 only for now.
```

- [ ] **Step 2: Verify the build/tests still pass (docs-only, sanity)**

Run: `go test ./...`
Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "docs: document unifi network list provider"
```

---

## Final validation (manual, against the live gateway)

Not a code task — do this once the MCP/gateway is reachable:

1. In the UniFi UI, create a throwaway Network List `ip-whitelister` (IPv4).
2. Point a test port-forward's **From: List** at it.
3. Set real `unifi.host` / credentials (via env vars) and run the app.
4. Whitelist your IP in the web UI; confirm it appears in the Network List.
5. Confirm it drops out after the TTL (or force `updateResources()` by restart).
6. **Confirm member format:** check whether UniFi stores `x.x.x.x/32` or bare
   `x.x.x.x`. If it normalises to bare IPs, the reconcile will PUT on every sync
   (harmless but noisy) — if so, normalise members in `buildMembers`
   (e.g. `deleteNetmask` single hosts) and update `TestBuildMembers`.

---

## Self-review notes (for the executor)

- Every task is TDD (failing test → minimal impl → pass → commit).
- Cross-task type consistency: `unifiClient` interface methods
  (`getFirewallGroup`, `updateFirewallGroup`) and the `unifiFirewallGroup` DTO
  (`ID`/`Name`/`GroupType`/`Members`) are used identically in Tasks 3 and 6.
- Ordering caveat: Task 5 references `newUnifiClient` (Task 6) and the sample
  config (Task 7). Do Tasks 1→2→3→4→6→5→7→8, or use the stub noted in Task 5
  Step 3. The plan is written in reading order; the executor should follow the
  dependency order above.
```
