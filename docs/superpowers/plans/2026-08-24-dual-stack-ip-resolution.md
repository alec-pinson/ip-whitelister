# Dual-stack IP Resolution Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let one user hold both an IPv4 and an IPv6 whitelist entry at the same time, captured via a new `ip_resolution` config block and stored under family-suffixed Redis keys.

**Architecture:** Two independent halves. **Storage** — Redis DB0 gains a `:v6` key suffix so an IPv6 entry no longer overwrites the same user's IPv4 entry; providers are untouched because `r.getGroups()` normalises the suffix away and PR #8's `matchesIpVersion` guards already route entries by family. **Capture** — a new `ip_resolution` block describes per family how to learn an address (trusted proxy header / connection, and/or a browser-side fetch to a family-pinned echo service), with claims posted back to a new `/resolve` endpoint.

**Tech Stack:** Go 1.x, flat `package main` at repo root. `gopkg.in/yaml.v2` for config, `gomodule/redigo` for Redis, `html/template` for pages, `ory/dockertest` for Redis-backed tests.

**Spec:** `docs/superpowers/specs/2026-08-24-dual-stack-ip-resolution-design.md`

**Branch:** `feat/dual-stack-ip-resolution` (already created; spec already committed)

---

## File Structure

| File | Responsibility after this plan |
|------|-------------------------------|
| `functions.go` | Pure helpers. Gains `redisKey` / `baseKey`. |
| `redis.go` | Redis I/O. `getGroups` normalises the family suffix. |
| `whitelist.go` | `add()` becomes family-aware and enforces `ip_resolution` enablement. |
| `config.go` | `IpResolution` / `IpFamilyResolution` types, validation, `auth.ip_header` deprecation. |
| `user.go` | `observedIp()` — resolution order for the address the app sees. |
| `http.go` | `/resolve` handler, `pendingProbes()`, probe JS in both templates. |
| `config/config.yaml`, `README.md` | Documentation. |

Tests live beside their subject in the existing `*_test.go` files. **Tests touching Redis need Docker and are slow (~66s suite);** pure-logic tests go in `functions_test.go` / `config_test.go`, which need neither.

Notes that affect several tasks:

- Globals are declared in `main.go:3-10`: `c Configuration`, `r RedisConfiguration`, `h Authentication`, `w Whitelist`, `a Azure`, `u Unifi`. Inside `user.go` methods, `u` is the `*User` receiver and shadows the `Unifi` global — do not add code referring to the Unifi global inside a `User` method.
- `config.load()` is never called by most tests, so every new type must behave correctly at its Go zero value. A `nil` `Enabled` pointer must mean *enabled*.

---

## Task 1: Family-suffixed Redis key helpers

**Files:**
- Modify: `functions.go`
- Test: `functions_test.go`

- [ ] **Step 1: Write the failing test**

Append to `functions_test.go`:

```go
func TestRedisKey(t *testing.T) {
	tests := []struct {
		base string
		t    IpType
		want string
	}{
		// ipv4 keeps the bare user key, so existing entries need no migration
		{"alecpinson123456", IpV4, "alecpinson123456"},
		{"alecpinson123456", IpV6, "alecpinson123456:v6"},
		// an unknown family is treated as ipv4 rather than inventing a third key
		{"alecpinson123456", Undefined, "alecpinson123456"},
		// auth.type none derives the key from the ip itself; the regex strip in
		// finishUser leaves only [a-z0-9], so ':' can never collide
		{"2a001", IpV6, "2a001:v6"},
	}

	for _, f := range tests {
		if got := redisKey(f.base, f.t); got != f.want {
			t.Errorf("redisKey(%q, %v) = %q, want %q", f.base, f.t, got, f.want)
		}
	}
}

func TestBaseKey(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"alecpinson123456", "alecpinson123456"},
		{"alecpinson123456:v6", "alecpinson123456"},
		{"2a001:v6", "2a001"},
		// only a trailing suffix is stripped
		{"alec:v6user", "alec:v6user"},
	}

	for _, f := range tests {
		if got := baseKey(f.in); got != f.want {
			t.Errorf("baseKey(%q) = %q, want %q", f.in, got, f.want)
		}
	}
}

func TestRedisKeyRoundTrip(t *testing.T) {
	for _, base := range []string{"alecpinson123456", "2a001", "a"} {
		for _, ipType := range []IpType{IpV4, IpV6} {
			if got := baseKey(redisKey(base, ipType)); got != base {
				t.Errorf("baseKey(redisKey(%q, %v)) = %q, want %q", base, ipType, got, base)
			}
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -run 'TestRedisKey|TestBaseKey' -v .`
Expected: FAIL — `undefined: redisKey`, `undefined: baseKey`

- [ ] **Step 3: Write minimal implementation**

Append to `functions.go`:

```go
// redisKeySuffixV6 distinguishes a user's IPv6 whitelist entry from their IPv4
// one in Redis DB0. IPv4 keeps the bare user key so entries written before
// dual-stack support need no migration. A user key is [a-z0-9]+ after the regex
// strip in finishUser, so ':' can never collide with a generated key.
const redisKeySuffixV6 = ":v6"

// redisKey returns the DB0 key holding this user's address for family t.
func redisKey(base string, t IpType) string {
	if t == IpV6 {
		return base + redisKeySuffixV6
	}
	return base
}

// baseKey strips any family suffix, returning the plain user key used by the
// groups cache (DB1) and the API throttle (DB2), both of which are per user
// rather than per address family.
func baseKey(k string) string {
	return strings.TrimSuffix(k, redisKeySuffixV6)
}
```

`strings` is already imported in `functions.go:7`.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test -run 'TestRedisKey|TestBaseKey' -v .`
Expected: PASS (3 tests)

- [ ] **Step 5: Commit**

```bash
git add functions.go functions_test.go
git commit -m "feat: add family-suffixed redis key helpers"
```

---

## Task 2: Normalise the family suffix in getGroups

This is what keeps all seven providers unchanged: they call `r.getGroups(key)` with whatever key they read out of `w.List`, which may now carry a `:v6` suffix, while the groups cache is keyed per user.

**Files:**
- Modify: `redis.go:181-210`
- Test: `redis_test.go` (needs Docker — slow)

- [ ] **Step 1: Write the failing test**

Append to `redis_test.go`:

```go
func TestGetGroupsIgnoresFamilySuffix(t *testing.T) {
	var testRedisInstance = CreateTestRedis(t)
	var rc RedisConfiguration
	rc.Host = testRedisInstance.Host
	rc.Port = testRedisInstance.Port
	rc.Token = testRedisInstance.Token
	if r.connect(rc) {
		const user = "testuser111111"
		if !r.addGroups(user, []string{"group1", "group2"}) {
			t.Fatal("failed to seed groups")
		}

		// providers read keys straight out of w.List, which now contains
		// family-suffixed entries; both forms must find the same cached groups
		if got := r.getGroups(user); len(got) != 2 {
			t.Errorf("getGroups(%q) = %v, want 2 groups", user, got)
		}
		if got := r.getGroups(user + redisKeySuffixV6); len(got) != 2 {
			t.Errorf("getGroups(%q) = %v, want 2 groups", user+redisKeySuffixV6, got)
		}
	}

	DeleteTestRedis(t, testRedisInstance)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -run TestGetGroupsIgnoresFamilySuffix -v .`
Expected: FAIL — the suffixed lookup returns 0 groups

- [ ] **Step 3: Write minimal implementation**

In `redis.go`, change the opening of `getGroups` (line 181) from:

```go
func (r RedisConfiguration) getGroups(user string) []string {
	var g []string
```

to:

```go
func (r RedisConfiguration) getGroups(user string) []string {
	// w.List keys carry a family suffix, but the groups cache is per user —
	// normalising here is what lets every provider stay unchanged.
	user = baseKey(user)

	var g []string
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test -run TestGetGroupsIgnoresFamilySuffix -v .`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add redis.go redis_test.go
git commit -m "feat: normalise family suffix in redis getGroups"
```

---

## Task 3: Config types for `ip_resolution`

Validation is split into a testable `resolveIpResolution` returning an error plus a fatal wrapper, mirroring the existing `resolveIpVersion` / `mustResolveIpVersion` pair at `config.go:102-126`.

**Files:**
- Modify: `config.go`
- Test: `config_test.go`

- [ ] **Step 1: Write the failing test**

Append to `config_test.go`:

```go
func boolPtr(b bool) *bool { return &b }

func TestIsEnabledDefaultsToTrue(t *testing.T) {
	// the zero value must mean enabled: config.load() is never called in most
	// tests, and an omitted block must not disable whitelisting
	if !(IpFamilyResolution{}).isEnabled() {
		t.Error("zero-value IpFamilyResolution should be enabled")
	}
	if !(IpFamilyResolution{Enabled: boolPtr(true)}).isEnabled() {
		t.Error("explicit true should be enabled")
	}
	if (IpFamilyResolution{Enabled: boolPtr(false)}).isEnabled() {
		t.Error("explicit false should be disabled")
	}
}

func TestResolveIpResolutionDefaults(t *testing.T) {
	got, err := resolveIpResolution(IpResolution{}, "")
	if err != nil {
		t.Fatalf("empty block should be valid, got: %v", err)
	}
	if !got.IPv4.isEnabled() || !got.IPv6.isEnabled() {
		t.Error("both families should default to enabled")
	}
	if got.IPv4.Header != "X-Azure-Clientip" || got.IPv6.Header != "X-Azure-Clientip" {
		t.Errorf("headers should default to X-Azure-Clientip, got %q / %q", got.IPv4.Header, got.IPv6.Header)
	}
	if got.IPv4.timeout() != defaultUrlTimeout {
		t.Errorf("timeout = %v, want %v", got.IPv4.timeout(), defaultUrlTimeout)
	}
}

func TestResolveIpResolutionDeprecatedAuthHeader(t *testing.T) {
	// auth.ip_header still fills in for a family that names no header of its own
	got, err := resolveIpResolution(IpResolution{}, "Cf-Connecting-Ip")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.IPv4.Header != "Cf-Connecting-Ip" || got.IPv6.Header != "Cf-Connecting-Ip" {
		t.Errorf("auth.ip_header not used as fallback, got %q / %q", got.IPv4.Header, got.IPv6.Header)
	}

	// an explicit per-family header wins over the deprecated field
	got, err = resolveIpResolution(IpResolution{IPv4: IpFamilyResolution{Header: "X-Own"}}, "Cf-Connecting-Ip")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.IPv4.Header != "X-Own" {
		t.Errorf("explicit header should win, got %q", got.IPv4.Header)
	}
	if got.IPv6.Header != "Cf-Connecting-Ip" {
		t.Errorf("other family should still fall back, got %q", got.IPv6.Header)
	}
}

func TestResolveIpResolutionTimeout(t *testing.T) {
	got, err := resolveIpResolution(IpResolution{
		IPv4: IpFamilyResolution{Url: "https://ipv4.icanhazip.com", UrlTimeout: "2s"},
	}, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.IPv4.timeout() != 2*time.Second {
		t.Errorf("timeout = %v, want 2s", got.IPv4.timeout())
	}
	// a url with no explicit timeout falls back to the default
	if got.IPv6.timeout() != defaultUrlTimeout {
		t.Errorf("unset timeout = %v, want %v", got.IPv6.timeout(), defaultUrlTimeout)
	}
}

func TestResolveIpResolutionErrors(t *testing.T) {
	cases := []struct {
		name string
		in   IpResolution
	}{
		{
			"both families disabled",
			IpResolution{
				IPv4: IpFamilyResolution{Enabled: boolPtr(false)},
				IPv6: IpFamilyResolution{Enabled: boolPtr(false)},
			},
		},
		{
			"url on a disabled family",
			IpResolution{
				IPv6: IpFamilyResolution{Enabled: boolPtr(false), Url: "https://ipv6.icanhazip.com"},
			},
		},
		{
			"url_timeout without url",
			IpResolution{IPv4: IpFamilyResolution{UrlTimeout: "5s"}},
		},
		{
			"unparseable url_timeout",
			IpResolution{IPv4: IpFamilyResolution{Url: "https://ipv4.icanhazip.com", UrlTimeout: "soon"}},
		},
		{
			"non-positive url_timeout",
			IpResolution{IPv4: IpFamilyResolution{Url: "https://ipv4.icanhazip.com", UrlTimeout: "0s"}},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := resolveIpResolution(tc.in, ""); err == nil {
				t.Errorf("expected an error for %s", tc.name)
			}
		})
	}
}

func TestIpResolutionFamily(t *testing.T) {
	ir := IpResolution{
		IPv4: IpFamilyResolution{Url: "https://v4.example.com"},
		IPv6: IpFamilyResolution{Url: "https://v6.example.com"},
	}

	fr, ipType, ok := ir.family("ipv4")
	if !ok || ipType != IpV4 || fr.Url != "https://v4.example.com" {
		t.Errorf("family(ipv4) = %+v, %v, %v", fr, ipType, ok)
	}
	// normalised like ip_version is
	if _, _, ok := ir.family("  IPv6  "); !ok {
		t.Error("family() should normalise case and whitespace")
	}
	if _, _, ok := ir.family("ipv5"); ok {
		t.Error("family(ipv5) should not be ok")
	}
}

func TestIpResolutionEnabledFor(t *testing.T) {
	ir := IpResolution{IPv6: IpFamilyResolution{Enabled: boolPtr(false)}}
	if !ir.enabledFor(IpV4) {
		t.Error("ipv4 should be enabled")
	}
	if ir.enabledFor(IpV6) {
		t.Error("ipv6 should be disabled")
	}
}
```

Add `"time"` to the imports of `config_test.go`.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -run 'TestIsEnabled|TestResolveIpResolution|TestIpResolution' -v .`
Expected: FAIL — `undefined: IpFamilyResolution`, `undefined: resolveIpResolution`

- [ ] **Step 3: Write minimal implementation**

Add `"errors"` and `"time"` to the imports of `config.go`, then append these types and functions:

```go
// IpResolution describes, per address family, how the app learns a user's
// address. It governs what we COLLECT; a resource's ip_version governs where we
// SEND it. The two are orthogonal.
type IpResolution struct {
	IPv4 IpFamilyResolution `yaml:"ipv4"`
	IPv6 IpFamilyResolution `yaml:"ipv6"`
}

// IpFamilyResolution is one family's settings. Enabled is a pointer because
// Go's zero value for bool is false, which would make an omitted block
// indistinguishable from an explicitly disabled one and silently disable
// whitelisting for every existing config.
type IpFamilyResolution struct {
	Enabled    *bool  `yaml:"enabled"`
	Header     string `yaml:"header"`
	Url        string `yaml:"url"`
	UrlTimeout string `yaml:"url_timeout"`

	// resolved from UrlTimeout by resolveIpResolution. yaml.v2 cannot unmarshal
	// "5s" into a time.Duration — it only maps integers, as nanoseconds — so the
	// config field stays a string and is parsed here.
	timeoutDur time.Duration
}

const defaultUrlTimeout = 5 * time.Second
const defaultIpHeader = "X-Azure-Clientip"

// isEnabled reports whether this family may be whitelisted. An unset Enabled
// means true.
func (f IpFamilyResolution) isEnabled() bool {
	return f.Enabled == nil || *f.Enabled
}

// timeout is how long the browser may spend fetching Url.
func (f IpFamilyResolution) timeout() time.Duration {
	if f.timeoutDur <= 0 {
		return defaultUrlTimeout
	}
	return f.timeoutDur
}

// family returns the settings and IpType for a named address family.
func (ir IpResolution) family(name string) (IpFamilyResolution, IpType, bool) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case ipVersionV4:
		return ir.IPv4, IpV4, true
	case ipVersionV6:
		return ir.IPv6, IpV6, true
	}
	return IpFamilyResolution{}, Undefined, false
}

// enabledFor reports whether addresses of family t may be whitelisted.
func (ir IpResolution) enabledFor(t IpType) bool {
	if t == IpV6 {
		return ir.IPv6.isEnabled()
	}
	return ir.IPv4.isEnabled()
}

// headers returns the distinct client-IP header names to try, ipv4 first. It
// falls back to the deprecated auth.ip_header and then the Front Door default,
// so it behaves correctly even when config.load() has not run (as in tests).
func (ir IpResolution) headers() []string {
	out := []string{}
	for _, h := range []string{ir.IPv4.Header, ir.IPv6.Header} {
		if h == "" {
			continue
		}
		dup := false
		for _, e := range out {
			if e == h {
				dup = true
			}
		}
		if !dup {
			out = append(out, h)
		}
	}
	if len(out) == 0 {
		if c.Auth.IPHeader != "" {
			return []string{c.Auth.IPHeader}
		}
		return []string{defaultIpHeader}
	}
	return out
}

// resolveIpResolution validates the ip_resolution block and fills in derived
// values: the header fallback chain and the parsed url_timeout. authIpHeader is
// the deprecated auth.ip_header. It returns an error rather than exiting so it
// can be tested; load() wraps it with a fatal, matching mustResolveIpVersion.
func resolveIpResolution(ir IpResolution, authIpHeader string) (IpResolution, error) {
	if !ir.IPv4.isEnabled() && !ir.IPv6.isEnabled() {
		return ir, errors.New("ip_resolution: both ipv4 and ipv6 are disabled, nothing could ever be whitelisted")
	}

	families := []struct {
		name string
		fr   *IpFamilyResolution
	}{
		{ipVersionV4, &ir.IPv4},
		{ipVersionV6, &ir.IPv6},
	}

	for _, f := range families {
		if f.fr.Header == "" {
			f.fr.Header = authIpHeader
		}
		if f.fr.Header == "" {
			f.fr.Header = defaultIpHeader
		}

		if f.fr.Url != "" && !f.fr.isEnabled() {
			return ir, errors.New("ip_resolution." + f.name + ": url is set on a disabled family")
		}
		if f.fr.UrlTimeout != "" {
			if f.fr.Url == "" {
				return ir, errors.New("ip_resolution." + f.name + ": url_timeout is set without url")
			}
			d, err := time.ParseDuration(f.fr.UrlTimeout)
			if err != nil {
				return ir, errors.New("ip_resolution." + f.name + ": invalid url_timeout '" + f.fr.UrlTimeout + "'")
			}
			if d <= 0 {
				return ir, errors.New("ip_resolution." + f.name + ": url_timeout must be positive, got '" + f.fr.UrlTimeout + "'")
			}
			f.fr.timeoutDur = d
		}
	}

	return ir, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test -run 'TestIsEnabled|TestResolveIpResolution|TestIpResolution' -v .`
Expected: PASS (7 tests)

- [ ] **Step 5: Commit**

```bash
git add config.go config_test.go
git commit -m "feat: add ip_resolution config types and validation"
```

---

## Task 4: Wire `ip_resolution` into config.load()

**Files:**
- Modify: `config.go:14-25` (struct field), `config.go:176` (load wiring)
- Test: `config_test.go`

The deprecation warning must read the **raw** `auth.ip_header`, captured before `applyAuthDefaults` runs — that function sets `IPHeader` to `Cf-Connecting-Ip` for every `auth.type: none` config (`config.go:137-139`), so warning afterwards would fire for users who never set the field.

- [ ] **Step 1: Write the failing test**

Append to `config_test.go`:

```go
func TestLoadIpResolutionDefaults(t *testing.T) {
	ret := c.load()

	// the sample config has no ip_resolution block, so both families must come
	// out enabled with a usable header — today's behaviour, unchanged
	if !ret.IpResolution.IPv4.isEnabled() || !ret.IpResolution.IPv6.isEnabled() {
		t.Error("both families should be enabled when the block is omitted")
	}
	if ret.IpResolution.IPv4.Header == "" || ret.IpResolution.IPv6.Header == "" {
		t.Errorf("headers should be populated, got %q / %q", ret.IpResolution.IPv4.Header, ret.IpResolution.IPv6.Header)
	}
	if len(ret.IpResolution.headers()) == 0 {
		t.Error("headers() should never be empty")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -run TestLoadIpResolutionDefaults -v .`
Expected: FAIL — `ret.IpResolution undefined`

- [ ] **Step 3: Write minimal implementation**

In `config.go`, add the field to `Configuration` (after `Unifi` on line 24):

```go
	Unifi        UnifiConfiguration      `yaml:"unifi"`
	IpResolution IpResolution            `yaml:"ip_resolution"`
```

Then replace `config.go:176`:

```go
	c.Auth = applyAuthDefaults(c.Auth)
```

with:

```go
	// captured before applyAuthDefaults, which sets IPHeader for auth.type none
	// — warning afterwards would fire for configs that never set the field
	deprecatedIpHeader := c.Auth.IPHeader

	c.Auth = applyAuthDefaults(c.Auth)

	if deprecatedIpHeader != "" {
		log.Println("config.load(): WARNING auth.ip_header is deprecated, use ip_resolution.<family>.header instead")
	}

	ipResolution, err := resolveIpResolution(c.IpResolution, c.Auth.IPHeader)
	if err != nil {
		log.Fatalln("config.load(): " + err.Error())
	}
	c.IpResolution = ipResolution

	// client-asserted resolution weakens the trust model: the address arrives as
	// a claim rather than something the app observed. Setting url is the opt-in,
	// so record it in the log rather than behind a config flag.
	if c.IpResolution.IPv4.Url != "" {
		log.Println("config.load(): ipv4 uses client-asserted resolution via " + c.IpResolution.IPv4.Url)
	}
	if c.IpResolution.IPv6.Url != "" {
		log.Println("config.load(): ipv6 uses client-asserted resolution via " + c.IpResolution.IPv6.Url)
	}
```

`err` is already in scope from `load()` line 163; `ipResolution, err := ...` is still valid because `ipResolution` is new.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test -run 'TestLoad|TestUnifiConfigLoad' -v .`
Expected: PASS — including the pre-existing `TestLoad` and `TestUnifiConfigLoad`, which must not regress

- [ ] **Step 5: Commit**

```bash
git add config.go config_test.go
git commit -m "feat: wire ip_resolution into config load with ip_header deprecation"
```

---

## Task 5: Resolution order in observedIp

**Files:**
- Modify: `user.go:103-144`
- Test: `user_test.go`

- [ ] **Step 1: Write the failing test**

Append to `user_test.go`:

```go
func TestObservedIp(t *testing.T) {
	defer func() { c.IpResolution = IpResolution{}; c.Auth.IPHeader = "" }()

	// a per-family header is read
	c.IpResolution = IpResolution{
		IPv4: IpFamilyResolution{Header: "Cf-Connecting-Ip"},
		IPv6: IpFamilyResolution{Header: "Cf-Connecting-Ip"},
	}
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Cf-Connecting-Ip", "203.0.113.7")
	if got := observedIp(req); got != "203.0.113.7" {
		t.Errorf("observedIp() = %q, want %q", got, "203.0.113.7")
	}

	// the two families may name different headers; both are tried, ipv4 first
	c.IpResolution = IpResolution{
		IPv4: IpFamilyResolution{Header: "X-V4-Ip"},
		IPv6: IpFamilyResolution{Header: "X-V6-Ip"},
	}
	req = httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-V6-Ip", "2a00:11c7:1234:b801::1")
	if got := observedIp(req); got != "2a00:11c7:1234:b801::1" {
		t.Errorf("observedIp() = %q, want the ipv6 header value", got)
	}

	// with no header present, fall back to RemoteAddr
	c.IpResolution = IpResolution{}
	req = httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "198.51.100.9:54321"
	if got := observedIp(req); got != "198.51.100.9" {
		t.Errorf("observedIp() = %q, want %q", got, "198.51.100.9")
	}

	// the deprecated auth.ip_header still works when no family names one
	c.IpResolution = IpResolution{}
	c.Auth.IPHeader = "X-Legacy-Ip"
	req = httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Legacy-Ip", "203.0.113.8")
	if got := observedIp(req); got != "203.0.113.8" {
		t.Errorf("observedIp() = %q, want %q", got, "203.0.113.8")
	}
}
```

Ensure `user_test.go` imports `net/http/httptest` and `testing`.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -run TestObservedIp -v .`
Expected: FAIL — `undefined: observedIp`

- [ ] **Step 3: Write minimal implementation**

In `user.go`, add above `finishUser`:

```go
// observedIp returns the client address as the app sees it: the first
// ip_resolution header that is present, falling back to RemoteAddr. This is the
// trusted path — the value is something the app or its proxy observed, not
// something the client asserted.
func observedIp(req *http.Request) string {
	for _, header := range c.IpResolution.headers() {
		if v := req.Header.Get(header); v != "" {
			return v
		}
	}
	ip, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		log.Printf("user.observedIp(): %q is not IP:port\n", req.RemoteAddr)
		return ""
	}
	return ip
}
```

Then replace the header block in `finishUser` (`user.go:104-118`) with:

```go
	// the client IP as observed by the app or its trusted proxy
	u.ip = observedIp(req)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test -run 'TestObservedIp|TestNoAuthIndexHandler' -v .`
Expected: PASS — `TestNoAuthIndexHandler` (Docker, slow) must still pass, proving the deprecated `c.Auth.IPHeader` path still works

- [ ] **Step 5: Commit**

```bash
git add user.go user_test.go
git commit -m "feat: resolve observed client ip via ip_resolution headers"
```

---

## Task 6: Family-aware whitelist.add()

**Files:**
- Modify: `whitelist.go:37-72`
- Test: `whitelist_test.go` (needs Docker — slow)

`addGroups`, `apiCalled` and `canCallApi` keep taking the **base** key: the groups cache and the API throttle are per user, not per family. Only `addIp` and `setIpExpiry` take the family key.

- [ ] **Step 1: Write the failing test**

Append to `whitelist_test.go`:

```go
func TestAddDualStack(t *testing.T) {
	var testRedisInstance = CreateTestRedis(t)
	var rc RedisConfiguration
	rc.Host = testRedisInstance.Host
	rc.Port = testRedisInstance.Port
	rc.Token = testRedisInstance.Token
	defer DeleteTestRedis(t, testRedisInstance)

	c.TTL = 24
	c.IPWhiteList = nil
	c.IpResolution = IpResolution{}
	defer func() { c.IpResolution = IpResolution{} }()

	if !r.connect(rc) {
		t.Fatal("could not connect to test redis")
	}

	v4 := &User{key: "dualstackuser", ip: "203.0.113.7", cidr: "203.0.113.7/32"}
	v6 := &User{key: "dualstackuser", ip: "2a00:11c7:1234:b801::1", cidr: "2a00:11c7:1234:b801::1/128"}

	if !w.add(v4) {
		t.Fatal("adding the ipv4 address failed")
	}
	if !w.add(v6) {
		t.Fatal("adding the ipv6 address failed")
	}

	list := r.getWhitelist()
	if got := list["dualstackuser"]; got != "203.0.113.7/32" {
		t.Errorf("ipv4 entry = %q, want %q", got, "203.0.113.7/32")
	}
	if got := list["dualstackuser"+redisKeySuffixV6]; got != "2a00:11c7:1234:b801::1/128" {
		t.Errorf("ipv6 entry = %q, want %q", got, "2a00:11c7:1234:b801::1/128")
	}
}

func TestAddSkipsDisabledFamily(t *testing.T) {
	var testRedisInstance = CreateTestRedis(t)
	var rc RedisConfiguration
	rc.Host = testRedisInstance.Host
	rc.Port = testRedisInstance.Port
	rc.Token = testRedisInstance.Token
	defer DeleteTestRedis(t, testRedisInstance)

	c.TTL = 24
	c.IPWhiteList = nil
	disabled := false
	c.IpResolution = IpResolution{IPv6: IpFamilyResolution{Enabled: &disabled}}
	defer func() { c.IpResolution = IpResolution{} }()

	if !r.connect(rc) {
		t.Fatal("could not connect to test redis")
	}

	v6 := &User{key: "disabledfamilyuser", ip: "2a00:11c7:1234:b801::2", cidr: "2a00:11c7:1234:b801::2/128"}
	if w.add(v6) {
		t.Error("add() should refuse an address whose family is disabled")
	}
	if got := r.getWhitelist()["disabledfamilyuser"+redisKeySuffixV6]; got != "" {
		t.Errorf("disabled family should not be stored, got %q", got)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -run 'TestAddDualStack|TestAddSkipsDisabledFamily' -v .`
Expected: FAIL — `TestAddDualStack` finds the v6 value under the bare key (the v4 entry was overwritten); `TestAddSkipsDisabledFamily` stores the address anyway

- [ ] **Step 3: Write minimal implementation**

Replace `whitelist.go:37-72` with:

```go
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
```

Also update `delete` (`whitelist.go:74-82`) so it removes both families:

```go
func (w *Whitelist) delete(u *User) bool {
	for _, t := range []IpType{IpV4, IpV6} {
		if !r.deleteIp(redisKey(u.key, t)) {
			return false
		}
	}
	w.updateResources()
	log.Println("whitelist.delete(): whitelisting for '" + u.key + "' removed.")
	return true
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test -run 'TestAdd|TestDelete' -v .`
Expected: PASS — including the pre-existing `TestAdd` and `TestDelete`

- [ ] **Step 5: Commit**

```bash
git add whitelist.go whitelist_test.go
git commit -m "feat: make whitelist add and delete family-aware"
```

---

## Task 7: The /resolve endpoint

**Files:**
- Modify: `http.go`
- Test: `http_test.go` (needs Docker — slow)

Two details that are easy to get wrong:

1. `w.add()` calls `r.addGroups(u.key, u.groups)`. A `User` rebuilt for `/resolve` with `groups: nil` would **overwrite the cached groups with an empty list**, silently dropping the user out of every group-scoped resource. The rebuilt user must carry `r.getGroups(key)`.
2. `callbackHandler` currently stores `name` and `ip_address` in the session but not `key`, and `/resolve` needs the key. Add it.

- [ ] **Step 1: Write the failing test**

Append to `http_test.go`:

```go
func TestResolveHandler(t *testing.T) {
	testRedisInstance := CreateTestRedis(t)
	var rc RedisConfiguration
	rc.Host = testRedisInstance.Host
	rc.Port = testRedisInstance.Port
	rc.Token = testRedisInstance.Token
	if !r.connect(rc) {
		t.Fatal("could not connect to test redis")
	}
	defer DeleteTestRedis(t, testRedisInstance)

	c.TTL = 24
	c.IPWhiteList = nil
	c.Auth.Type = "none"
	c.Auth.Header = "Cf-Access-Authenticated-User-Email"
	c.Auth.IPHeader = "Cf-Connecting-Ip"
	c.IpResolution = IpResolution{
		IPv4: IpFamilyResolution{Header: "Cf-Connecting-Ip", Url: "https://ipv4.icanhazip.com"},
		IPv6: IpFamilyResolution{Header: "Cf-Connecting-Ip", Url: "https://ipv6.icanhazip.com"},
	}
	defer func() {
		c.Auth.Type = ""
		c.Auth.Header = ""
		c.Auth.IPHeader = ""
		c.IpResolution = IpResolution{}
	}()

	newReq := func(body string) *http.Request {
		req := httptest.NewRequest("POST", "/resolve", strings.NewReader(body))
		req.Header.Set("Cf-Access-Authenticated-User-Email", "bob@example.com")
		req.Header.Set("Cf-Connecting-Ip", "203.0.113.7")
		return req
	}

	// a valid ipv6 claim from a request that arrived over ipv4 is accepted
	rr := httptest.NewRecorder()
	if err := resolveHandler(rr, newReq(`{"family":"ipv6","ip":"2a00:11c7:1234:b801::1"}`)); err != nil {
		t.Fatalf("resolveHandler() unexpected error: %v", err)
	}
	if got := r.getWhitelist()["bobexamplecom"+redisKeySuffixV6]; got != "2a00:11c7:1234:b801::1/128" {
		t.Errorf("ipv6 entry = %q, want %q", got, "2a00:11c7:1234:b801::1/128")
	}

	// the claimed family must match the address actually supplied
	rr = httptest.NewRecorder()
	if err := resolveHandler(rr, newReq(`{"family":"ipv6","ip":"198.51.100.9"}`)); err == nil {
		t.Error("expected an error for a family mismatch")
	}

	// unparseable addresses are rejected. This must claim ipv6: the request
	// arrives over ipv4, so an ipv4 claim would be replaced by the observed
	// address before it was ever parsed.
	rr = httptest.NewRecorder()
	if err := resolveHandler(rr, newReq(`{"family":"ipv6","ip":"not-an-ip"}`)); err == nil {
		t.Error("expected an error for an unparseable ip")
	}

	// a claim for the family we observed is replaced by the observed address,
	// which is trustworthy where the claim is not
	rr = httptest.NewRecorder()
	if err := resolveHandler(rr, newReq(`{"family":"ipv4","ip":"8.8.8.8"}`)); err != nil {
		t.Fatalf("resolveHandler() unexpected error: %v", err)
	}
	if got := r.getWhitelist()["bobexamplecom"]; got != "203.0.113.7/32" {
		t.Errorf("ipv4 entry = %q, want the observed %q, not the claimed 8.8.8.8", got, "203.0.113.7/32")
	}

	// an unknown family is rejected
	rr = httptest.NewRecorder()
	if err := resolveHandler(rr, newReq(`{"family":"ipv5","ip":"198.51.100.9"}`)); err == nil {
		t.Error("expected an error for an unknown family")
	}

	// GET is not allowed
	rr = httptest.NewRecorder()
	getReq := httptest.NewRequest("GET", "/resolve", nil)
	if err := resolveHandler(rr, getReq); err == nil {
		t.Error("expected an error for a GET request")
	}
}

func TestResolveHandlerRejectsUnconfiguredFamily(t *testing.T) {
	testRedisInstance := CreateTestRedis(t)
	var rc RedisConfiguration
	rc.Host = testRedisInstance.Host
	rc.Port = testRedisInstance.Port
	rc.Token = testRedisInstance.Token
	if !r.connect(rc) {
		t.Fatal("could not connect to test redis")
	}
	defer DeleteTestRedis(t, testRedisInstance)

	c.TTL = 24
	c.Auth.Type = "none"
	c.Auth.Header = "Cf-Access-Authenticated-User-Email"
	// no url configured for ipv6 => the deployment never opted into
	// client-asserted resolution, so /resolve must not act as an open
	// whitelisting endpoint
	c.IpResolution = IpResolution{IPv4: IpFamilyResolution{Url: "https://ipv4.icanhazip.com"}}
	defer func() {
		c.Auth.Type = ""
		c.Auth.Header = ""
		c.IpResolution = IpResolution{}
	}()

	req := httptest.NewRequest("POST", "/resolve", strings.NewReader(`{"family":"ipv6","ip":"2a00:11c7:1234:b801::9"}`))
	req.Header.Set("Cf-Access-Authenticated-User-Email", "carol@example.com")
	rr := httptest.NewRecorder()

	if err := resolveHandler(rr, req); err == nil {
		t.Error("expected an error for a family with no url configured")
	}
	if got := r.getWhitelist()["carolexamplecom"+redisKeySuffixV6]; got != "" {
		t.Errorf("unconfigured family should not be stored, got %q", got)
	}
}

func TestResolveHandlerRejectsUnauthenticated(t *testing.T) {
	// azure mode with no session token: /resolve must not whitelist anything
	store = sessions.NewFilesystemStore(t.TempDir(), sessionStoreKeyPairs...)
	c.Auth.Type = "azure"
	c.IpResolution = IpResolution{IPv6: IpFamilyResolution{Url: "https://ipv6.icanhazip.com"}}
	defer func() {
		c.Auth.Type = ""
		c.IpResolution = IpResolution{}
	}()

	req := httptest.NewRequest("POST", "/resolve", strings.NewReader(`{"family":"ipv6","ip":"2a00:11c7:1234:b801::3"}`))
	rr := httptest.NewRecorder()

	err := resolveHandler(rr, req)
	if err == nil {
		t.Fatal("expected an error for an unauthenticated caller")
	}
	httpErr, ok := err.(Error)
	if !ok || httpErr.Code != http.StatusUnauthorized {
		t.Errorf("error = %v, want a 401", err)
	}
}
```

Ensure `http_test.go` imports `encoding/json` is **not** needed, but `strings` (already present at line 7) and `net/http` (line 5) are.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -run TestResolveHandler -v .`
Expected: FAIL — `undefined: resolveHandler`

- [ ] **Step 3: Write minimal implementation**

Add `"encoding/json"` and `"io"` to the imports of `http.go`, then append:

```go
// resolveRequest is a client-asserted address for one family, POSTed by the
// probe JS after it fetches the configured echo url.
type resolveRequest struct {
	Family string `json:"family"`
	Ip     string `json:"ip"`
}

// resolveUser rebuilds the authenticated user for a /resolve request without
// setting an address — the caller supplies that from the claim or the
// connection. Groups are read back from the cache rather than left nil: w.add()
// writes u.groups to the cache, so a nil slice here would silently drop the
// user out of every group-scoped resource.
func resolveUser(req *http.Request) (*User, error) {
	switch strings.ToLower(c.Auth.Type) {
	case "none", "disabled":
		var u User
		if u.newFromRequest(req) == nil {
			return nil, Error{Code: http.StatusUnauthorized, Message: "could not determine client identity"}
		}
		return &u, nil
	default:
		session, _ := store.Get(req, "session")
		if session.Values["token"] == nil {
			return nil, Error{Code: http.StatusUnauthorized}
		}
		key, _ := session.Values["key"].(string)
		if key == "" {
			return nil, Error{Code: http.StatusUnauthorized}
		}
		name, _ := session.Values["name"].(string)
		return &User{key: key, name: name, groups: r.getGroups(key)}, nil
	}
}

// resolveHandler accepts a client-asserted address for one family and
// whitelists it. The address is a claim the app cannot verify, so it is only
// accepted for a family that has a url configured — otherwise a deployment that
// never opted into client-asserted resolution would expose an open whitelisting
// endpoint.
func resolveHandler(wr http.ResponseWriter, req *http.Request) error {
	if req.Method != http.MethodPost {
		return Error{Code: http.StatusMethodNotAllowed}
	}

	var body resolveRequest
	if err := json.NewDecoder(io.LimitReader(req.Body, 1024)).Decode(&body); err != nil {
		return Error{Code: http.StatusBadRequest, Message: "invalid json"}
	}

	fr, claimed, ok := c.IpResolution.family(body.Family)
	if !ok {
		return Error{Code: http.StatusBadRequest, Message: "unknown address family"}
	}
	if !fr.isEnabled() {
		return Error{Code: http.StatusBadRequest, Message: "address family is disabled"}
	}
	if fr.Url == "" {
		return Error{Code: http.StatusBadRequest, Message: "client-asserted resolution is not configured for this family"}
	}

	u, err := resolveUser(req)
	if err != nil {
		return err
	}

	ip := body.Ip
	// if this request itself arrived over the claimed family, the address we
	// observed is strictly better than the one being claimed
	if observed := observedIp(req); observed != "" {
		if t, err := ipVersion(observed); err == nil && t == claimed {
			ip = observed
		}
	}

	t, err := ipVersion(ip)
	if err != nil {
		return Error{Code: http.StatusBadRequest, Message: "unparseable ip"}
	}
	if t != claimed {
		return Error{Code: http.StatusBadRequest, Message: "ip does not match the claimed address family"}
	}

	cidr, err := addNetmask(ip)
	if err != nil {
		return Error{Code: http.StatusBadRequest, Message: "unparseable ip"}
	}
	u.ip = ip
	u.cidr = cidr
	u.whitelist()

	wr.WriteHeader(http.StatusNoContent)
	return nil
}
```

Register it in both auth modes. In `initAzure` (`http.go:180-184`) add before the `/` handler:

```go
	http.Handle("/resolve", handle(resolveHandler))
```

and the same line in `initNoAuth` (`http.go:205-208`).

Finally, store the key in the session so the azure path can rebuild the user. In `callbackHandler`, after `session.Values["name"] = &u.name` (`http.go:242`), add:

```go
	session.Values["key"] = u.key
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test -run TestResolveHandler -v .`
Expected: PASS (2 tests)

- [ ] **Step 5: Commit**

```bash
git add http.go http_test.go
git commit -m "feat: add /resolve endpoint for client-asserted addresses"
```

---

## Task 8: Probe JS in the page templates

**Files:**
- Modify: `http.go` (both templates, both index handlers)
- Test: `http_test.go`

`AbortSignal.timeout()` requires Chrome 103+ / Firefox 100+ / Safari 15.4+ (all 2022). `html/template` escapes `{{.Url}}` and `{{.Family}}` correctly for a JS string context and `{{.Timeout}}` for a JS numeric context — do not hand-quote them.

- [ ] **Step 1: Write the failing test**

Append to `http_test.go`:

```go
func TestPendingProbes(t *testing.T) {
	defer func() { c.IpResolution = IpResolution{} }()

	c.IpResolution = IpResolution{
		IPv4: IpFamilyResolution{Url: "https://ipv4.icanhazip.com"},
		IPv6: IpFamilyResolution{Url: "https://ipv6.icanhazip.com"},
	}

	// connected over ipv4 => only the ipv6 probe is pending
	probes := pendingProbes("203.0.113.7")
	if len(probes) != 1 || probes[0].Family != ipVersionV6 {
		t.Errorf("pendingProbes(ipv4 client) = %+v, want one ipv6 probe", probes)
	}
	if probes[0].Timeout != int(defaultUrlTimeout/time.Millisecond) {
		t.Errorf("timeout = %d ms, want %d ms", probes[0].Timeout, int(defaultUrlTimeout/time.Millisecond))
	}

	// connected over ipv6 => only the ipv4 probe is pending
	probes = pendingProbes("2a00:11c7:1234:b801::1")
	if len(probes) != 1 || probes[0].Family != ipVersionV4 {
		t.Errorf("pendingProbes(ipv6 client) = %+v, want one ipv4 probe", probes)
	}

	// a family with no url is never probed
	c.IpResolution = IpResolution{IPv4: IpFamilyResolution{Url: "https://ipv4.icanhazip.com"}}
	if probes := pendingProbes("203.0.113.7"); len(probes) != 0 {
		t.Errorf("pendingProbes() = %+v, want none", probes)
	}

	// a disabled family is never probed
	disabled := false
	c.IpResolution = IpResolution{
		IPv6: IpFamilyResolution{Enabled: &disabled, Url: ""},
		IPv4: IpFamilyResolution{Url: "https://ipv4.icanhazip.com"},
	}
	if probes := pendingProbes("2a00:11c7:1234:b801::1"); len(probes) != 1 {
		t.Errorf("pendingProbes() = %+v, want just the ipv4 probe", probes)
	}
}

func TestNoAuthIndexHandlerRendersProbe(t *testing.T) {
	testRedisInstance := CreateTestRedis(t)
	var rc RedisConfiguration
	rc.Host = testRedisInstance.Host
	rc.Port = testRedisInstance.Port
	rc.Token = testRedisInstance.Token
	if !r.connect(rc) {
		t.Fatal("could not connect to test redis")
	}
	defer DeleteTestRedis(t, testRedisInstance)

	c.TTL = 24
	c.IPWhiteList = nil
	c.Auth.Header = "Cf-Access-Authenticated-User-Email"
	c.Auth.IPHeader = "Cf-Connecting-Ip"
	c.IpResolution = IpResolution{
		IPv4: IpFamilyResolution{Header: "Cf-Connecting-Ip"},
		IPv6: IpFamilyResolution{Header: "Cf-Connecting-Ip", Url: "https://ipv6.icanhazip.com"},
	}
	defer func() {
		c.Auth.Header = ""
		c.Auth.IPHeader = ""
		c.IpResolution = IpResolution{}
	}()

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Cf-Access-Authenticated-User-Email", "dave@example.com")
	req.Header.Set("Cf-Connecting-Ip", "203.0.113.7")
	rr := httptest.NewRecorder()

	if err := noAuthIndexHandler(rr, req); err != nil {
		t.Fatalf("noAuthIndexHandler() unexpected error: %v", err)
	}

	body := rr.Body.String()
	if !strings.Contains(body, "ipv6.icanhazip.com") {
		t.Errorf("body missing the ipv6 probe url:\n%s", body)
	}
	if !strings.Contains(body, "/resolve") {
		t.Errorf("body missing the /resolve POST:\n%s", body)
	}
	// the ipv4 address came from the connection, so it must not be probed for
	if strings.Contains(body, "ipv4.icanhazip.com") {
		t.Errorf("body should not probe for the family already observed:\n%s", body)
	}
}
```

Add `"time"` to the imports of `http_test.go`.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -run 'TestPendingProbes|TestNoAuthIndexHandlerRendersProbe' -v .`
Expected: FAIL — `undefined: pendingProbes`

- [ ] **Step 3: Write minimal implementation**

Add `"time"` to the imports of `http.go`, then append:

```go
// probe is one family's browser-side lookup, rendered into the page.
type probe struct {
	Family  string
	Url     string
	Timeout int // milliseconds, for AbortSignal.timeout()
}

// pendingProbes returns the lookups the page should run: one per enabled family
// that has a url configured and was not already satisfied by the connection.
// The family we observed needs no probe, which also avoids a third-party
// request for an address we already know.
func pendingProbes(observed string) []probe {
	observedType, err := ipVersion(observed)
	if err != nil {
		observedType = Undefined
	}

	var out []probe
	families := []struct {
		name string
		t    IpType
		fr   IpFamilyResolution
	}{
		{ipVersionV4, IpV4, c.IpResolution.IPv4},
		{ipVersionV6, IpV6, c.IpResolution.IPv6},
	}
	for _, f := range families {
		if !f.fr.isEnabled() || f.fr.Url == "" || f.t == observedType {
			continue
		}
		out = append(out, probe{
			Family:  f.name,
			Url:     f.fr.Url,
			Timeout: int(f.fr.timeout() / time.Millisecond),
		})
	}
	return out
}
```

Add this block to **both** templates, immediately before the closing `</body>` in `indexTempl` and `noAuthTempl`:

```html
{{range .Probes}}
    <script>
      (function () {
        fetch({{.Url}}, {referrerPolicy: 'no-referrer', signal: AbortSignal.timeout({{.Timeout}})})
          .then(function (res) { return res.ok ? res.text() : Promise.reject(res.status); })
          .then(function (ip) {
            return fetch('/resolve', {
              method: 'POST',
              headers: {'Content-Type': 'application/json'},
              body: JSON.stringify({family: {{.Family}}, ip: ip.trim()})
            });
          })
          .catch(function (err) { console.log('ip probe failed', err); });
      })();
    </script>
{{end}}
```

Add `Probes []probe` to both template data structs and populate them.

In `noAuthIndexHandler` (`http.go:194-201`):

```go
	var data = struct {
		Name      string
		IPAddress string
		Probes    []probe
	}{
		Name:      u.name,
		IPAddress: u.ip,
		Probes:    pendingProbes(u.ip),
	}
```

In `IndexHandler` (`http.go:271-279`):

```go
	var probes []probe
	if token != nil {
		// before authentication the page only renders a redirect, so there is
		// nothing to probe for yet
		probes = pendingProbes(ipAddress)
	}

	var data = struct {
		Token     *oauth2.Token
		AuthURL   string
		IPAddress string
		Probes    []probe
	}{
		Token:     token,
		AuthURL:   oauthConfig.AuthCodeURL(SessionState(session), oauth2.AccessTypeOnline),
		IPAddress: ipAddress,
		Probes:    probes,
	}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test -run 'TestPendingProbes|TestNoAuthIndexHandler|TestIndexHandler' -v .`
Expected: PASS — including the pre-existing `TestIndexHandler`, `TestIndexHandlerWithToken` and `TestNoAuthIndexHandler`

- [ ] **Step 5: Commit**

```bash
git add http.go http_test.go
git commit -m "feat: render browser-side ip probes into the page templates"
```

---

## Task 9: Documentation

**Files:**
- Modify: `config/config.yaml`, `README.md`
- Modify (local only): `config.dev/config.yaml`

`config.dev/` is gitignored, so its edits never reach the PR — update it anyway so local `docker-compose.dev.yaml` runs exercise the new block.

- [ ] **Step 1: Add the block to the sample config**

In `config/config.yaml`, after the `ttl:` block (line 9), insert:

```yaml
# How the app learns a user's address, per family. This controls what we
# COLLECT; a resource's ip_version controls where we SEND it.
#
# Both families default to enabled. Omitting this block entirely reproduces the
# previous behaviour: whichever family the browser connected over is recorded.
#
# header — a trusted client-IP header set by your proxy. The value is something
#   the app observed, so it cannot be forged by the user.
# url — a family-pinned echo service fetched BY THE BROWSER, letting a
#   dual-stack user register both addresses in one visit. The address arrives as
#   a claim the app cannot verify, so an authenticated user could whitelist an
#   address they do not control. Setting url is the opt-in to that trade-off.
# url_timeout — how long the browser may spend on that fetch (default 5s).
#
# ip_resolution:
#   ipv4:
#     enabled: true
#     header: Cf-Connecting-Ip
#     url: https://ipv4.icanhazip.com
#     url_timeout: 5s
#   ipv6:
#     enabled: true
#     header: Cf-Connecting-Ip
#     url: https://ipv6.icanhazip.com
#     url_timeout: 5s
```

- [ ] **Step 2: Fix the now-false comment**

`config/config.yaml:79-80` currently reads:

```
  # A user has one IP — whichever family their browser reached the app over — so
  # an IPv4 user never appears in an ipv6 resource, and vice versa.
```

Replace those two lines with:

```
  # A user has one address per family. Without ip_resolution urls configured
  # they only have whichever family their browser reached the app over, so an
  # IPv4-only user never appears in an ipv6 resource.
```

- [ ] **Step 3: Update the README**

In `README.md`, replace lines 130-134 (the paragraph beginning "The client IP is read from the `ip_header` request header") with:

```markdown
The client IP is read from the header named by `ip_resolution` (see below).
`auth.ip_header` is **deprecated** but still honoured as a fallback for any
family that names no header of its own. **Your proxy MUST set this header to the
real client IP and strip any client-supplied value** — otherwise an
authenticated user could spoof it to whitelist an arbitrary address. For Azure
Front Door use `X-Azure-Clientip`.
```

Then add a new section immediately after the "Disabling auth" section (after line 139):

```markdown
### Dual-stack (`ip_resolution`)

A request only reveals the address family the browser connected over, so a
dual-stack user is normally whitelisted for one family only — in practice IPv6,
which browsers prefer. `ip_resolution` describes how to learn an address for
each family:

```yaml
ip_resolution:
  ipv4:
    enabled: true                     # default true
    header: Cf-Connecting-Ip          # trusted client-IP header
    url: https://ipv4.icanhazip.com   # optional, see below
    url_timeout: 5s                   # optional, default 5s
  ipv6:
    enabled: true
    header: Cf-Connecting-Ip
    url: https://ipv6.icanhazip.com
    url_timeout: 5s
```

Omitting the block entirely reproduces the previous behaviour: both families are
enabled, and whichever family the browser connected over is recorded. Each
family gets its own Redis entry and its own TTL, so one expiring does not
disturb the other.

This controls what the app **collects**. A resource's `ip_version` controls
where it is **sent** — the two are independent, and an IPv6 address still only
reaches resources configured for `ipv6` or `both`.

**`header` is trusted; `url` is not.** A header value is observed by the app or
its proxy and cannot be forged. A `url` is a family-pinned echo service fetched
**by the browser**, whose answer is POSTed back to `/resolve` — so the address
arrives as a *claim*. An authenticated user can fabricate it and whitelist an
address they do not control. Setting `url` is the opt-in to that trade-off; the
app logs which families use it at startup. Where the app can see the address
itself, the observed value always wins over the claim.

The echo service must send `Access-Control-Allow-Origin` or the browser will
refuse to read the response; `icanhazip.com` does. Note that it will learn your
hostname (via the `Origin` header) and the user's IP. No cookies or auth headers
are sent to it.
```

- [ ] **Step 4: Mirror into the local dev config**

Add the same `ip_resolution` block, uncommented and pointing at icanhazip, to `config.dev/config.yaml`.

- [ ] **Step 5: Run the full suite**

Run: `go test ./...`
Expected: PASS (slow — the Redis-backed tests start Docker containers)

- [ ] **Step 6: Commit**

```bash
git add config/config.yaml README.md
git commit -m "docs: document ip_resolution and deprecate auth.ip_header"
```

---

## Task 10: Full verification

- [ ] **Step 1: Vet and build**

Run: `go vet ./...`
Expected: no output

- [ ] **Step 2: Full test suite**

Run: `go test ./...`
Expected: `ok` — no failures

- [ ] **Step 3: Confirm the Helm chart still renders**

The chart passes `.Values.config` through verbatim, so no template change is needed — confirm nothing broke:

Run: `helm lint helm/ip-whitelister`
Expected: `1 chart(s) linted, 0 chart(s) failed`

- [ ] **Step 4: Push the branch**

```bash
git push -u origin feat/dual-stack-ip-resolution
```

Do **not** open a PR without asking — `main` is branch-protected and requires a review.
