# Disable auth (`auth.type: none`) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a no-auth mode (`auth.type: none`) so the app can run behind an external SSO reverse proxy (e.g. Cloudflare Access) instead of doing its own AzureAD OAuth login.

**Architecture:** Additive change on the existing `switch auth.type` seam. A new `none`/`disabled` case registers a minimal handler that whitelists the caller's IP directly from request headers — no OAuth redirect, callback, or Graph API call. Identity comes from a configurable trusted header (default `Cf-Access-Authenticated-User-Email`), falling back to the IP. No-auth users get empty `groups`, so the existing `hasGroup` logic skips group-scoped resources for free.

**Tech Stack:** Go (flat `package main`), `net/http` + `html/template`, `gorilla/sessions` (OAuth path only), `redigo` for Redis. Tests use `net/http/httptest`; the no-auth unit tests reuse the existing `stubRedis()` fake and need no Docker.

Spec: `docs/superpowers/specs/2026-07-02-disable-auth-none-provider-design.md`

---

## File Structure

- `http.go` — add `Header` field to `Authentication`; add `none`/`disabled` case to `init`; add `initNoAuth`, `noAuthIndexHandler`, and a confirmation template `noAuthTempl`.
- `user.go` — extract shared request-derived logic into `finishUser`; add `newFromRequest`.
- `config.go` — add `applyAuthDefaults` and call it in `load`.
- `config_test.go` / `user_test.go` / `http_test.go` — new unit tests.
- `README.md` — document `auth.type: none`.

All new tests use `-run <TestName> .` so they never spin the Docker-backed Redis suite.

---

### Task 1: `Authentication.Header` field + config default

**Files:**
- Modify: `http.go` (the `Authentication` struct, ~L114-119)
- Modify: `config.go` (add `applyAuthDefaults`, call in `load`)
- Test: `config_test.go`

- [ ] **Step 1: Add the `Header` field to the struct**

In `http.go`, change the `Authentication` struct to add the `Header` field:

```go
type Authentication struct {
	Type         string `yaml:"type"`
	Header       string `yaml:"header"`
	TenantId     string `yaml:"tenant_id"`
	ClientId     string `yaml:"client_id"`
	ClientSecret string `yaml:"client_secret"`
}
```

- [ ] **Step 2: Write the failing test for the default helper**

Add to `config_test.go`:

```go
func TestApplyAuthDefaults(t *testing.T) {
	cases := []struct {
		name   string
		typ    string
		header string
		want   string
	}{
		{"none defaults the cloudflare header", "none", "", "Cf-Access-Authenticated-User-Email"},
		{"disabled alias defaults too", "disabled", "", "Cf-Access-Authenticated-User-Email"},
		{"case-insensitive type", "None", "", "Cf-Access-Authenticated-User-Email"},
		{"explicit header is kept", "none", "X-My-Header", "X-My-Header"},
		{"azure is unaffected", "azure", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := applyAuthDefaults(Authentication{Type: tc.typ, Header: tc.header})
			if got.Header != tc.want {
				t.Errorf("header = %q, want %q", got.Header, tc.want)
			}
		})
	}
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `go test -run TestApplyAuthDefaults -v .`
Expected: FAIL — `undefined: applyAuthDefaults`.

- [ ] **Step 4: Implement `applyAuthDefaults` and wire it into `load`**

In `config.go`, add the function (near `applyDefaults`, ~L56):

```go
// applyAuthDefaults fills in auth defaults. When auth is disabled
// (type none/disabled) and no identity header is configured, it defaults to the
// header set by Cloudflare Access.
func applyAuthDefaults(a Authentication) Authentication {
	switch strings.ToLower(a.Type) {
	case "none", "disabled":
		if a.Header == "" {
			a.Header = "Cf-Access-Authenticated-User-Email"
		}
	}
	return a
}
```

Then in `Configuration.load`, right after the `yaml.Unmarshal` block that populates `c` (immediately after the `if c.TTL == 0 { ... }` block, ~L97), add:

```go
	c.Auth = applyAuthDefaults(c.Auth)
```

(`strings` is already imported in `config.go`.)

- [ ] **Step 5: Run test to verify it passes**

Run: `go test -run TestApplyAuthDefaults -v .`
Expected: PASS.

- [ ] **Step 6: Confirm the build and existing config tests still pass**

Run: `go build . && go test -run 'TestLoad|TestUnifiConfigLoad|TestApplyDefaults' -v .`
Expected: PASS (the sample config stays `type: azure`, so its `Header` stays empty).

- [ ] **Step 7: Commit**

```bash
git add http.go config.go config_test.go
git commit -m "feat: add auth.header field + default for auth.type none"
```

---

### Task 2: Extract shared `finishUser` helper (refactor under existing tests)

**Files:**
- Modify: `user.go` (`User.new`, ~L89-118)
- Guarded by: existing `user_test.go::TestUserNew`

This task introduces no new behaviour — it moves the IP/cidr/key logic out of `new` into a reusable helper. `TestUserNew` is the safety net.

- [ ] **Step 1: Add the `finishUser` helper**

In `user.go`, add this method (e.g. just below `new`):

```go
// finishUser fills in the request-derived fields shared by both the OAuth and
// no-auth constructors: the client IP (with a loopback override for local
// testing), its cidr, and the whitelist key derived from identity. When
// identity is empty the key falls back to the client IP.
func (u *User) finishUser(identity string, req *http.Request) error {
	// get ip
	u.ip = req.Header.Get("X-Azure-Clientip")
	if u.ip == "" {
		var err error
		u.ip, _, err = net.SplitHostPort(req.RemoteAddr)
		if err != nil {
			log.Printf("user.finishUser(): %q is not IP:port\n", req.RemoteAddr)
		}
	}

	// annoying when testing locally, make up an ip :)
	if u.ip == "::1" {
		u.ip = "80.18.81.18"
	}

	cidr, err := addNetmask(u.ip)
	if err != nil {
		return err
	}
	u.cidr = cidr

	// Create our 'key' by removing spaces, lower-casing and stripping special
	// characters. Fall back to the IP when there is no identity (no-auth mode).
	if identity == "" {
		identity = u.ip
	}
	reg, err := regexp.Compile("[^a-zA-Z0-9]+")
	if err != nil {
		return err
	}
	u.key = strings.ToLower(reg.ReplaceAllString(identity, ""))

	return nil
}
```

- [ ] **Step 2: Replace the inline block in `new` with a call to `finishUser`**

In `user.go`, replace the block from the `// Create our 'key' ...` comment (~L89) down to and including the `u.cidr, err = addNetmask(...)` block (~L114) with:

```go
	// derive key, client IP, and cidr (shared with the no-auth path)
	if err := u.finishUser(u.name+u.employeeId, req); err != nil {
		log.Fatal("user.new(): ", err)
	}
```

Leave the final `log.Println("user.new(): authentication successful ...")` line and `return u` exactly as they are.

- [ ] **Step 3: Run the existing user tests to verify no regression**

Run: `go test -run 'TestUserNew|TestUserNewErrorStatus' -v .`
Expected: PASS — key/ip/cidr/groups unchanged for all three `TestUserNew` cases.

- [ ] **Step 4: Verify the whole package still builds and vets cleanly**

Run: `go build . && go vet .`
Expected: no output (success).

- [ ] **Step 5: Commit**

```bash
git add user.go
git commit -m "refactor: extract shared finishUser helper from User.new"
```

---

### Task 3: `User.newFromRequest`

**Files:**
- Modify: `user.go` (add `newFromRequest`)
- Test: `user_test.go`

- [ ] **Step 1: Write the failing test**

Add to `user_test.go`:

```go
func TestUserNewFromRequest(t *testing.T) {
	c.Debug = false
	c.Auth.Header = "Cf-Access-Authenticated-User-Email"
	defer func() { c.Auth.Header = "" }()

	tests := []struct {
		name       string
		header     string // Cf-Access-Authenticated-User-Email value ("" = not set)
		clientIP   string // X-Azure-Clientip value ("" = not set)
		remoteAddr string
		wantName   string
		wantKey    string
		wantIP     string
		wantCidr   string
	}{
		{
			name:       "identity from trusted header",
			header:     "alice@example.com",
			clientIP:   "1.2.3.4",
			remoteAddr: "10.0.0.1:5555",
			wantName:   "alice@example.com",
			wantKey:    "aliceexamplecom",
			wantIP:     "1.2.3.4",
			wantCidr:   "1.2.3.4/32",
		},
		{
			name:       "no header falls back to keying on IP",
			header:     "",
			clientIP:   "",
			remoteAddr: "8.8.8.8:1234",
			wantName:   "",
			wantKey:    "8888",
			wantIP:     "8.8.8.8",
			wantCidr:   "8.8.8.8/32",
		},
		{
			name:       "loopback is rewritten for local testing",
			header:     "",
			clientIP:   "::1",
			remoteAddr: "[::1]:8080",
			wantName:   "",
			wantKey:    "80188118",
			wantIP:     "80.18.81.18",
			wantCidr:   "80.18.81.18/32",
		},
	}

	for _, f := range tests {
		t.Run(f.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			req.RemoteAddr = f.remoteAddr
			if f.clientIP != "" {
				req.Header.Set("X-Azure-Clientip", f.clientIP)
			}
			if f.header != "" {
				req.Header.Set("Cf-Access-Authenticated-User-Email", f.header)
			}

			var u User
			if got := u.newFromRequest(req); got == nil {
				t.Fatalf("newFromRequest() returned nil, want a populated user")
			}
			if u.name != f.wantName {
				t.Errorf("name: got %q, want %q", u.name, f.wantName)
			}
			if u.key != f.wantKey {
				t.Errorf("key: got %q, want %q", u.key, f.wantKey)
			}
			if u.ip != f.wantIP {
				t.Errorf("ip: got %q, want %q", u.ip, f.wantIP)
			}
			if u.cidr != f.wantCidr {
				t.Errorf("cidr: got %q, want %q", u.cidr, f.wantCidr)
			}
			if u.groups != nil {
				t.Errorf("groups: got %v, want nil", u.groups)
			}
		})
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -run TestUserNewFromRequest -v .`
Expected: FAIL — `u.newFromRequest undefined`.

- [ ] **Step 3: Implement `newFromRequest`**

In `user.go`, add (below `finishUser`):

```go
// newFromRequest builds a User without OAuth, for auth.type: none. Identity
// comes from the configured trusted header (set by an upstream SSO proxy such
// as Cloudflare Access). Groups are unavailable, so u.groups stays nil and the
// existing hasGroup logic skips group-scoped resources.
func (u *User) newFromRequest(req *http.Request) *User {
	var identity string
	if c.Auth.Header != "" {
		identity = req.Header.Get(c.Auth.Header)
	}
	if identity != "" {
		u.name = identity
	}

	if err := u.finishUser(identity, req); err != nil {
		log.Printf("user.newFromRequest(): %v", err)
		return nil
	}

	log.Println("user.newFromRequest(): request accepted - " + u.name + " - " + u.ip)
	return u
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test -run TestUserNewFromRequest -v .`
Expected: PASS (all three sub-cases).

- [ ] **Step 5: Add a `hasGroup` case proving empty-group users are skipped**

No-auth users have `groups == nil`, so group-scoped resources must reject them.
`TestHasGroup` (`functions_test.go`) has a non-matching case but no empty-user
case. Add this line to the `groups` table in `functions_test.go` (after the
existing `{[]string{"group1"}, []string{"group9", "group10", "group11"}, false},`
line):

```go
		// a no-auth user has no groups -> group-scoped resources are skipped
		{[]string{"group1"}, nil, false},
```

- [ ] **Step 6: Run the group test to verify it passes**

Run: `go test -run TestHasGroup -v .`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add user.go user_test.go functions_test.go
git commit -m "feat: add User.newFromRequest for no-auth mode"
```

---

### Task 4: No-auth handler, template, and init case

**Files:**
- Modify: `http.go` (add `noAuthTempl`, `noAuthIndexHandler`, `initNoAuth`, switch case)
- Test: `http_test.go`

- [ ] **Step 1: Write the failing handler test**

This test needs a real Redis: the handler calls `u.whitelist()` → `w.add()` →
`r.getWhitelist()`, which `log.Fatal`s on any Redis error (so `stubRedis()`'s
error-returning fake conn would kill the process). Mirror the `CreateTestRedis`
pattern from `TestUserWhitelist` in `user_test.go`. Add to `http_test.go`:

```go
func TestNoAuthIndexHandler(t *testing.T) {
	testRedisInstance := CreateTestRedis(t)
	var rc RedisConfiguration
	rc.Host = testRedisInstance.Host
	rc.Port = testRedisInstance.Port
	rc.Token = testRedisInstance.Token
	if !r.connect(rc) {
		t.Fatal("could not connect to test redis")
	}
	defer DeleteTestRedis(t, testRedisInstance)

	// config is never loaded in tests; give redis keys a real TTL and set the
	// trusted header the no-auth path reads.
	c.TTL = 24
	c.Auth.Header = "Cf-Access-Authenticated-User-Email"
	defer func() { c.Auth.Header = "" }()

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Cf-Access-Authenticated-User-Email", "alice@example.com")
	req.Header.Set("X-Azure-Clientip", "203.0.113.7")
	rr := httptest.NewRecorder()

	if err := noAuthIndexHandler(rr, req); err != nil {
		t.Fatalf("noAuthIndexHandler() unexpected error: %v", err)
	}

	// the confirmation page shows the identity + whitelisted IP
	body := rr.Body.String()
	if !strings.Contains(body, "203.0.113.7") {
		t.Errorf("body missing whitelisted IP:\n%s", body)
	}
	if !strings.Contains(body, "alice@example.com") {
		t.Errorf("body missing identity:\n%s", body)
	}
	if !strings.Contains(body, "has been whitelisted") {
		t.Errorf("body missing confirmation text:\n%s", body)
	}
	// no-auth mode must never render the OAuth redirect branch
	if strings.Contains(body, "Whitelisting your IP") {
		t.Errorf("body unexpectedly rendered the OAuth redirect branch:\n%s", body)
	}

	// and the IP was actually stored, keyed on the header-derived identity
	if got := r.getWhitelist()["aliceexamplecom"]; got != "203.0.113.7/32" {
		t.Errorf("redis whitelist entry = %q, want %q", got, "203.0.113.7/32")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -run TestNoAuthIndexHandler -v .`
Expected: FAIL — `undefined: noAuthIndexHandler` (compile error).

- [ ] **Step 3: Add the confirmation template**

In `http.go`, add near the existing `indexTempl` var:

```go
var noAuthTempl = template.Must(template.New("").Parse(`<!DOCTYPE html>
<html>
  <head>
    <title>Dynamic IP Whitelist</title>

    <link href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-BVYiiSIFeK1dGmJRAkycuHAHRg32OmUcww7on3RYdg4Va+PmSTsz/K68vbdEjh4u" crossorigin="anonymous">
  </head>
  <body class="container-fluid">
    <div class="row">
      <div class="col-xs-4 col-xs-offset-4">
        <h1>Dynamic IP Whitelist</h1>
        Welcome{{with .Name}} {{.}}{{end}}, your IP ({{.IPAddress}}) has been whitelisted.
        <br>
        <i>Note: It can take a few minutes for your whitelisting to become active. Please note that IPv6 cannot be whitelisted on all resources.</i>
      </div>
    </div>
  </body>
</html>
`))
```

- [ ] **Step 4: Add the handler and init function**

In `http.go`, add:

```go
func noAuthIndexHandler(w http.ResponseWriter, req *http.Request) error {
	var u User
	if u.newFromRequest(req) == nil {
		return Error{Code: http.StatusBadRequest, Message: "could not determine client IP"}
	}
	u.whitelist()

	var data = struct {
		Name      string
		IPAddress string
	}{
		Name:      u.name,
		IPAddress: u.ip,
	}
	return noAuthTempl.Execute(w, &data)
}

func (a *Authentication) initNoAuth() {
	http.Handle("/live", handle(livenessHandler))
	http.Handle("/ready", handle(readinessHandler))
	http.Handle("/", handle(noAuthIndexHandler))
	log.Fatal(http.ListenAndServe(":8090", nil))
}
```

- [ ] **Step 5: Wire the switch case in `Authentication.init`**

In `http.go`, change the `switch` in `init` (~L129) to:

```go
	switch strings.ToLower(a.Type) {
	case "azure":
		a.initAzure()
	case "none", "disabled":
		a.initNoAuth()
	default:
		log.Fatalln("http.init(): unsupported authentication type '" + a.Type + "'")
	}
```

- [ ] **Step 6: Run test to verify it passes**

Run: `go test -run TestNoAuthIndexHandler -v .`
Expected: PASS (this test starts a throwaway Redis container via `dockertest`, so it takes longer than the pure-unit tests — Docker must be running).

- [ ] **Step 7: Confirm the existing OAuth handler tests still pass**

Run: `go test -run 'TestIndexHandler|TestIndexHandlerWithToken|TestServeHTTP|TestLivenessHandler|TestReadinessHandler' -v .`
Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add http.go http_test.go
git commit -m "feat: add no-auth index handler + auth.type none init path"
```

---

### Task 5: Document `auth.type: none` in the README

**Files:**
- Modify: `README.md` (the `auth` config-table row, ~L65; new subsection before `### UniFi`, ~L89)

- [ ] **Step 1: Update the `auth` row in the config table**

In `README.md`, replace the existing `auth` table row (~L65):

```
| `auth`         | AzureAD tenant/client credentials (`type: azure`).                 |
```

with:

```
| `auth`         | Authentication mode: `type: azure` (AzureAD OAuth) or `type: none` (disable in-app auth — see [Disabling auth](#disabling-auth-reverse-proxy-sso)). |
```

- [ ] **Step 2: Add the "Disabling auth" subsection**

In `README.md`, insert this new subsection immediately before `### UniFi` (~L89):

````markdown
### Disabling auth (reverse-proxy SSO)

If you run ip-whitelister behind an SSO reverse proxy (e.g. Cloudflare Access,
Authelia, oauth2-proxy) you can disable the built-in AzureAD login and let the
proxy handle authentication:

```yaml
auth:
  type: none   # alias: disabled
  # header: Cf-Access-Authenticated-User-Email   # trusted identity header (default shown)
```

In this mode any request to `/` immediately whitelists the caller's IP and shows
a confirmation page — there is no OAuth redirect or callback. The whitelist
entry is keyed on the identity the proxy supplies in the configured `header`
(default `Cf-Access-Authenticated-User-Email`); if that header is absent the
entry is keyed on the client IP instead.

Because AzureAD group membership is unavailable without OAuth, **group-scoped
resources are skipped** in this mode — only resources without a `group:` filter
are whitelisted. `tenant_id`, `client_id` and `client_secret` are ignored and
can be omitted.
````

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "docs: document auth.type none (reverse-proxy SSO)"
```

---

### Task 6: Full-suite verification

**Files:** none (verification only).

- [ ] **Step 1: Run the complete test suite**

Run: `go test ./...`
Expected: PASS (this includes the Docker-backed Redis suite, ~60s).

- [ ] **Step 2: Run the race detector**

Run: `go test -race ./...`
Expected: PASS, no race warnings.

- [ ] **Step 3: Vet and build**

Run: `go vet ./... && go build ./...`
Expected: no output (success).

- [ ] **Step 4: Manual smoke check (optional)**

Confirm the new mode is reachable by grepping the wired case:

Run: `grep -n '"none", "disabled"' http.go`
Expected: one match in the `init` switch.

---

## Notes for the implementer

- The package is a flat `package main`; there are no subpackages. Run tests from the repo root.
- Do NOT use `stubRedis()` for the handler test. `getWhitelist()` calls `log.Fatal` on any Redis error, and `stubRedis()`'s fake conn returns errors — so it would exit the test process. The handler exercises the real whitelist path, so it uses `CreateTestRedis` (Docker), mirroring `TestUserWhitelist`. `stubRedis()` only works for the UniFi tests because they set `w.List` manually and never call `getWhitelist`.
- Global test state: `c`, `r`, `u`, `w`, `a` are package-level singletons shared across tests. Always restore `c.Auth.Header` with a `defer` (as the tests above do) so you don't leak state into other tests.
- Do not touch the sample `config/config.yaml` — it stays on `type: azure`; no-auth is README-documented only (per the spec).
