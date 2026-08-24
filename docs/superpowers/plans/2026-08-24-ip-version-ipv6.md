# `ip_version` / IPv6 Support Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a provider-agnostic `ip_version` field (`ipv4` default / `ipv6` / `both`) to every resource in `config.yaml`, so a user's IPv6 address can be synced into a UniFi `ipv6-address-group` Network List.

**Architecture:** One pure helper, `matchesIpVersion(want, ip)`, replaces the hardcoded `isValidIpOrNetV4` guard at all twelve existing whitelist call sites plus one missing guard in Front Door. Each resource struct carries an `IPVersion` string that `config.load()` resolves and validates. Separately, `getIpList` — which silently truncates IPv6 masks to four bytes — is replaced by a non-enumerating, family-agnostic `ipRange`.

**Tech Stack:** Go (flat `package main` at repo root), `net` stdlib, `gopkg.in/yaml.v2`, standard `testing`.

**Spec:** `docs/superpowers/specs/2026-08-24-ip-version-ipv6-design.md`

**Branch:** `feat/ip-version-ipv6` (already created; the spec commit is on it)

---

## File Structure

No new files. All changes land in the existing flat package:

| File | Responsibility after this change |
|---|---|
| `functions.go` | Gains `matchesIpVersion` + `ipRange`; loses `isValidIpOrNetV4` + `getIpList` |
| `config.go` | Gains `ip_version` on `ResourceConfiguration`, plus `resolveIpVersion` / `mustResolveIpVersion`; each of the 7 `case` arms plumbs `IPVersion` onto its resource struct |
| `unifi.go` | `UnifiNetworkList.IPVersion`; `buildMembers` guards switch to `matchesIpVersion`; `unifiMember` becomes family-aware |
| `azure.go` | `IPVersion` on all 6 structs; 10 guards swapped; Front Door's missing guard added; 6 `getIpList` calls become `ipRange` |
| `functions_test.go`, `config_test.go`, `unifi_test.go` | Coverage for the above |
| `config/config.yaml`, `config.dev/config.yaml`, `README.md` | Document `ip_version` |

**Ordering rule:** every task must leave the tree compiling and green. The two old helpers are therefore kept until Task 8, after every caller has moved off them.

---

## Task 1: `matchesIpVersion` helper

**Files:**
- Modify: `functions.go` (add after `isValidIpOrNetV4`, ~line 88)
- Test: `functions_test.go`

- [ ] **Step 1: Write the failing test**

Add to `functions_test.go`:

```go
func TestMatchesIpVersion(t *testing.T) {
	tests := []struct {
		want    string
		ip      string
		success bool
	}{
		// empty want behaves as ipv4, preserving the old isValidIpOrNetV4 default
		{"", "1.2.3.4", true},
		{"", "1.2.3.0/24", true},
		{"", "2a00:11c7:1234:b801::1", false},

		{"ipv4", "1.2.3.4", true},
		{"ipv4", "1.2.3.4/32", true},
		{"ipv4", "1.2.3.0/24", true},
		{"ipv4", "2a00:11c7:1234:b801::1", false},
		{"ipv4", "2a00:11c7:1234:b801::/64", false},

		{"ipv6", "2a00:11c7:1234:b801::1", true},
		{"ipv6", "2a00:11c7:1234:b801::1/128", true},
		{"ipv6", "2a00:11c7:1234:b801::/64", true},
		{"ipv6", "1.2.3.4", false},
		{"ipv6", "1.2.3.0/24", false},

		{"both", "1.2.3.4", true},
		{"both", "2a00:11c7:1234:b801::1", true},
		{"both", "1.2.3.0/24", true},
		{"both", "2a00:11c7:1234:b801::/64", true},

		// unparseable input is never a match, whatever the family
		{"ipv4", "not-an-ip", false},
		{"ipv6", "not-an-ip", false},
		{"both", "not-an-ip", false},
		{"", "not-an-ip", false},
	}

	for _, f := range tests {
		success := matchesIpVersion(f.want, f.ip)
		if success != f.success {
			t.Errorf("matchesIpVersion(%q, %q) = %v, want %v", f.want, f.ip, success, f.success)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test . -run TestMatchesIpVersion -v`
Expected: FAIL — `undefined: matchesIpVersion`

- [ ] **Step 3: Write minimal implementation**

Add the constants next to the existing `IpType` block in `functions.go` (after the `const (...)` that defines `Undefined`/`IpV4`/`IpV6`):

```go
// Supported values for a resource's ip_version field.
const (
	ipVersionV4   = "ipv4"
	ipVersionV6   = "ipv6"
	ipVersionBoth = "both"
)
```

Add the helper immediately after `isValidIpOrNetV4` in `functions.go`:

```go
// matchesIpVersion reports whether ip is a parseable address (with or without a
// netmask) of the address family selected by a resource's ip_version. An empty
// want means ipv4, which is the default for every resource type except Front
// Door. Unparseable input never matches, so this fully replaces the
// isValidIpOrNetV4 guard it supersedes.
func matchesIpVersion(want, ip string) bool {
	t, err := ipVersion(ip)
	if err != nil {
		return false
	}
	switch want {
	case ipVersionV6:
		return t == IpV6
	case ipVersionBoth:
		return true
	default:
		return t == IpV4
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test . -run 'TestMatchesIpVersion|TestIsValidIpOrNetV4|TestIpVersion' -v`
Expected: PASS (all three)

- [ ] **Step 5: Commit**

```bash
git add functions.go functions_test.go
git commit -m "feat: add matchesIpVersion address-family filter"
```

---

## Task 2: `ipRange` replacing `getIpList`

`getIpList` computes a CIDR's bounds via `binary.BigEndian.Uint32`, which reads only the first four bytes of a sixteen-byte IPv6 mask and address — no panic, just wrong answers. It also materialises every address in the range, which is impossible for IPv6 and wasteful for large IPv4 blocks. Nothing consumes its third return value: all six `azure.go` call sites are `first, last, _ :=`, and only `functions_test.go` reads `all`.

**Files:**
- Modify: `functions.go` (add after `getIpList`, ~line 66)
- Test: `functions_test.go`

- [ ] **Step 1: Write the failing test**

Add to `functions_test.go`:

```go
func TestIpRange(t *testing.T) {
	tests := []struct {
		cidr         string
		successFirst string
		successLast  string
	}{
		// IPv4 — same expectations the old getIpList test asserted
		{"10.0.0.0/31", "10.0.0.0", "10.0.0.1"},
		{"200.0.0.0/30", "200.0.0.0", "200.0.0.3"},
		{"10.0.0.1", "10.0.0.1", "10.0.0.1"},
		{"1.2.3.4/32", "1.2.3.4", "1.2.3.4"},
		{"10.0.0.0/24", "10.0.0.0", "10.0.0.255"},

		// IPv6 — the family the old implementation silently corrupted
		{"2a00:11c7:1234:b801::/64", "2a00:11c7:1234:b801::", "2a00:11c7:1234:b801:ffff:ffff:ffff:ffff"},
		{"2a00:11c7:1234:b801::1/128", "2a00:11c7:1234:b801::1", "2a00:11c7:1234:b801::1"},
		{"2a00:11c7:1234:b801::1", "2a00:11c7:1234:b801::1", "2a00:11c7:1234:b801::1"},
	}

	for _, f := range tests {
		first, last, err := ipRange(f.cidr)
		if err != nil {
			t.Errorf("ipRange(%q) returned unexpected error %v", f.cidr, err)
			continue
		}
		if first != f.successFirst {
			t.Errorf("ipRange(%q) first = %v, want %v", f.cidr, first, f.successFirst)
		}
		if last != f.successLast {
			t.Errorf("ipRange(%q) last = %v, want %v", f.cidr, last, f.successLast)
		}
	}
}

// TestIpRangeInvalid asserts a bad value returns an error rather than calling
// log.Fatal and taking the process down mid-reconcile, as getIpList did.
func TestIpRangeInvalid(t *testing.T) {
	for _, cidr := range []string{"not-an-ip", "10.0.0.0/99", "10.0.0.0/", ""} {
		if _, _, err := ipRange(cidr); err == nil {
			t.Errorf("ipRange(%q) should return an error", cidr)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test . -run TestIpRange -v`
Expected: FAIL — `undefined: ipRange`

- [ ] **Step 3: Write minimal implementation**

Add to `functions.go`, immediately after `getIpList`:

```go
// ipRange returns the first and last address of cidr. Bounds are computed with
// byte-wise mask arithmetic, so it works for IPv4 and IPv6 alike — unlike
// getIpList, which reads a 16-byte IPv6 mask as a uint32 and returns nonsense.
// It deliberately does not enumerate the range: an IPv6 /64 holds 1.8e19
// addresses, and no caller needs the full list. A bare address is its own first
// and last. An unparseable value returns an error rather than exiting.
func ipRange(cidr string) (first string, last string, err error) {
	if !strings.Contains(cidr, "/") {
		if _, err := ipVersion(cidr); err != nil {
			return "", "", err
		}
		return cidr, cidr, nil
	}

	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return "", "", err
	}

	firstIP := make(net.IP, len(network.IP))
	lastIP := make(net.IP, len(network.IP))
	for i := range network.IP {
		firstIP[i] = network.IP[i] & network.Mask[i]
		lastIP[i] = network.IP[i] | ^network.Mask[i]
	}
	return firstIP.String(), lastIP.String(), nil
}
```

`net.ParseCIDR` returns `IP` and `Mask` of matching length (4 bytes for IPv4, 16 for IPv6), so the loop is safe for both families.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test . -run 'TestIpRange|TestGetIpList' -v`
Expected: PASS (both — `getIpList` is still present and untouched)

- [ ] **Step 5: Commit**

```bash
git add functions.go functions_test.go
git commit -m "feat: add family-agnostic ipRange without enumeration"
```

---

## Task 3: `ip_version` config field and resolution

**Files:**
- Modify: `config.go:41-50` (`ResourceConfiguration`), plus new helpers
- Test: `config_test.go`

- [ ] **Step 1: Write the failing test**

Add to `config_test.go`:

```go
func TestResolveIpVersion(t *testing.T) {
	tests := []struct {
		in      string
		def     string
		want    string
		wantOk  bool
	}{
		// unset falls back to the per-resource-type default
		{"", ipVersionV4, ipVersionV4, true},
		{"", ipVersionBoth, ipVersionBoth, true},

		// explicit values win over the default, and are normalised
		{"ipv4", ipVersionBoth, ipVersionV4, true},
		{"ipv6", ipVersionV4, ipVersionV6, true},
		{"both", ipVersionV4, ipVersionBoth, true},
		{"IPv6", ipVersionV4, ipVersionV6, true},
		{"  Both  ", ipVersionV4, ipVersionBoth, true},

		// anything else is rejected
		{"ipv5", ipVersionV4, "", false},
		{"v6", ipVersionV4, "", false},
		{"yes", ipVersionV4, "", false},
	}

	for _, f := range tests {
		got, ok := resolveIpVersion(f.in, f.def)
		if ok != f.wantOk {
			t.Errorf("resolveIpVersion(%q, %q) ok = %v, want %v", f.in, f.def, ok, f.wantOk)
			continue
		}
		if got != f.want {
			t.Errorf("resolveIpVersion(%q, %q) = %q, want %q", f.in, f.def, got, f.want)
		}
	}
}

func TestLoadResourceConfigsIpVersion(t *testing.T) {
	dir := t.TempDir()
	yaml := "" +
		"resources:\n" +
		"  - cloud: unifi\n" +
		"    type: networklist\n" +
		"    name: list-v6\n" +
		"    ip_version: ipv6\n" +
		"  - cloud: unifi\n" +
		"    type: networklist\n" +
		"    name: list-default\n"
	if err := os.WriteFile(filepath.Join(dir, "app.yaml"), []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}

	resources, err := loadResourceConfigs(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resources) != 2 {
		t.Fatalf("expected 2 resources, got %d", len(resources))
	}
	if resources[0].IPVersion != "ipv6" {
		t.Errorf("ip_version did not unmarshal, got %q want %q", resources[0].IPVersion, "ipv6")
	}
	if resources[1].IPVersion != "" {
		t.Errorf("omitted ip_version should stay empty, got %q", resources[1].IPVersion)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test . -run 'TestResolveIpVersion|TestLoadResourceConfigsIpVersion' -v`
Expected: FAIL — `undefined: resolveIpVersion` and `resources[0].IPVersion undefined`

- [ ] **Step 3: Write minimal implementation**

In `config.go`, add the field to `ResourceConfiguration`:

```go
type ResourceConfiguration struct {
	Cloud          string   `yaml:"cloud"`
	Type           string   `yaml:"type"`
	SubscriptionId string   `yaml:"subscription_id"`
	ResourceGroup  string   `yaml:"resource_group"`
	PolicyName     string   `yaml:"policy_name"`
	Name           string   `yaml:"name"`
	IPWhiteList    []string `yaml:"ip_whitelist"`
	Group          []string `yaml:"group"`
	IPVersion      string   `yaml:"ip_version"`
}
```

Add both helpers to `config.go`, immediately after `applyDefaults`:

```go
// resolveIpVersion normalises a resource's ip_version and applies def when it is
// unset. ok is false for an unsupported value; callers decide how to react.
func resolveIpVersion(v, def string) (out string, ok bool) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "":
		return def, true
	case ipVersionV4:
		return ipVersionV4, true
	case ipVersionV6:
		return ipVersionV6, true
	case ipVersionBoth:
		return ipVersionBoth, true
	}
	return "", false
}

// mustResolveIpVersion resolves a resource's ip_version or exits, matching how
// config.load() already treats an unsupported cloud or resource type.
func mustResolveIpVersion(v, def string) string {
	out, ok := resolveIpVersion(v, def)
	if !ok {
		log.Fatalln("config.load(): unsupported ip_version '" + v + "' (expected ipv4, ipv6 or both)")
	}
	return out
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test . -run 'TestResolveIpVersion|TestLoadResourceConfigs' -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add config.go config_test.go
git commit -m "feat: add ip_version resource config field"
```

---

## Task 4: UniFi — family filter and family-aware member format

`unifiMember` currently does `strings.TrimSuffix(ip, "/32")`. Naively adding `/128` alongside it would be a bug: `/32` is a single-host mask only for IPv4 — on IPv6 it is a very large subnet, and `2a00:11c7::/32` must keep its mask. The check has to be family-aware.

**Files:**
- Modify: `unifi.go:23-28` (struct), `unifi.go:222`, `unifi.go:232`, `unifi.go:239-246` (`unifiMember`)
- Modify: `config.go:236-245` (the `unifi` → `networklist` case arm)
- Test: `unifi_test.go`

- [ ] **Step 1: Write the failing test**

Add to `unifi_test.go`:

```go
// TestUnifiMemberFamilyAware asserts single hosts lose their mask while real
// subnets keep theirs — including the trap that /32 is a host mask on IPv4 but a
// large subnet on IPv6.
func TestUnifiMemberFamilyAware(t *testing.T) {
	tests := []struct {
		ip   string
		want string
	}{
		{"1.1.1.1/32", "1.1.1.1"},
		{"1.1.1.1", "1.1.1.1"},
		{"85.0.0.0/24", "85.0.0.0/24"},
		{"2a00:11c7:1234:b801::1/128", "2a00:11c7:1234:b801::1"},
		{"2a00:11c7:1234:b801::1", "2a00:11c7:1234:b801::1"},
		{"2a00:11c7:1234:b801::/64", "2a00:11c7:1234:b801::/64"},
		// /32 on IPv6 is a subnet, not a host — it must survive untouched
		{"2a00:11c7::/32", "2a00:11c7::/32"},
		// unparseable input is passed through unchanged
		{"not-an-ip", "not-an-ip"},
	}

	for _, f := range tests {
		if got := unifiMember(f.ip); got != f.want {
			t.Errorf("unifiMember(%q) = %q, want %q", f.ip, got, f.want)
		}
	}
}

func TestBuildMembersIPv6(t *testing.T) {
	c.Debug = false
	c.IPWhiteList = []string{"9.9.9.9/32", "2a00:1111::5/128"} // one of each family
	getGroups := func(string) []string { return nil }
	nl := UnifiNetworkList{Name: "v6", Group: nil, IPVersion: ipVersionV6}
	list := map[string]string{
		"alice": "1.1.1.1/32",                  // IPv4 -> excluded from a v6 list
		"bob":   "2a00:2222:3333:4444::1/128",  // IPv6 -> included, mask stripped
	}

	got := nl.buildMembers(list, getGroups)

	want := map[string]bool{
		"2a00:2222:3333:4444::1": true, // bob, host mask stripped
		"2a00:1111::5":           true, // static v6 host, mask stripped
	}
	if len(got) != len(want) {
		t.Fatalf("buildMembers = %v, want keys %v", got, want)
	}
	for _, m := range got {
		if !want[m] {
			t.Errorf("unexpected member %q in %v (v6 list must exclude IPv4)", m, got)
		}
	}
}

func TestBuildMembersBothFamilies(t *testing.T) {
	c.Debug = false
	c.IPWhiteList = nil
	getGroups := func(string) []string { return nil }
	nl := UnifiNetworkList{Name: "mixed", Group: nil, IPVersion: ipVersionBoth}
	list := map[string]string{
		"alice": "1.1.1.1/32",
		"bob":   "2a00:2222::1/128",
		"bad":   "not-an-ip",
	}

	got := nl.buildMembers(list, getGroups)

	want := map[string]bool{"1.1.1.1": true, "2a00:2222::1": true}
	if len(got) != len(want) {
		t.Fatalf("buildMembers = %v, want keys %v", got, want)
	}
	for _, m := range got {
		if !want[m] {
			t.Errorf("unexpected member %q in %v", m, got)
		}
	}
}

// TestBuildMembersDefaultsToIPv4 pins the upgrade guarantee: a list with no
// ip_version set behaves exactly as it did before this field existed.
func TestBuildMembersDefaultsToIPv4(t *testing.T) {
	c.Debug = false
	c.IPWhiteList = nil
	getGroups := func(string) []string { return nil }
	nl := UnifiNetworkList{Name: "legacy", Group: nil} // IPVersion zero value
	list := map[string]string{
		"alice": "1.1.1.1/32",
		"bob":   "2a00:2222::1/128",
	}

	got := nl.buildMembers(list, getGroups)

	if len(got) != 1 || got[0] != "1.1.1.1" {
		t.Errorf("buildMembers = %v, want [1.1.1.1] (unset ip_version means ipv4)", got)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test . -run 'TestUnifiMember|TestBuildMembers' -v`
Expected: FAIL — `unknown field IPVersion in struct literal` and `TestUnifiMemberFamilyAware` failing on the IPv6 cases

- [ ] **Step 3: Write minimal implementation**

In `unifi.go`, add the field to `UnifiNetworkList`:

```go
type UnifiNetworkList struct {
	Name        string   // the Network List / firewall group name
	Group       []string // optional AzureAD group filter
	IPWhiteList []string // optional per-list static entries
	IPVersion   string   // ipv4 (default) | ipv6 | both
	client      unifiClient
}
```

In `unifi.go:222`, swap the dynamic-whitelist guard:

```go
		if !w.inRange(ip, nl.IPWhiteList) && matchesIpVersion(nl.IPVersion, ip) {
```

In `unifi.go:232`, swap the static-whitelist guard:

```go
		if matchesIpVersion(nl.IPVersion, ip) {
```

Replace `unifiMember` in `unifi.go:239-246` entirely:

```go
// unifiMember formats an address for a UniFi firewall group. UniFi stores single
// hosts as bare IPs — its UI rejects a host netmask ("enter single host
// addresses without the subnet mask") — so we strip the single-host mask while
// leaving real subnets (e.g. /24) untouched. Matching UniFi's stored form also
// keeps sameMembers() stable, so an unchanged whitelist doesn't force a PUT on
// every reconcile. The host mask is family-dependent: /32 for IPv4, /128 for
// IPv6. On IPv6 a /32 is a large subnet and must be preserved, so the family
// must be resolved before trimming.
func unifiMember(ip string) string {
	t, err := ipVersion(ip)
	if err != nil {
		return ip
	}
	if t == IpV6 {
		return strings.TrimSuffix(ip, "/128")
	}
	return strings.TrimSuffix(ip, "/32")
}
```

In `config.go`, the `unifi` → `networklist` arm gains one line:

```go
			case "networklist":
				var nl UnifiNetworkList
				nl.Name = resource.Name
				nl.Group = resource.Group
				nl.IPWhiteList = resource.IPWhiteList
				nl.IPVersion = mustResolveIpVersion(resource.IPVersion, ipVersionV4)
				nl.client = newUnifiClient(c.Unifi)
				nl.new(nl)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test . -run 'TestUnifiMember|TestBuildMembers|TestSameMembers|TestUpdate' -v`
Expected: PASS — including the four pre-existing `TestBuildMembers*` tests, which construct `UnifiNetworkList` without `IPVersion` and must keep their current IPv4 behaviour

- [ ] **Step 5: Commit**

```bash
git add unifi.go unifi_test.go config.go
git commit -m "feat: support ip_version on unifi network lists"
```

---

## Task 5: Azure — plumb `IPVersion` onto the resource structs

Plumbing only; the field is unused until Task 6, so the tree stays green.

**Files:**
- Modify: `azure.go:32-78` (all six structs)
- Modify: `config.go:183-232` (all six `azure` case arms)

- [ ] **Step 1: Add the field to all six structs**

In `azure.go`, add `IPVersion string` to `AzureFrontDoor`, `AzureStorageAccount`, `AzureKeyVault`, `AzurePostgresServer`, `AzureRedisCache` and `AzureCosmosDb`. For example:

```go
type AzureFrontDoor struct {
	SubscriptionId string
	ResourceGroup  string
	PolicyName     string
	IPWhiteList    []string
	Group          []string
	IPVersion      string
}
```

`AzureCosmosDb` keeps its trailing `Queued bool` field; add `IPVersion string` above it.

- [ ] **Step 2: Plumb it in `config.load()`**

In `config.go`, add one line to each of the six `azure` case arms, before the `.new(...)` call. Front Door defaults to `both`; every other type defaults to `ipv4`:

```go
			case "frontdoor":
				// Front Door has never filtered by address family, so it defaults
				// to both — an ipv4 default would silently stop whitelisting
				// existing IPv6 users on upgrade.
				fd.IPVersion = mustResolveIpVersion(resource.IPVersion, ipVersionBoth)
			case "storageaccount":
				st.IPVersion = mustResolveIpVersion(resource.IPVersion, ipVersionV4)
			case "keyvault":
				kv.IPVersion = mustResolveIpVersion(resource.IPVersion, ipVersionV4)
			case "postgres":
				pg.IPVersion = mustResolveIpVersion(resource.IPVersion, ipVersionV4)
			case "redis":
				rc.IPVersion = mustResolveIpVersion(resource.IPVersion, ipVersionV4)
			case "cosmosdb":
				cd.IPVersion = mustResolveIpVersion(resource.IPVersion, ipVersionV4)
```

The `case` labels above are shown only to identify which arm each line belongs in — insert the single assignment into the existing arm, do not duplicate the `case` statements. The arms are at `config.go:185` (frontdoor), `:193` (storageaccount), `:201` (keyvault), `:209` (postgres), `:217` (redis — note the label is `redis`, not `rediscache`) and `:225` (cosmosdb).

- [ ] **Step 3: Verify it compiles and everything still passes**

Run: `go build ./... && go vet ./...`
Expected: no output (success)

Run: `go test . -run 'TestMatchesIpVersion|TestIpRange|TestResolveIpVersion|TestLoadResourceConfigs|TestBuildMembers|TestUnifiMember' -v`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add azure.go config.go
git commit -m "feat: plumb ip_version onto azure resource structs"
```

---

## Task 6: Azure — apply the family filter

Ten existing guards swap to `matchesIpVersion`, and Front Door gains the guard it has always been missing.

**Files:**
- Modify: `azure.go:134` (Front Door — **add**), `azure.go:260`, `:294`, `:349`, `:365`, `:419`, `:438`, `:528`, `:547`, `:622`, `:638`

- [ ] **Step 1: Add Front Door's missing guard**

`azure.go:134` is the only whitelist guard in the codebase without a family check. Change:

```go
		if !w.inRange(ipval, fd.IPWhiteList) {
```

to:

```go
		if !w.inRange(ipval, fd.IPWhiteList) && matchesIpVersion(fd.IPVersion, ipval) {
```

Because `config.load()` defaults Front Door to `both`, this is behaviour-preserving by default and only filters when an operator asks for it.

- [ ] **Step 2: Swap the ten existing guards**

Replace each `isValidIpOrNetV4(x)` with `matchesIpVersion(<receiver>.IPVersion, x)`, using the receiver already in scope at that line:

| Line | Receiver | New expression |
|---|---|---|
| 260 | `st` | `!w.inRange(ipval, st.IPWhiteList) && matchesIpVersion(st.IPVersion, ipval)` |
| 294 | `st` | `matchesIpVersion(st.IPVersion, ipval)` |
| 349 | `kv` | `!w.inRange(ipval, kv.IPWhiteList) && matchesIpVersion(kv.IPVersion, ipval)` |
| 365 | `kv` | `matchesIpVersion(kv.IPVersion, ipval)` |
| 419 | `pg` | `!w.inRange(cidr, pg.IPWhiteList) && matchesIpVersion(pg.IPVersion, cidr)` |
| 438 | `pg` | `matchesIpVersion(pg.IPVersion, cidr)` |
| 528 | `rc` | `!w.inRange(cidr, rc.IPWhiteList) && matchesIpVersion(rc.IPVersion, cidr)` |
| 547 | `rc` | `matchesIpVersion(rc.IPVersion, cidr)` |
| 622 | `cd` | `!w.inRange(ipval, cd.IPWhiteList) && matchesIpVersion(cd.IPVersion, ipval)` |
| 638 | `cd` | `matchesIpVersion(cd.IPVersion, ipval)` |

Line numbers shift as you edit — work bottom-up (638 first, 260 last) so earlier line numbers stay valid.

- [ ] **Step 3: Verify no callers remain**

Run: `grep -n 'isValidIpOrNetV4' azure.go unifi.go`
Expected: no output

- [ ] **Step 4: Verify it builds and tests pass**

Run: `go build ./... && go vet ./...`
Expected: no output

Run: `go test . -run 'TestMatchesIpVersion|TestIpRange|TestResolveIpVersion|TestLoadResourceConfigs|TestBuildMembers|TestUnifiMember|TestUpdate' -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add azure.go
git commit -m "feat: filter azure whitelists by ip_version, fix missing front door guard"
```

---

## Task 7: Azure — move from `getIpList` to `ipRange`

Six call sites, all currently discarding the error via `_`. `ipRange` returns an error instead of calling `log.Fatal`, so each site must handle it.

**Files:**
- Modify: `azure.go:269`, `:301`, `:422`, `:439`, `:531`, `:548`

- [ ] **Step 1: Update the two Storage Account sites**

At `azure.go:269` (inside the dynamic-whitelist loop, within the `/31` split branch), change:

```go
					first, last, _ := getIpList(ipval)
```

to:

```go
					first, last, err := ipRange(ipval)
					if err != nil {
						log.Print("azure.AzureStorageAccount.update(): ", err)
						continue
					}
```

At `azure.go:301` (the static-whitelist loop, same `/31` branch), change:

```go
				first, last, _ := getIpList(ipval)
```

to:

```go
				first, last, err := ipRange(ipval)
				if err != nil {
					log.Print("azure.AzureStorageAccount.update(): ", err)
					continue
				}
```

- [ ] **Step 2: Update the two Postgres sites**

At `azure.go:422`:

```go
				first, last, err := ipRange(cidr)
				if err != nil {
					log.Print("azure.AzurePostgresServer.update(): ", err)
					continue
				}
```

At `azure.go:439`:

```go
			first, last, err := ipRange(cidr)
			if err != nil {
				log.Print("azure.AzurePostgresServer.update(): ", err)
				continue
			}
```

Note `azure.go:441` already declares `err` from `regexp.Compile` a few lines below with `:=`. After this change that becomes a redeclaration in the same scope — change line 441's `reg, err := regexp.Compile(...)` to `reg, err = regexp.Compile(...)`. Compile after editing to confirm.

- [ ] **Step 3: Update the two Redis Cache sites**

At `azure.go:531` and `azure.go:548`, apply the identical pattern with the `azure.AzureRedisCache.update(): ` log prefix:

```go
				first, last, err := ipRange(cidr)
				if err != nil {
					log.Print("azure.AzureRedisCache.update(): ", err)
					continue
				}
```

Check whether either site is followed by a `regexp.Compile` that also uses `:=` on `err`, as Postgres is, and switch that to `=` if so.

- [ ] **Step 4: Verify no callers remain**

Run: `grep -n 'getIpList' azure.go`
Expected: no output

- [ ] **Step 5: Verify it builds and tests pass**

Run: `go build ./... && go vet ./...`
Expected: no output

Run: `go test . -run 'TestIpRange|TestGetIpList|TestMatchesIpVersion|TestBuildMembers' -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add azure.go
git commit -m "refactor: use ipRange instead of getIpList in azure resources"
```

---

## Task 8: Delete the superseded helpers

Both are now unreferenced outside their own tests.

**Files:**
- Modify: `functions.go` (delete `isValidIpOrNetV4` ~line 84, delete `getIpList` ~line 38)
- Modify: `functions_test.go` (delete `TestIsValidIpOrNetV4`, `TestGetIpList`)

- [ ] **Step 1: Confirm nothing but the tests reference them**

Run: `grep -rn 'isValidIpOrNetV4\|getIpList' --include='*.go' .`
Expected: hits only in `functions.go` (the definitions) and `functions_test.go` (the two tests)

- [ ] **Step 2: Delete `isValidIpOrNetV4` from `functions.go`**

Remove:

```go
// isValidIpOrNetV4 reports whether ip is a parseable IPv4 address or IPv4 CIDR.
func isValidIpOrNetV4(ip string) bool {
	ipType, err := ipVersion(ip)
	return err == nil && ipType == IpV4
}
```

- [ ] **Step 3: Delete `getIpList` from `functions.go`**

Remove the whole `getIpList` function (the one with the `binary.BigEndian` arithmetic and the enumeration loop), including its `// function to get ips in subnet range` comment.

- [ ] **Step 4: Drop the now-unused `encoding/binary` import**

`getIpList` was the only user of `binary`. Remove `"encoding/binary"` from the `import` block at the top of `functions.go`. Confirm with:

Run: `grep -n 'binary\.' functions.go`
Expected: no output

- [ ] **Step 5: Delete the two obsolete tests**

Remove `TestGetIpList` and `TestIsValidIpOrNetV4` from `functions_test.go`. `TestGetIpList` was the only user of `reflect` in that file — check and remove the `"reflect"` import if nothing else needs it:

Run: `grep -n 'reflect\.' functions_test.go`
Expected: no output (if so, drop the import)

- [ ] **Step 6: Verify the full suite**

Run: `go build ./... && go vet ./...`
Expected: no output

Run: `go test ./...`
Expected: PASS. This run includes the Docker-backed Redis suite (`ory/dockertest`) and takes roughly 60 seconds; Docker/OrbStack must be running.

- [ ] **Step 7: Commit**

```bash
git add functions.go functions_test.go
git commit -m "refactor: remove isValidIpOrNetV4 and getIpList"
```

---

## Task 9: Documentation

**Files:**
- Modify: `config/config.yaml`, `config.dev/config.yaml`, `README.md`
- Check: `helm/ip-whitelister/README.md`

- [ ] **Step 1: Document the field in the sample configs**

In `config/config.yaml`, above the `resources:` list, add a comment describing the field, and add a UniFi IPv6 example alongside the existing UniFi entry (around line 74):

```yaml
  # ip_version selects which address family a resource is whitelisted for:
  #   ipv4 (default) | ipv6 | both
  # A user has one IP — whichever family their browser reached the app over — so
  # an IPv4 user never appears in an ipv6 resource, and vice versa.
  # Note: azure frontdoor defaults to both, since it has never filtered by family.
  - cloud: unifi
    type: networklist
    name: example-allow-list-ipv6
    ip_version: ipv6
```

Mirror the same comment and example in `config.dev/config.yaml` (near its existing `unifi` resource around line 31).

- [ ] **Step 2: Document it in the README**

Add a row to the config key table, after the `ip_whitelist` row at `README.md:69`:

```markdown
| `ip_version`   | Per-resource address family: `ipv4` (default), `ipv6`, or `both`. |
```

Then add this subsection immediately after that table (before `### Secrets via environment variables` at line 71):

```markdown
### Address families (`ip_version`)

Each entry in `resources` takes an optional `ip_version`:

| Value  | Effect                                              |
| ------ | --------------------------------------------------- |
| `ipv4` | Only IPv4 addresses are whitelisted. **Default.**   |
| `ipv6` | Only IPv6 addresses are whitelisted.                |
| `both` | Both families are whitelisted.                      |

A user has a single whitelisted IP — whichever family their browser reached the
app over — so an IPv4 user never appears in an `ipv6` resource, and vice versa.
To cover both, whitelist against two resources.

**Exception:** `azure` / `frontdoor` defaults to `both`, because it has never
filtered by address family. Set `ip_version: ipv4` explicitly to restrict it.

Note that not every backing service accepts IPv6 — Azure Key Vault firewall
rules, for example, are IPv4-only. `ip_version` filters what the app sends; it
does not check what the service accepts.
```

Finally, extend the UniFi example at `README.md:135-143` with an IPv6 list, since UniFi Network Lists are family-typed (`address-group` vs `ipv6-address-group`) and need one list per family:

```yaml
resources:
  - cloud: unifi
    type: networklist
    name: ip-whitelister      # the Network List to manage
    group:                    # optional: only whitelist users in these AzureAD groups
      - <group-object-id>
    ip_whitelist:             # optional: per-list static entries
      - 1.2.3.4/32

  # a UniFi Network List is family-typed, so IPv6 needs its own list
  - cloud: unifi
    type: networklist
    name: ip-whitelister-ipv6
    ip_version: ipv6
```

- [ ] **Step 3: Check the Helm chart README**

Run: `grep -n 'ip_whitelist\|resources:' helm/ip-whitelister/README.md`

If it documents resource fields, add `ip_version` there too. If it only documents chart values and points at the app README for resource schema, leave it alone.

- [ ] **Step 4: Verify nothing broke**

Run: `go test ./...`
Expected: PASS (`TestLoad` reads `config/config.yaml`, so a YAML syntax error there fails the suite)

- [ ] **Step 5: Commit**

```bash
git add config/config.yaml config.dev/config.yaml README.md helm/ip-whitelister/README.md
git commit -m "docs: document ip_version resource field"
```

---

## Done criteria

- [ ] `go test ./...` passes with Docker running
- [ ] `grep -rn 'isValidIpOrNetV4\|getIpList' --include='*.go' .` returns nothing
- [ ] A `unifi` / `networklist` resource with `ip_version: ipv6` builds members from IPv6 whitelist entries with `/128` stripped
- [ ] A resource with no `ip_version` behaves exactly as it did before this branch
- [ ] An invalid `ip_version` value stops startup with a clear message

## Follow-up (not this plan)

The `/128` member format and UniFi's `ipv6-address-group` handling are unverified against a live gateway — the same open item already tracked for the `/32` behaviour. Add both to the outstanding UniFi live-gateway validation task rather than blocking this work.
