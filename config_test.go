package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

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

func TestLoad(t *testing.T) {
	ret := c.load()
	if ret.Url == "" {
		t.Error("Failed to load config, missing config.url")
	}
	if ret.Auth.Type == "" {
		t.Error("Failed to load config, missing config.auth.type")
	}
	if ret.Auth.TenantId == "" {
		t.Error("Failed to load config, missing config.auth.tenant_id")
	}
	if ret.Auth.ClientId == "" {
		t.Error("Failed to load config, missing config.auth.client_id")
	}
	if ret.Auth.ClientSecret == "" {
		t.Error("Failed to load config, missing config.auth.client_secret")
	}
	if ret.Redis.Host == "" {
		t.Error("Failed to load config, missing config.redis.host")
	}
	if ret.Redis.Port == 0 {
		t.Error("Failed to load config, missing config.redis.port")
	}
	if ret.Redis.Token == "" {
		t.Error("Failed to load config, missing config.redis.token")
	}
}

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

func TestLoadResourceConfigsMissingDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "does-not-exist")

	resources, err := loadResourceConfigs(dir)
	if err != nil {
		t.Fatalf("missing resources dir should not error, got: %v", err)
	}
	if len(resources) != 0 {
		t.Errorf("expected no resources from missing dir, got %d", len(resources))
	}
}

func TestLoadResourceConfigs(t *testing.T) {
	dir := t.TempDir()
	yaml := "" +
		"defaults:\n" +
		"  subscription_id: sub-file\n" +
		"resources:\n" +
		"  - cloud: azure\n" +
		"    type: keyvault\n" +
		"    name: kv1\n"
	if err := os.WriteFile(filepath.Join(dir, "app.yaml"), []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	// a subdirectory and a ..data entry should both be ignored
	if err := os.Mkdir(filepath.Join(dir, "nested"), 0o755); err != nil {
		t.Fatal(err)
	}

	resources, err := loadResourceConfigs(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resources) != 1 {
		t.Fatalf("expected 1 resource, got %d", len(resources))
	}
	if resources[0].Name != "kv1" {
		t.Errorf("expected resource name kv1, got %q", resources[0].Name)
	}
	if resources[0].SubscriptionId != "sub-file" {
		t.Errorf("per-file defaults not applied, got %q", resources[0].SubscriptionId)
	}
}

func TestResolveIpVersion(t *testing.T) {
	tests := []struct {
		in     string
		def    string
		want   string
		wantOk bool
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

func TestApplyDefaults(t *testing.T) {
	defaults := Defaults{SubscriptionId: "sub-default", ResourceGroup: "rg-default"}
	resources := []ResourceConfiguration{
		{Name: "blank"}, // inherits both defaults
		{Name: "own", SubscriptionId: "sub-own", ResourceGroup: "rg-own"}, // keeps its own values
		{Name: "partial", SubscriptionId: "sub-own"},                      // keeps sub, inherits rg
	}

	applyDefaults(resources, defaults)

	if resources[0].SubscriptionId != "sub-default" || resources[0].ResourceGroup != "rg-default" {
		t.Errorf("blank resource did not inherit defaults: %+v", resources[0])
	}
	if resources[1].SubscriptionId != "sub-own" || resources[1].ResourceGroup != "rg-own" {
		t.Errorf("resource with its own values was overridden: %+v", resources[1])
	}
	if resources[2].SubscriptionId != "sub-own" || resources[2].ResourceGroup != "rg-default" {
		t.Errorf("partial resource not defaulted correctly: %+v", resources[2])
	}
}

func TestApplyAuthDefaults(t *testing.T) {
	cases := []struct {
		name         string
		typ          string
		header       string
		ipHeader     string
		wantHeader   string
		wantIPHeader string
	}{
		{"none defaults both headers", "none", "", "", "Cf-Access-Authenticated-User-Email", "Cf-Connecting-Ip"},
		{"disabled alias defaults too", "disabled", "", "", "Cf-Access-Authenticated-User-Email", "Cf-Connecting-Ip"},
		{"case-insensitive type", "None", "", "", "Cf-Access-Authenticated-User-Email", "Cf-Connecting-Ip"},
		{"explicit headers are kept", "none", "X-My-Id", "X-My-Ip", "X-My-Id", "X-My-Ip"},
		{"azure is unaffected", "azure", "", "", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := applyAuthDefaults(Authentication{Type: tc.typ, Header: tc.header, IPHeader: tc.ipHeader})
			if got.Header != tc.wantHeader {
				t.Errorf("header = %q, want %q", got.Header, tc.wantHeader)
			}
			if got.IPHeader != tc.wantIPHeader {
				t.Errorf("ipHeader = %q, want %q", got.IPHeader, tc.wantIPHeader)
			}
		})
	}
}

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
