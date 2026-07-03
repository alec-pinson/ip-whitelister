package main

import (
	"os"
	"path/filepath"
	"testing"
)

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
