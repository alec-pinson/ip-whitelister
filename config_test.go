package main

import "testing"

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
