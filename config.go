package main

import (
	"errors"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
	"gopkg.in/yaml.v2"
)

type Configuration struct {
	File        string
	Debug       bool
	Url         string                  `yaml:"url"`
	Redis       RedisConfiguration      `yaml:"redis"`
	Auth        Authentication          `yaml:"auth"`
	Resources   []ResourceConfiguration `yaml:"resources"`
	Defaults    Defaults                `yaml:"defaults"`
	IPWhiteList []string                `yaml:"ip_whitelist"`
	TTL         int                     `yaml:"ttl"`
	Unifi       UnifiConfiguration      `yaml:"unifi"`
}

// Defaults are per-config-file fallback values applied to any resource in that
// file that leaves the corresponding field blank.
type Defaults struct {
	SubscriptionId string `yaml:"subscription_id"`
	ResourceGroup  string `yaml:"resource_group"`
}

// UnifiConfiguration holds the single UniFi gateway connection + credentials.
type UnifiConfiguration struct {
	Host     string `yaml:"host"`
	Site     string `yaml:"site"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

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

var defaultConfigFile = "config/config.yaml"
var resourcesDir = "config/resources"

// loadResourceConfigs reads every YAML file in dir, applying each file's own
// defaults, and returns the combined resources. A missing dir is not an error:
// it simply yields no extra resources, so running with only config.yaml works.
func loadResourceConfigs(dir string) ([]ResourceConfiguration, error) {
	entries, err := ioutil.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var resources []ResourceConfiguration
	for _, resourceConfig := range entries {
		if resourceConfig.IsDir() || resourceConfig.Name() == "..data" {
			continue
		}
		var rc Configuration
		yamlFile, err := ioutil.ReadFile(filepath.Join(dir, resourceConfig.Name()))
		if err != nil {
			return nil, err
		}
		if err := yaml.Unmarshal(yamlFile, &rc); err != nil {
			return nil, err
		}
		// each resource file can define its own defaults
		applyDefaults(rc.Resources, rc.Defaults)
		resources = append(resources, rc.Resources...)
	}
	return resources, nil
}

// applyDefaults fills in any per-resource subscription_id / resource_group that
// were left blank with the file-level defaults.
func applyDefaults(resources []ResourceConfiguration, d Defaults) {
	for i := range resources {
		if resources[i].SubscriptionId == "" {
			resources[i].SubscriptionId = d.SubscriptionId
		}
		if resources[i].ResourceGroup == "" {
			resources[i].ResourceGroup = d.ResourceGroup
		}
	}
}

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

// applyAuthDefaults fills in auth defaults. When auth is disabled
// (type none/disabled) and no identity header is configured, it defaults to the
// header set by Cloudflare Access.
func applyAuthDefaults(a Authentication) Authentication {
	switch strings.ToLower(a.Type) {
	case "none", "disabled":
		if a.Header == "" {
			a.Header = "Cf-Access-Authenticated-User-Email"
		}
		if a.IPHeader == "" {
			a.IPHeader = "Cf-Connecting-Ip"
		}
	}
	return a
}

func (c *Configuration) load(reload ...bool) *Configuration {
	if strings.ToLower(os.Getenv("DEBUG")) == "true" {
		c.Debug = true
	} else {
		c.Debug = false
	}

	c.File = os.Getenv("CONFIG_FILE")
	if c.File == "" {
		c.File = defaultConfigFile
	}

	if len(reload) == 0 {
		log.Println("config.load(): loading config file '" + c.File + "'")
	} else {
		log.Println("config.load(): changes detected, reloading config file '" + c.File + "'")
	}

	// read config
	yamlFile, err := ioutil.ReadFile(c.File)
	if err != nil {
		log.Fatalf("config.load(): %v ", err)
	}
	err = yaml.Unmarshal(yamlFile, &c)
	if err != nil {
		log.Fatalf("config.load(): %v", err)
	}

	if c.TTL == 0 {
		c.TTL = 24
	}

	c.Auth = applyAuthDefaults(c.Auth)

	if c.Unifi.Site == "" {
		c.Unifi.Site = "default"
	}
	if os.Getenv("UNIFI_USERNAME") != "" {
		c.Unifi.Username = os.Getenv("UNIFI_USERNAME")
	}
	if os.Getenv("UNIFI_PASSWORD") != "" {
		c.Unifi.Password = os.Getenv("UNIFI_PASSWORD")
	}

	// empty resources first
	a.FrontDoor = nil
	a.KeyVault = nil
	a.PostgresServer = nil
	a.StorageAccount = nil
	a.RedisCache = nil
	a.CosmosDb = nil
	u.NetworkList = nil

	// apply the main config file's defaults to its own resources
	applyDefaults(c.Resources, c.Defaults)

	// load extra resource configs (optional — a missing dir is fine)
	extraResources, err := loadResourceConfigs(resourcesDir)
	if err != nil {
		log.Fatalf("config.load(): %v", err)
	}
	c.Resources = append(c.Resources, extraResources...)

	// load resources
	for _, resource := range c.Resources {
		switch strings.ToLower(resource.Cloud) {
		case "azure":
			switch strings.ToLower(resource.Type) {
			case "frontdoor":
				var fd AzureFrontDoor
				fd.SubscriptionId = resource.SubscriptionId
				fd.ResourceGroup = resource.ResourceGroup
				fd.PolicyName = resource.PolicyName
				fd.IPWhiteList = resource.IPWhiteList
				fd.Group = resource.Group
				// Front Door has never filtered by address family, so it defaults
				// to both — an ipv4 default would silently stop whitelisting
				// existing IPv6 users on upgrade.
				fd.IPVersion = mustResolveIpVersion(resource.IPVersion, ipVersionBoth)
				fd.new(fd)
			case "storageaccount":
				var st AzureStorageAccount
				st.SubscriptionId = resource.SubscriptionId
				st.ResourceGroup = resource.ResourceGroup
				st.Name = resource.Name
				st.IPWhiteList = resource.IPWhiteList
				st.Group = resource.Group
				st.IPVersion = mustResolveIpVersion(resource.IPVersion, ipVersionV4)
				st.new(st)
			case "keyvault":
				var kv AzureKeyVault
				kv.SubscriptionId = resource.SubscriptionId
				kv.ResourceGroup = resource.ResourceGroup
				kv.Name = resource.Name
				kv.IPWhiteList = resource.IPWhiteList
				kv.Group = resource.Group
				kv.IPVersion = mustResolveIpVersion(resource.IPVersion, ipVersionV4)
				kv.new(kv)
			case "postgres":
				var pg AzurePostgresServer
				pg.SubscriptionId = resource.SubscriptionId
				pg.ResourceGroup = resource.ResourceGroup
				pg.Name = resource.Name
				pg.IPWhiteList = resource.IPWhiteList
				pg.Group = resource.Group
				pg.IPVersion = mustResolveIpVersion(resource.IPVersion, ipVersionV4)
				pg.new(pg)
			case "redis":
				var rc AzureRedisCache
				rc.SubscriptionId = resource.SubscriptionId
				rc.ResourceGroup = resource.ResourceGroup
				rc.Name = resource.Name
				rc.IPWhiteList = resource.IPWhiteList
				rc.Group = resource.Group
				rc.IPVersion = mustResolveIpVersion(resource.IPVersion, ipVersionV4)
				rc.new(rc)
			case "cosmosdb":
				var cd AzureCosmosDb
				cd.SubscriptionId = resource.SubscriptionId
				cd.ResourceGroup = resource.ResourceGroup
				cd.Name = resource.Name
				cd.IPWhiteList = resource.IPWhiteList
				cd.Group = resource.Group
				cd.IPVersion = mustResolveIpVersion(resource.IPVersion, ipVersionV4)
				cd.new(cd)
			default:
				log.Fatalln("config.load(): unsupported " + resource.Cloud + " resource type '" + resource.Type + "'")
			}
		case "unifi":
			switch strings.ToLower(resource.Type) {
			case "networklist":
				var nl UnifiNetworkList
				nl.Name = resource.Name
				nl.Group = resource.Group
				nl.IPWhiteList = resource.IPWhiteList
				nl.IPVersion = mustResolveIpVersion(resource.IPVersion, ipVersionV4)
				nl.client = newUnifiClient(c.Unifi)
				nl.new(nl)
			default:
				log.Fatalln("config.load(): unsupported " + resource.Cloud + " resource type '" + resource.Type + "'")
			}
		default:
			log.Fatalln("config.load(): unsupported cloud '" + resource.Cloud + "'")
		}
	}

	if os.Getenv("CLIENT_SECRET") != "" {
		c.Auth.ClientSecret = os.Getenv("CLIENT_SECRET")
	}
	if os.Getenv("REDIS_TOKEN") != "" {
		c.Redis.Token = os.Getenv("REDIS_TOKEN")
	}

	if len(reload) == 0 {
		log.Println("config.load(): config file loaded")
	} else {
		log.Println("config.load(): config file reloaded")
	}

	go c.watchForConfigChanges()

	return c
}

func (c *Configuration) watchForConfigChanges() {
	c.File = os.Getenv("CONFIG_FILE")
	if c.File == "" {
		c.File = defaultConfigFile
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal(err)
	}
	defer watcher.Close()

	done := make(chan bool)
	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				if c.Debug {
					log.Println("config.watchForConfigChanges(): event:", event)
				}
				if event.Op&fsnotify.Write == fsnotify.Write || event.Op&fsnotify.Remove == fsnotify.Remove {
					if c.Debug {
						log.Println("config.watchForConfigChanges(): modified file:", event.Name)
					}
					c.load(true)
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				log.Println("config.watchForConfigChanges(): error:", err)
			}
		}
	}()

	err = watcher.Add(c.File)
	if err != nil {
		log.Fatal(err)
	}
	// only watch the resources dir if it exists — it's optional
	if _, err := os.Stat(resourcesDir); err == nil {
		if err := watcher.Add(resourcesDir); err != nil {
			log.Fatal(err)
		}
	}
	<-done
}
