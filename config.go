package main

import (
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"

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
				fd.new(fd)
			case "storageaccount":
				var st AzureStorageAccount
				st.SubscriptionId = resource.SubscriptionId
				st.ResourceGroup = resource.ResourceGroup
				st.Name = resource.Name
				st.IPWhiteList = resource.IPWhiteList
				st.Group = resource.Group
				st.new(st)
			case "keyvault":
				var kv AzureKeyVault
				kv.SubscriptionId = resource.SubscriptionId
				kv.ResourceGroup = resource.ResourceGroup
				kv.Name = resource.Name
				kv.IPWhiteList = resource.IPWhiteList
				kv.Group = resource.Group
				kv.new(kv)
			case "postgres":
				var pg AzurePostgresServer
				pg.SubscriptionId = resource.SubscriptionId
				pg.ResourceGroup = resource.ResourceGroup
				pg.Name = resource.Name
				pg.IPWhiteList = resource.IPWhiteList
				pg.Group = resource.Group
				pg.new(pg)
			case "redis":
				var rc AzureRedisCache
				rc.SubscriptionId = resource.SubscriptionId
				rc.ResourceGroup = resource.ResourceGroup
				rc.Name = resource.Name
				rc.IPWhiteList = resource.IPWhiteList
				rc.Group = resource.Group
				rc.new(rc)
			case "cosmosdb":
				var cd AzureCosmosDb
				cd.SubscriptionId = resource.SubscriptionId
				cd.ResourceGroup = resource.ResourceGroup
				cd.Name = resource.Name
				cd.IPWhiteList = resource.IPWhiteList
				cd.Group = resource.Group
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
