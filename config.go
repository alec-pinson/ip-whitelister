package main

import (
	"io/ioutil"
	"log"
	"os"
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
	IPWhiteList []string                `yaml:"ip_whitelist"`
	TTL         int                     `yaml":ttl"`
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

	// empty resources first
	a.FrontDoor = nil
	a.KeyVault = nil
	a.PostgresServer = nil
	a.StorageAccount = nil
	a.RedisCache = nil
	a.CosmosDb = nil

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
				if event.Op&fsnotify.Write == fsnotify.Write {
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
	<-done
}
