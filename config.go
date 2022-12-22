package main

import (
	"io/ioutil"
	"log"
	"os"
	"strings"

	"github.com/fsnotify/fsnotify"
	"gopkg.in/yaml.v2"
)

type SelectedConfigFile struct {
	Config []Configuration
}

type Configuration struct {
	File        string
	Debug       bool
	Url         string                  `yaml:"url"`
	Redis       RedisConfiguration      `yaml:"redis"`
	Auth        Authentication          `yaml:"auth"`
	Resources   []ResourceConfiguration `yaml:"resources"`
	Defaults    []Defaults              `yaml:"defaults"`
	IPWhiteList []string                `yaml:"ip_whitelist"`
	TTL         int                     `yaml":ttl"`
}

type Defaults struct {
	SubscriptionId string `yaml:"subscription_id"`
	ResourceGroup  string `yaml:"resource_group"`
}

type ResourceConfiguration struct {
	Defaults       []string `yaml:"defaults"`
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

	// load extra resource configs
	resourceConfigs, err := ioutil.ReadDir("config/resources/")
	if err != nil {
		log.Fatal(err)
	}

	var rc Configuration
	var scf SelectedConfigFile
	scf.Config = append(scf.Config, *c)
	for _, resourceConfig := range resourceConfigs {
		if !resourceConfig.IsDir() && resourceConfig.Name() != "..data" {
			yamlFile, err := ioutil.ReadFile("config/resources/" + resourceConfig.Name())
			if err != nil {
				log.Fatalf("config.load(): %v ", err)
			}
			err = yaml.Unmarshal(yamlFile, &rc)
			if err != nil {
				log.Fatalf("config.load(): %v", err)
			}
			rc.File = resourceConfig.Name()
			scf.Config = append(scf.Config, rc)
		}
	}

	// load resources
	for _, config := range scf.Config {
		subId := ""
		rg := ""
		for _, resource := range config.Resources {
			if resource.SubscriptionId == "" {
				subId = config.Defaults[0].SubscriptionId
			} else if resource.SubscriptionId != "" {
				subId = resource.SubscriptionId
			}
			if resource.ResourceGroup == "" {
				rg = config.Defaults[0].ResourceGroup
			} else if resource.ResourceGroup != "" {
				rg = resource.ResourceGroup
			}
			switch strings.ToLower(resource.Cloud) {
			case "azure":
				switch strings.ToLower(resource.Type) {

				case "frontdoor":
					var fd AzureFrontDoor
					fd.SubscriptionId = subId
					fd.ResourceGroup = rg
					fd.PolicyName = resource.PolicyName
					fd.IPWhiteList = resource.IPWhiteList
					fd.Group = resource.Group
					fd.new(fd)
				case "storageaccount":
					var st AzureStorageAccount
					st.SubscriptionId = subId
					st.ResourceGroup = rg
					st.Name = resource.Name
					st.IPWhiteList = resource.IPWhiteList
					st.Group = resource.Group
					st.new(st)
				case "keyvault":
					var kv AzureKeyVault
					kv.SubscriptionId = subId
					kv.ResourceGroup = rg
					kv.Name = resource.Name
					kv.IPWhiteList = resource.IPWhiteList
					kv.Group = resource.Group
					kv.new(kv)
				case "postgres":
					var pg AzurePostgresServer
					pg.SubscriptionId = subId
					pg.ResourceGroup = rg
					pg.Name = resource.Name
					pg.IPWhiteList = resource.IPWhiteList
					pg.Group = resource.Group
					pg.new(pg)
				case "redis":
					var rc AzureRedisCache
					rc.SubscriptionId = subId
					rc.ResourceGroup = rg
					rc.Name = resource.Name
					rc.IPWhiteList = resource.IPWhiteList
					rc.Group = resource.Group
					rc.new(rc)
				case "cosmosdb":
					var cd AzureCosmosDb
					cd.SubscriptionId = subId
					cd.ResourceGroup = rg
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
	err = watcher.Add("config/resources")
	if err != nil {
		log.Fatal(err)
	}
	<-done
}
