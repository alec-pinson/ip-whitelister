package main

import (
	"io/ioutil"
	"log"
	"os"
	"strings"

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
	Group          []string `yaml:"group"`
}

func (c *Configuration) load() *Configuration {
	if strings.ToLower(os.Getenv("DEBUG")) == "true" {
		c.Debug = true
	} else {
		c.Debug = false
	}

	c.File = os.Getenv("CONFIG_FILE")
	// default to config/config.yaml
	if c.File == "" {
		c.File = "config/config.yaml"
	}

	log.Println("config.load(): loading config file '" + c.File + "'")

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
				fd.Group = resource.Group
				fd.new(fd)
			case "storageaccount":
				var st AzureStorageAccount
				st.SubscriptionId = resource.SubscriptionId
				st.ResourceGroup = resource.ResourceGroup
				st.Name = resource.Name
				st.Group = resource.Group
				st.new(st)
			case "keyvault":
				var kv AzureKeyVault
				kv.SubscriptionId = resource.SubscriptionId
				kv.ResourceGroup = resource.ResourceGroup
				kv.Name = resource.Name
				kv.Group = resource.Group
				kv.new(kv)
			case "postgres":
				var pg AzurePostgresServer
				pg.SubscriptionId = resource.SubscriptionId
				pg.ResourceGroup = resource.ResourceGroup
				pg.Name = resource.Name
				pg.Group = resource.Group
				pg.new(pg)
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

	log.Println("config.load(): config file loaded")

	return c
}
