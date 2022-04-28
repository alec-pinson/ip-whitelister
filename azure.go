package main

import (
	"context"
	"encoding/json"
	"log"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/services/cosmos-db/mgmt/2021-10-15/documentdb"
	"github.com/Azure/azure-sdk-for-go/services/frontdoor/mgmt/2019-10-01/frontdoor"
	"github.com/Azure/azure-sdk-for-go/services/keyvault/mgmt/2019-09-01/keyvault"
	"github.com/Azure/azure-sdk-for-go/services/postgresql/mgmt/2020-01-01/postgresql"
	"github.com/Azure/azure-sdk-for-go/services/redis/mgmt/2020-12-01/redis"
	"github.com/Azure/azure-sdk-for-go/services/storage/mgmt/2021-04-01/storage"
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/adal"
	"github.com/Azure/go-autorest/autorest/to"
)

type Azure struct {
	FrontDoor      []AzureFrontDoor
	StorageAccount []AzureStorageAccount
	KeyVault       []AzureKeyVault
	PostgresServer []AzurePostgresServer
	RedisCache     []AzureRedisCache
	CosmosDb       []AzureCosmosDb
}

type AzureFrontDoor struct {
	SubscriptionId string
	ResourceGroup  string
	PolicyName     string
	IPWhiteList    []string
	Group          []string
}

type AzureStorageAccount struct {
	SubscriptionId string
	ResourceGroup  string
	Name           string
	IPWhiteList    []string
	Group          []string
}

type AzureKeyVault struct {
	SubscriptionId string
	ResourceGroup  string
	Name           string
	IPWhiteList    []string
	Group          []string
}

type AzurePostgresServer struct {
	SubscriptionId string
	ResourceGroup  string
	Name           string
	IPWhiteList    []string
	Group          []string
}

type AzureRedisCache struct {
	SubscriptionId string
	ResourceGroup  string
	Name           string
	IPWhiteList    []string
	Group          []string
}

type AzureCosmosDb struct {
	SubscriptionId string
	ResourceGroup  string
	Name           string
	IPWhiteList    []string
	Group          []string
	Queued         bool
}

func (*AzureFrontDoor) new(fd AzureFrontDoor) {
	a.FrontDoor = append(a.FrontDoor, fd)
	log.Println("azure.AzureFrontDoor.new(): frontdoor added '" + fd.ResourceGroup + "/" + fd.PolicyName + "'")
}

func (*AzureStorageAccount) new(st AzureStorageAccount) {
	a.StorageAccount = append(a.StorageAccount, st)
	log.Println("azure.AzureStorageAccount.new(): storage account added '" + st.ResourceGroup + "/" + st.Name + "'")
}

func (*AzureKeyVault) new(kv AzureKeyVault) {
	a.KeyVault = append(a.KeyVault, kv)
	log.Println("azure.AzureKeyVault.new(): key vault added '" + kv.ResourceGroup + "/" + kv.Name + "'")
}

func (*AzurePostgresServer) new(pg AzurePostgresServer) {
	a.PostgresServer = append(a.PostgresServer, pg)
	log.Println("azure.AzurePostgresServer.new(): postgres server added '" + pg.ResourceGroup + "/" + pg.Name + "'")
}

func (*AzureRedisCache) new(rc AzureRedisCache) {
	a.RedisCache = append(a.RedisCache, rc)
	log.Println("azure.AzureRedisCache.new(): redis cache added '" + rc.ResourceGroup + "/" + rc.Name + "'")
}

func (*AzureCosmosDb) new(cd AzureCosmosDb) {
	a.CosmosDb = append(a.CosmosDb, cd)
	log.Println("azure.AzureCosmosDb.new(): cosmos db added '" + cd.ResourceGroup + "/" + cd.Name + "'")
}

func (*Azure) authorize() (autorest.Authorizer, error) {
	var a autorest.Authorizer

	oauthConfig, err := adal.NewOAuthConfig("https://login.microsoftonline.com", c.Auth.TenantId)
	if err != nil {
		return nil, err
	}

	token, err := adal.NewServicePrincipalToken(*oauthConfig, c.Auth.ClientId, c.Auth.ClientSecret, "https://management.azure.com/")
	if err != nil {
		return nil, err
	}
	a = autorest.NewBearerAuthorizer(token)
	return a, nil
}

func (fd *AzureFrontDoor) update() int {
	log.Print("azure.AzureFrontDoor.update(): updating '" + fd.ResourceGroup + "/" + fd.PolicyName + "'")

	var rules []frontdoor.CustomRule

	ips := make([]string, 0, len(w.List))
	for key, ipval := range w.List {
		if !w.inRange(ipval, fd.IPWhiteList) {
			// ip not within static whitelist range
			if hasGroup(fd.Group, r.getGroups(key)) {
				ips = append(ips, ipval)
			} else {
				if c.Debug {
					log.Print("azure.AzureFrontDoor.update(): user '"+key+"' is not part of any of the groups ", fd.Group, " required for frontdoor '"+fd.ResourceGroup+"/"+fd.PolicyName+"'")
				}
			}
		}
	}

	// split into lists of 100 ips
	// ip whitelist
	var ii int
	for i, v := range chunkList(ips, 100) {
		if len(v) != 0 {
			rule := &frontdoor.CustomRule{
				Name:         to.StringPtr("ipwhitelist" + strconv.Itoa(i)),
				EnabledState: frontdoor.CustomRuleEnabledStateEnabled,
				Action:       frontdoor.Allow,
				Priority:     to.Int32Ptr(int32(i + 1)),
				RuleType:     frontdoor.MatchRule,
				MatchConditions: &[]frontdoor.MatchCondition{
					{
						MatchVariable:   "RemoteAddr",
						Operator:        "IPMatch",
						NegateCondition: to.BoolPtr(false),
						MatchValue:      to.StringSlicePtr(v),
					},
				},
			}
			rules = append(rules, *rule)
			ii = i
		}
	}

	// static ip whitelist
	ii += 1
	for i, v := range chunkList(append(c.IPWhiteList, fd.IPWhiteList...), 100) {
		if len(v) != 0 {
			rule := &frontdoor.CustomRule{
				Name:         to.StringPtr("staticwhitelist" + strconv.Itoa(i)),
				EnabledState: frontdoor.CustomRuleEnabledStateEnabled,
				Action:       frontdoor.Allow,
				Priority:     to.Int32Ptr(int32(ii + i + 1)),
				RuleType:     frontdoor.MatchRule,
				MatchConditions: &[]frontdoor.MatchCondition{
					{
						MatchVariable:   "RemoteAddr",
						Operator:        "IPMatch",
						NegateCondition: to.BoolPtr(false),
						MatchValue:      to.StringSlicePtr(v),
					},
				},
			}
			rules = append(rules, *rule)
		}
	}

	// default block all rule
	rule := &frontdoor.CustomRule{
		Name:         to.StringPtr("blockall"),
		EnabledState: frontdoor.CustomRuleEnabledStateEnabled,
		Action:       frontdoor.Block,
		Priority:     to.Int32Ptr(10000),
		RuleType:     frontdoor.MatchRule,
		MatchConditions: &[]frontdoor.MatchCondition{
			{
				MatchVariable:   "RemoteAddr",
				Operator:        "IPMatch",
				NegateCondition: to.BoolPtr(false),
				MatchValue:      to.StringSlicePtr([]string{"0.0.0.0/0", "::/0"}),
			},
		},
	}
	rules = append(rules, *rule)

	azfd := frontdoor.NewPoliciesClient(fd.SubscriptionId)
	azfd.Authorizer, _ = a.authorize()
	_, err := azfd.CreateOrUpdate(context.Background(), fd.ResourceGroup, fd.PolicyName, frontdoor.WebApplicationFirewallPolicy{
		Location: to.StringPtr("Global"),
		WebApplicationFirewallPolicyProperties: &frontdoor.WebApplicationFirewallPolicyProperties{
			PolicySettings: &frontdoor.PolicySettings{
				EnabledState:                  frontdoor.PolicyEnabledStateEnabled,
				Mode:                          "Prevention",
				CustomBlockResponseStatusCode: to.Int32Ptr(403),
			},
			CustomRules: &frontdoor.CustomRuleList{
				Rules: &rules,
			},
			ManagedRules: &frontdoor.ManagedRuleSetList{
				ManagedRuleSets: &[]frontdoor.ManagedRuleSet{
					{
						RuleSetType:    to.StringPtr("Microsoft_BotManagerRuleSet"),
						RuleSetVersion: to.StringPtr("1.0"),
					},
				},
			},
		},
	})
	if c.Debug {
		prettyBody, _ := json.MarshalIndent(rules, "", "\t")
		log.Printf("azure.AzureFrontDoor.update(): \n%v", string(prettyBody))
	}
	if err != nil {
		log.Print("azure.AzureFrontDoor.update():", err)
	} else {
		log.Print("azure.AzureFrontDoor.update(): updated '" + fd.ResourceGroup + "/" + fd.PolicyName + "'")
	}

	return 0
}

func (st *AzureStorageAccount) update() int {
	log.Print("azure.AzureStorageAccount.update(): updating '" + st.ResourceGroup + "/" + st.Name + "'")

	var ipRules []storage.IPRule
	// ip whitelist
	for key, ipval := range w.List {
		if !w.inRange(ipval, st.IPWhiteList) && isValidIpOrNetV4(ipval) {
			// ip not within static whitelist range
			if !strings.Contains(ipval, "/32") {
				ipval = deleteNetmask(ipval)
			}
			if hasGroup(st.Group, r.getGroups(key)) {
				if strings.Contains(ipval, "/31") {
					// storage account doesnt support /31, have to split both ips
					first, last, _ := getIpList(ipval)
					ipRules = append(ipRules, storage.IPRule{
						IPAddressOrRange: to.StringPtr(first),
						Action:           storage.ActionAllow,
					})
					ipRules = append(ipRules, storage.IPRule{
						IPAddressOrRange: to.StringPtr(last),
						Action:           storage.ActionAllow,
					})
				} else {
					ipRules = append(ipRules, storage.IPRule{
						IPAddressOrRange: to.StringPtr(ipval),
						Action:           storage.ActionAllow,
					})
				}
			} else {
				if c.Debug {
					log.Print("azure.AzureStorageAccount.update(): user '"+key+"' is not part of any of the groups ", st.Group, " required for storage account '"+st.ResourceGroup+"/"+st.Name+"'")
				}
			}
		}
	}

	// static ip whitelist
	for _, ipval := range append(c.IPWhiteList, st.IPWhiteList...) {
		if isValidIpOrNetV4(ipval) {
			ipval = deleteNetmask(ipval)
			if strings.Contains(ipval, "/31") {
				// storage account doesnt support /31, have to split both ips
				first, last, _ := getIpList(ipval)
				ipRules = append(ipRules, storage.IPRule{
					IPAddressOrRange: to.StringPtr(first),
					Action:           storage.ActionAllow,
				})
				ipRules = append(ipRules, storage.IPRule{
					IPAddressOrRange: to.StringPtr(last),
					Action:           storage.ActionAllow,
				})
			} else {
				ipRules = append(ipRules, storage.IPRule{
					IPAddressOrRange: to.StringPtr(ipval),
					Action:           storage.ActionAllow,
				})
			}
		}
	}

	azst := storage.NewAccountsClient(st.SubscriptionId)
	azst.Authorizer, _ = a.authorize()
	ret, err := azst.Update(context.Background(), st.ResourceGroup, st.Name, storage.AccountUpdateParameters{
		AccountPropertiesUpdateParameters: &storage.AccountPropertiesUpdateParameters{
			AllowBlobPublicAccess: to.BoolPtr(false),
			NetworkRuleSet: &storage.NetworkRuleSet{
				DefaultAction: storage.DefaultActionDeny,
				IPRules:       &ipRules,
			},
		},
	})
	if c.Debug {
		prettyBody, _ := json.MarshalIndent(ipRules, "", "\t")
		log.Printf("azure.AzureStorageAccount.update(): \n%v", string(prettyBody))
	}
	if err != nil {
		log.Print("azure.AzureStorageAccount.update():", err)
	} else {
		log.Print("azure.AzureStorageAccount.update(): updated '" + st.ResourceGroup + "/" + st.Name + "'")
	}

	return ret.Response.StatusCode
}

func (kv *AzureKeyVault) update() int {
	log.Print("azure.AzureKeyVault.update(): updating '" + kv.ResourceGroup + "/" + kv.Name + "'")

	var ipRules []keyvault.IPRule
	// ip whitelist
	for key, ipval := range w.List {
		if !w.inRange(ipval, kv.IPWhiteList) && isValidIpOrNetV4(ipval) {
			// ip not within static whitelist range
			if hasGroup(kv.Group, r.getGroups(key)) {
				ipRules = append(ipRules, keyvault.IPRule{
					Value: to.StringPtr(ipval),
				})
			} else {
				if c.Debug {
					log.Print("azure.AzureKeyVault.update(): user '"+key+"' is not part of any of the groups ", kv.Group, " required for keyvault '"+kv.ResourceGroup+"/"+kv.Name+"'")
				}
			}
		}
	}

	// static ip whitelist
	for _, ipval := range append(c.IPWhiteList, kv.IPWhiteList...) {
		if isValidIpOrNetV4(ipval) {
			ipRules = append(ipRules, keyvault.IPRule{
				Value: to.StringPtr(ipval),
			})
		}
	}

	azkv := keyvault.NewVaultsClient(kv.SubscriptionId)
	azkv.Authorizer, _ = a.authorize()
	ret, err := azkv.Update(context.Background(), kv.ResourceGroup, kv.Name, keyvault.VaultPatchParameters{
		Properties: &keyvault.VaultPatchProperties{
			NetworkAcls: &keyvault.NetworkRuleSet{
				DefaultAction: keyvault.Deny,
				IPRules:       &ipRules,
			},
		},
	})
	if c.Debug {
		prettyBody, _ := json.MarshalIndent(ipRules, "", "\t")
		log.Printf("azure.AzureKeyVault.update(): \n%v", string(prettyBody))
	}
	if err != nil {
		log.Print("azure.AzureKeyVault.update():", err)
	} else {
		log.Print("azure.AzureKeyVault.update(): updated '" + kv.ResourceGroup + "/" + kv.Name + "'")
	}

	return ret.Response.StatusCode
}

func (pg *AzurePostgresServer) update() int {
	log.Print("azure.AzurePostgresServer.update(): updating '" + pg.ResourceGroup + "/" + pg.Name + "'")

	var error bool
	error = false

	azpg := postgresql.NewFirewallRulesClient(pg.SubscriptionId)
	azpg.Authorizer, _ = a.authorize()

	// 1. get current rules from postgres server
	getCurrRules, err := azpg.ListByServer(context.Background(), pg.ResourceGroup, pg.Name)
	if err != nil {
		log.Print("azure.AzurePostgresServer.update():", err)
		return 1
	}
	currRules := make(map[string]postgresql.FirewallRule)
	for _, v := range *getCurrRules.Value {
		currRules[*v.Name] = v
	}

	// 2. generate list of what postgres server should look like
	newRules := make(map[string]postgresql.FirewallRule)
	// ip whitelist
	for key, cidr := range w.List {
		if !w.inRange(cidr, pg.IPWhiteList) && isValidIpOrNetV4(cidr) {
			// ip not within static whitelist range
			if hasGroup(pg.Group, r.getGroups(key)) {
				first, last, _ := getIpList(cidr)
				newRules[key] = postgresql.FirewallRule{
					FirewallRuleProperties: &postgresql.FirewallRuleProperties{
						StartIPAddress: to.StringPtr(first),
						EndIPAddress:   to.StringPtr(last),
					},
				}
			} else {
				if c.Debug {
					log.Print("azure.AzurePostgresServer.update(): user '"+key+"' is not part of any of the groups ", pg.Group, " required for postgres '"+pg.ResourceGroup+"/"+pg.Name+"'")
				}
			}
		}
	}
	// static ip whitelist
	for _, cidr := range append(c.IPWhiteList, pg.IPWhiteList...) {
		if isValidIpOrNetV4(cidr) {
			first, last, _ := getIpList(cidr)
			// reg expression for creating key
			reg, err := regexp.Compile("[^a-zA-Z0-9]+")
			if err != nil {
				log.Fatal("azure.AzurePostgresServer.update():", err)
			}
			key := reg.ReplaceAllString("static"+first+last, "")
			newRules[key] = postgresql.FirewallRule{
				FirewallRuleProperties: &postgresql.FirewallRuleProperties{
					StartIPAddress: to.StringPtr(first),
					EndIPAddress:   to.StringPtr(last),
				},
			}
		}
	}

	// 3. compare lists and do necessary delete/add/update
	for key, fwRule := range currRules {
		if _, ok := newRules[key]; !ok {
			// delete
			if c.Debug {
				log.Print("azure.PostgresServer.update(): deleting rule '" + key + "' - start: " + *fwRule.StartIPAddress + ", end: " + *fwRule.EndIPAddress)
			}
			ret, err := azpg.Delete(context.Background(), pg.ResourceGroup, pg.Name, key)
			if err != nil {
				log.Print("azure.AzurePostgresServer.update():", err)
				log.Print("azure.AzurePostgresServer.update():", ret.Response().StatusCode)
				error = true
			}
		}
	}
	for key, fwRule := range newRules {
		if _, ok := currRules[key]; !ok {
			// add
			if c.Debug {
				log.Print("azure.PostgresServer.update(): adding rule '" + key + "' - start: " + *fwRule.StartIPAddress + ", end: " + *fwRule.EndIPAddress)
			}
			ret, err := azpg.CreateOrUpdate(context.Background(), pg.ResourceGroup, pg.Name, key, fwRule)
			if err != nil {
				log.Print("azure.AzurePostgresServer.update():", err)
				log.Print("azure.AzurePostgresServer.update():", ret.Response().StatusCode)
				error = true
			}
		} else if *currRules[key].StartIPAddress != *fwRule.StartIPAddress || *currRules[key].EndIPAddress != *fwRule.EndIPAddress {
			// update
			if c.Debug {
				log.Print("azure.PostgresServer.update(): updating rule '" + key + "' - start: " + *currRules[key].StartIPAddress + ", end: " + *currRules[key].EndIPAddress + " to start: " + *fwRule.StartIPAddress + ", end: " + *fwRule.EndIPAddress)
			}
			ret, err := azpg.CreateOrUpdate(context.Background(), pg.ResourceGroup, pg.Name, key, fwRule)
			if err != nil {
				log.Print("azure.AzurePostgresServer.update():", err)
				log.Print("azure.AzurePostgresServer.update():", ret.Response().StatusCode)
				error = true
			}
		}
	}

	if !error {
		log.Print("azure.AzurePostgresServer.update(): updated '" + pg.ResourceGroup + "/" + pg.Name + "'")
	}

	return 0
}

func (rc *AzureRedisCache) update() int {
	log.Print("azure.AzureRedisCache.update(): updating '" + rc.ResourceGroup + "/" + rc.Name + "'")

	var error bool
	error = false

	azrc := redis.NewFirewallRulesClient(rc.SubscriptionId)
	azrc.Authorizer, _ = a.authorize()

	// 1. get current rules from postgres server
	getCurrRules, err := azrc.List(context.Background(), rc.ResourceGroup, rc.Name)
	if err != nil {
		log.Print("azure.AzureRedisCache.update():", err)
		return 1
	}

	currRules := make(map[string]redis.FirewallRule)
	for _, v := range getCurrRules.Values() {
		currRules[strings.Split(*v.Name, "/")[1]] = v
	}

	// 2. generate list of what postgres server should look like
	newRules := make(map[string]redis.FirewallRule)
	// ip whitelist
	for key, cidr := range w.List {
		if !w.inRange(cidr, rc.IPWhiteList) && isValidIpOrNetV4(cidr) {
			// ip not within static whitelist range
			if hasGroup(rc.Group, r.getGroups(key)) {
				first, last, _ := getIpList(cidr)
				newRules[key] = redis.FirewallRule{
					FirewallRuleProperties: &redis.FirewallRuleProperties{
						StartIP: to.StringPtr(first),
						EndIP:   to.StringPtr(last),
					},
				}
			} else {
				if c.Debug {
					log.Print("azure.AzureRedisCache.update(): user '"+key+"' is not part of any of the groups ", rc.Group, " required for redis cache '"+rc.ResourceGroup+"/"+rc.Name+"'")
				}
			}
		}
	}
	// static ip whitelist
	for _, cidr := range append(c.IPWhiteList, rc.IPWhiteList...) {
		if isValidIpOrNetV4(cidr) {
			first, last, _ := getIpList(cidr)
			// reg expression for creating key
			reg, err := regexp.Compile("[^a-zA-Z0-9]+")
			if err != nil {
				log.Fatal("azure.AzureRedisCache.update():", err)
			}
			key := reg.ReplaceAllString("static"+first+last, "")
			newRules[key] = redis.FirewallRule{
				FirewallRuleProperties: &redis.FirewallRuleProperties{
					StartIP: to.StringPtr(first),
					EndIP:   to.StringPtr(last),
				},
			}
		}
	}

	// 3. compare lists and do necessary delete/add/update
	for key, fwRule := range currRules {
		if _, ok := newRules[key]; !ok {
			// delete
			if c.Debug {
				log.Print("azure.AzureRedisCache.update(): deleting rule '" + key + "' - start: " + *fwRule.StartIP + ", end: " + *fwRule.EndIP)
			}
			ret, err := azrc.Delete(context.Background(), rc.ResourceGroup, rc.Name, key)
			if err != nil {
				log.Print("azure.AzureRedisCache.update():", err)
				log.Print("azure.AzureRedisCache.update():", ret.Response.StatusCode)
				error = true
			}
		}
	}
	for key, fwRule := range newRules {
		if _, ok := currRules[key]; !ok {
			// add
			if c.Debug {
				log.Print("azure.AzureRedisCache.update(): adding rule '" + key + "' - start: " + *fwRule.StartIP + ", end: " + *fwRule.EndIP)
			}
			ret, err := azrc.CreateOrUpdate(context.Background(), rc.ResourceGroup, rc.Name, key, fwRule)
			if err != nil {
				log.Print("azure.AzureRedisCache.update():", err)
				log.Print("azure.AzureRedisCache.update():", ret.Response.StatusCode)
				error = true
			}
		} else if *currRules[key].StartIP != *fwRule.StartIP || *currRules[key].EndIP != *fwRule.EndIP {
			// update
			if c.Debug {
				log.Print("azure.AzureRedisCache.update(): updating rule '" + key + "' - start: " + *currRules[key].StartIP + ", end: " + *currRules[key].EndIP + " to start: " + *fwRule.StartIP + ", end: " + *fwRule.EndIP)
			}
			ret, err := azrc.CreateOrUpdate(context.Background(), rc.ResourceGroup, rc.Name, key, fwRule)
			if err != nil {
				log.Print("azure.AzureRedisCache.update():", err)
				log.Print("azure.AzureRedisCache.update():", ret.Response.StatusCode)
				error = true
			}
		}
	}

	if !error {
		log.Print("azure.AzureRedisCache.update(): updated '" + rc.ResourceGroup + "/" + rc.Name + "'")
	}

	return 0
}

func (cd *AzureCosmosDb) update() int {
	if cd.Queued {
		return 0
	}

	log.Print("azure.AzureCosmosDb.update(): updating '" + cd.ResourceGroup + "/" + cd.Name + "'")

	var ipRules []documentdb.IPAddressOrRange
	// ip whitelist
	for key, ipval := range w.List {
		if !w.inRange(ipval, cd.IPWhiteList) && isValidIpOrNetV4(ipval) {
			// ip not within static whitelist range
			if hasGroup(cd.Group, r.getGroups(key)) {
				ipRules = append(ipRules, documentdb.IPAddressOrRange{
					IPAddressOrRange: to.StringPtr(ipval),
				})
			} else {
				if c.Debug {
					log.Print("azure.AzureCosmosDb.update(): user '"+key+"' is not part of any of the groups ", cd.Group, " required for cosmosdb '"+cd.ResourceGroup+"/"+cd.Name+"'")
				}
			}
		}
	}

	// static ip whitelist
	for _, ipval := range append(c.IPWhiteList, cd.IPWhiteList...) {
		if isValidIpOrNetV4(ipval) {
			ipRules = append(ipRules, documentdb.IPAddressOrRange{
				IPAddressOrRange: to.StringPtr(ipval),
			})
		}
	}

	azcd := documentdb.NewDatabaseAccountsClient(cd.SubscriptionId)
	azcd.Authorizer, _ = a.authorize()
	ret, err := azcd.Update(context.Background(), cd.ResourceGroup, cd.Name, documentdb.DatabaseAccountUpdateParameters{
		DatabaseAccountUpdateProperties: &documentdb.DatabaseAccountUpdateProperties{
			IPRules: &ipRules,
		},
	})
	if c.Debug {
		prettyBody, _ := json.MarshalIndent(ipRules, "", "\t")
		log.Printf("azure.AzureCosmosDb.update(): \n%v", string(prettyBody))
	}
	if err != nil {
		if ret.Response().StatusCode == 412 {
			// There is already an operation in progress which requires exclusive lock on this service. Please retry the operation after sometime.
			// so stupid, queue job to run against in a few minutes :@
			go cd.queueUpdate(cd)
		} else {
			log.Print("azure.AzureCosmosDb.update():", err)
		}
	} else {
		log.Print("azure.AzureCosmosDb.update(): updated '" + cd.ResourceGroup + "/" + cd.Name + "'")
	}

	return 0
}

func (cd *AzureCosmosDb) queueUpdate(me *AzureCosmosDb) {
	if !me.Queued {
		me.Queued = true
		if c.Debug {
			log.Print("azure.AzureCosmosDb.queueUpdate(): queued job, retrying in 2 minutes")
		}
		time.Sleep(time.Minute * 2)
		if c.Debug {
			log.Print("azure.AzureCosmosDb.queueUpdate(): retrying job")
		}
		me.Queued = false
		me.update()
	}
}
