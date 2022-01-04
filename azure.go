package main

import (
	"context"
	"log"
	"regexp"
	"strconv"
	"strings"

	"github.com/Azure/azure-sdk-for-go/services/frontdoor/mgmt/2019-10-01/frontdoor"
	"github.com/Azure/azure-sdk-for-go/services/keyvault/mgmt/2019-09-01/keyvault"
	"github.com/Azure/azure-sdk-for-go/services/postgresql/mgmt/2020-01-01/postgresql"
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
}

type AzureFrontDoor struct {
	SubscriptionId string
	ResourceGroup  string
	PolicyName     string
	Group          []string
}

type AzureStorageAccount struct {
	SubscriptionId string
	ResourceGroup  string
	Name           string
	Group          []string
}

type AzureKeyVault struct {
	SubscriptionId string
	ResourceGroup  string
	Name           string
	Group          []string
}

type AzurePostgresServer struct {
	SubscriptionId string
	ResourceGroup  string
	Name           string
	Group          []string
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

	var rules []frontdoor.CustomRule

	ips := make([]string, 0, len(w.List))
	for key, ipval := range w.List {
		if fd.Group == nil {
			// no groups, allow everyone
			ips = append(ips, ipval)
		} else {
			// groups in use, only allow people that are in the group
			if hasGroup(fd.Group, r.getGroups(key)) {
				ips = append(ips, ipval)
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
	for i, v := range chunkList(c.IPWhiteList, 100) {
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
	ret, err := azfd.CreateOrUpdate(context.Background(), fd.ResourceGroup, fd.PolicyName, frontdoor.WebApplicationFirewallPolicy{
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
	if err != nil {
		log.Print(err)
	}

	return ret.Response().StatusCode
}

func (st *AzureStorageAccount) update() int {

	var ipRules []storage.IPRule
	// ip whitelist
	for _, ipval := range w.List {
		if strings.Contains(ipval, "/32") {
			// storage account requires /32 be removed...
			ipval = strings.ReplaceAll(ipval, "/32", "")
		}
		if strings.Contains(ipval, "/31") {
			// error for now, later can add something to add the 2 individal ips
			log.Print("azure.AzureStorageAccount.update(): currently /31 ip addresses are not supported")
		}
		ipRules = append(ipRules, storage.IPRule{
			IPAddressOrRange: to.StringPtr(ipval),
			Action:           storage.ActionAllow,
		})
	}

	// static ip whitelist
	for _, ipval := range c.IPWhiteList {
		if strings.Contains(ipval, "/32") {
			// storage account requires /32 be removed...
			ipval = strings.ReplaceAll(ipval, "/32", "")
		}
		if strings.Contains(ipval, "/31") {
			// error for now, later can add something to add the 2 individal ips
			log.Print("azure.AzureStorageAccount.update(): currently /31 ip addresses are not supported")
		}
		ipRules = append(ipRules, storage.IPRule{
			IPAddressOrRange: to.StringPtr(ipval),
			Action:           storage.ActionAllow,
		})
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
	if err != nil {
		log.Print(err)
	}

	return ret.Response.StatusCode
}

func (kv *AzureKeyVault) update() int {

	var ipRules []keyvault.IPRule
	// ip whitelist
	for _, ipval := range w.List {
		ipRules = append(ipRules, keyvault.IPRule{
			Value: to.StringPtr(ipval),
		})
	}

	// static ip whitelist
	for _, ipval := range c.IPWhiteList {
		if strings.Contains(ipval, "/32") {
			// storage account requires /32 be removed...
			ipval = strings.ReplaceAll(ipval, "/32", "")
		}
		if strings.Contains(ipval, "/31") {
			first, last, _ := getIpList(ipval)
			ipRules = append(ipRules, keyvault.IPRule{
				Value: to.StringPtr(first),
			})
			ipRules = append(ipRules, keyvault.IPRule{
				Value: to.StringPtr(last),
			})
		}
		ipRules = append(ipRules, keyvault.IPRule{
			Value: to.StringPtr(ipval),
		})
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
	if err != nil {
		log.Print(err)
	}

	return ret.Response.StatusCode
}

func (pg *AzurePostgresServer) update() int {
	azpg := postgresql.NewFirewallRulesClient(pg.SubscriptionId)
	azpg.Authorizer, _ = a.authorize()

	// 1. get current rules from postgres server
	getCurrRules, err := azpg.ListByServer(context.Background(), pg.ResourceGroup, pg.Name)
	if err != nil {
		log.Print(err)
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
		first, last, _ := getIpList(cidr)
		newRules[key] = postgresql.FirewallRule{
			FirewallRuleProperties: &postgresql.FirewallRuleProperties{
				StartIPAddress: to.StringPtr(first),
				EndIPAddress:   to.StringPtr(last),
			},
		}
	}
	// static ip whitelist
	for _, cidr := range c.IPWhiteList {
		first, last, _ := getIpList(cidr)
		// reg expression for creating key
		reg, err := regexp.Compile("[^a-zA-Z0-9]+")
		if err != nil {
			log.Fatal(err)
		}
		key := reg.ReplaceAllString("static"+first+last, "")
		newRules[key] = postgresql.FirewallRule{
			FirewallRuleProperties: &postgresql.FirewallRuleProperties{
				StartIPAddress: to.StringPtr(first),
				EndIPAddress:   to.StringPtr(last),
			},
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
				log.Print(err)
				log.Print(ret.Response().StatusCode)
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
				log.Print(err)
				log.Print(ret.Response().StatusCode)
			}
		} else if *currRules[key].StartIPAddress != *fwRule.StartIPAddress || *currRules[key].EndIPAddress != *fwRule.EndIPAddress {
			// update
			if c.Debug {
				log.Print("azure.PostgresServer.update(): updating rule '" + key + "' - start: " + *currRules[key].StartIPAddress + ", end: " + *currRules[key].EndIPAddress + " to start: " + *fwRule.StartIPAddress + ", end: " + *fwRule.EndIPAddress)
			}
			ret, err := azpg.CreateOrUpdate(context.Background(), pg.ResourceGroup, pg.Name, key, fwRule)
			if err != nil {
				log.Print(err)
				log.Print(ret.Response().StatusCode)
			}
		}
	}

	return 0
}
