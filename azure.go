package main

import (
	"context"
	"log"
	"strconv"

	"github.com/Azure/azure-sdk-for-go/services/frontdoor/mgmt/2019-10-01/frontdoor"
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/adal"
	"github.com/Azure/go-autorest/autorest/to"
)

type Azure struct {
	FrontDoor []AzureFrontDoor
}

type AzureFrontDoor struct {
	SubscriptionId string
	ResourceGroup  string
	PolicyName     string
}

func (*AzureFrontDoor) new(fd AzureFrontDoor) {
	a.FrontDoor = append(a.FrontDoor, fd)
	log.Println("azure.AzureFrontDoor.new(): frontdoor added '" + fd.ResourceGroup + "/" + fd.PolicyName + "'")
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
	for _, ipval := range w.List {
		ips = append(ips, ipval)
	}

	// split into lists of 100 ips
	// ip whitelisting
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

	// static ip whitelisting
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
