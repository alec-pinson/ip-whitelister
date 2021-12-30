package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
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

func (*Azure) getToken() string {
	targetUrl := "https://login.microsoftonline.com/" + c.Auth.TenantId + "/oauth2/token"
	requestBody := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {c.Auth.ClientId},
		"client_secret": {c.Auth.ClientSecret},
		"resource":      {"https://management.azure.com/"},
	}

	resp, err := http.PostForm(targetUrl, requestBody)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)

	if resp.StatusCode != 200 {
		log.Fatalln("azure.getToken(): response Body:", string(body))
	}

	authResp := AzureResourceToken{}
	jsonErr := json.Unmarshal(body, &authResp)
	if jsonErr != nil {
		log.Fatal("azure.getToken(): ", jsonErr)
	}

	if authResp.AccessToken == "" {
		log.Fatalln("azure.getToken(): Unable to retrive access token.")
	}

	return authResp.AccessToken
}

func (*AzureFrontDoor) new(fd AzureFrontDoor) {
	a.FrontDoor = append(a.FrontDoor, fd)
	log.Println("azure.AzureFrontDoor.new(): frontdoor added '" + fd.ResourceGroup + "/" + fd.PolicyName + "'")
}

func (fd *AzureFrontDoor) update() int {
	accessToken := a.getToken()
	url := "https://management.azure.com/subscriptions/" + fd.SubscriptionId + "/resourceGroups/" + fd.ResourceGroup + "/providers/Microsoft.Network/FrontDoorWebApplicationFirewallPolicies/" + fd.PolicyName + "?api-version=2019-10-01"

	var rules []AzureFrontDoorRules

	ips := make([]string, 0, len(w.List))
	for _, ipval := range w.List {
		ips = append(ips, ipval)
	}

	// split into lists of 100 ips
	// ip whitelisting START
	var ii int
	for i, v := range chunkList(ips, 100) {
		if len(v) != 0 {
			rule := new(AzureFrontDoorRules)
			rule.Name = "ipwhitelist" + strconv.Itoa(i)
			rule.EnabledState = "Enabled"
			rule.Action = "Allow"
			rule.Priority = i + 1
			rule.RuleType = "MatchRule"

			matchConditions := new(AzureFrontDoorMatchConditions)
			matchConditions.MatchVariable = "RemoteAddr"
			matchConditions.Operator = "IPMatch"
			matchConditions.NegateCondition = false
			matchConditions.MatchValue = v

			rule.MatchConditions = append(rule.MatchConditions, *matchConditions)

			rules = append(rules, *rule)
			ii = i
		}
	}
	// ip whitelisting END
	// static ip whitelisting START
	ii += 1
	for i, v := range chunkList(c.IPWhiteList, 100) {
		if len(v) != 0 {
			rule := new(AzureFrontDoorRules)
			rule.Name = "staticwhitelist" + strconv.Itoa(i)
			rule.EnabledState = "Enabled"
			rule.Action = "Allow"
			rule.Priority = ii + i + 1
			rule.RuleType = "MatchRule"

			matchConditions := new(AzureFrontDoorMatchConditions)
			matchConditions.MatchVariable = "RemoteAddr"
			matchConditions.Operator = "IPMatch"
			matchConditions.NegateCondition = false
			matchConditions.MatchValue = v

			rule.MatchConditions = append(rule.MatchConditions, *matchConditions)

			rules = append(rules, *rule)
		}
	}
	// static ip whitelisting END

	// default block all rule
	rule := new(AzureFrontDoorRules)
	rule.Name = "blockall"
	rule.EnabledState = "Enabled"
	rule.Action = "Block"
	rule.Priority = 10000
	rule.RuleType = "MatchRule"

	matchConditions := new(AzureFrontDoorMatchConditions)
	matchConditions.MatchVariable = "RemoteAddr"
	matchConditions.Operator = "IPMatch"
	matchConditions.NegateCondition = false
	matchConditions.MatchValue = append(matchConditions.MatchValue, "0.0.0.0/0", "::/0")

	rule.MatchConditions = append(rule.MatchConditions, *matchConditions)

	rules = append(rules, *rule)

	var managedRuleSets []AzureFrontDoorManagedRuleSets
	managedRuleSet := new(AzureFrontDoorManagedRuleSets)
	managedRuleSet.RuleSetType = "Microsoft_BotManagerRuleSet"
	managedRuleSet.RuleSetVersion = "1.0"
	managedRuleSets = append(managedRuleSets, *managedRuleSet)

	updateWAF := new(AzureFrontDoorCreateUpdate)
	updateWAF.Name = fd.PolicyName
	updateWAF.Type = "Microsoft.Network/frontdoorwebapplicationfirewallpolicies"
	updateWAF.Location = "Global"
	updateWAF.Properties.PolicySettings.EnabledState = "Enabled"
	updateWAF.Properties.PolicySettings.Mode = "Prevention"
	updateWAF.Properties.PolicySettings.CustomBlockResponseStatusCode = 403
	updateWAF.Properties.CustomRules.Rules = rules
	updateWAF.Properties.ManagedRules.ManagedRuleSets = managedRuleSets

	requestBody, err := json.Marshal(updateWAF)

	req, err := http.NewRequest(http.MethodPut, url, bytes.NewBuffer(requestBody))
	if err != nil {
		log.Fatal(err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	azureClient := http.Client{}
	res, getErr := azureClient.Do(req)
	if getErr != nil {
		log.Fatal(getErr)
	}

	if res.Body != nil {
		defer res.Body.Close()
	}

	body, readErr := ioutil.ReadAll(res.Body)
	if readErr != nil {
		log.Fatal(readErr)
	}

	authResp := AzureResourceToken{}
	jsonErr := json.Unmarshal(body, &authResp)
	if jsonErr != nil {
		log.Fatal(jsonErr)
	}

	// 200=OK, 201=Created, 202=Accepted
	if res.StatusCode != 200 && res.StatusCode != 201 && res.StatusCode != 202 {
		prettyBody, _ := json.MarshalIndent(updateWAF, "", "    ")
		log.Println("azure.AzureFrontDoor.update(): REQUEST:")
		fmt.Printf("%v", string(prettyBody))

		log.Println("azure.AzureFrontDoor.update(): STATUS CODE: " + strconv.Itoa(res.StatusCode))

		log.Println("azure.AzureFrontDoor.update(): RESPONSE:")
		fmt.Printf("%v", string(body))
	} else {
		if c.Debug {
			prettyBody, _ := json.MarshalIndent(updateWAF, "", "    ")
			log.Println("azure.AzureFrontDoor.update(): REQUEST:")
			fmt.Printf("%v", string(prettyBody))

			switch res.StatusCode {
			case 200:
				log.Println("azure.AzureFrontDoor.update(): STATUS CODE: 200 - OK")
			case 201:
				log.Println("azure.AzureFrontDoor.update(): STATUS CODE: 201 - Created")
			case 202:
				log.Println("azure.AzureFrontDoor.update(): STATUS CODE: 202 - Accepted")
			default:
				log.Println("azure.AzureFrontDoor.update(): STATUS CODE: " + strconv.Itoa(res.StatusCode))
			}

			log.Println("azure.AzureFrontDoor.update(): RESPONSE:")
			fmt.Printf("%v", string(body))
		}
	}

	return res.StatusCode
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

func (fd *AzureFrontDoor) update2() int {

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
