package main

type AzureResourceToken struct {
	TokenType    string `json:"token_type"`
	ExpiresIn    string `json:"expires_in"`
	ExtExpiresIn string `json:"ext_expires_in"`
	ExpiresOn    string `json:"expires_on"`
	NotBefore    string `json:"not_before"`
	Resource     string `json:"resource"`
	AccessToken  string `json:"access_token"`
}

// https://mholt.github.io/json-to-go/
type AzureFrontDoorCreateUpdate struct {
	Type       string `json:"type"`
	Name       string `json:"name"`
	Location   string `json:"location"`
	Properties struct {
		PolicySettings struct {
			EnabledState                  string `json:"enabledState"`
			Mode                          string `json:"mode"`
			CustomBlockResponseStatusCode int    `json:"customBlockResponseStatusCode"`
		} `json:"policySettings"`
		CustomRules struct {
			Rules []AzureFrontDoorRules `json:"rules"`
		} `json:"customRules"`
		ManagedRules struct {
			ManagedRuleSets []AzureFrontDoorManagedRuleSets `json:"managedRuleSets"`
		} `json:"managedRules"`
	} `json:"properties"`
}
type AzureFrontDoorRules struct {
	Name                       string                          `json:"name"`
	EnabledState               string                          `json:"enabledState"`
	Priority                   int                             `json:"priority"`
	RuleType                   string                          `json:"ruleType"`
	RateLimitDurationInMinutes int                             `json:"rateLimitDurationInMinutes"`
	RateLimitThreshold         int                             `json:"rateLimitThreshold"`
	MatchConditions            []AzureFrontDoorMatchConditions `json:"matchConditions"`
	Action                     string                          `json:"action"`
}
type AzureFrontDoorMatchConditions struct {
	MatchVariable   string   `json:"matchVariable"`
	Operator        string   `json:"operator"`
	NegateCondition bool     `json:"negateCondition"`
	MatchValue      []string `json:"matchValue"`
}
type AzureFrontDoorManagedRuleSets struct {
	RuleSetType    string `json:"ruleSetType"`
	RuleSetVersion string `json:"ruleSetVersion"`
}
