resource "azurerm_frontdoor_firewall_policy" "this" {
  name                              = join("", regexall("[a-zA-Z]+", format("%s-fd-policy", var.name)))
  resource_group_name               = azurerm_resource_group.this.name
  enabled                           = true
  mode                              = "Prevention"
  redirect_url                      = null
  custom_block_response_status_code = 403
  custom_block_response_body        = null

  /*
    The IP whitelist for this WAF rule is now managed by the below application:-
    https://xyz.com/ip-whitelister
  */
  lifecycle { ignore_changes = [custom_rule, managed_rule] }
}

output "azure_frontdoor_policy" {
  value = {
    subscription_id = var.subscription_id
    resource_group  = azurerm_frontdoor_firewall_policy.this.resource_group_name
    name            = azurerm_frontdoor_firewall_policy.this.name
  }
}

resource "azurerm_role_assignment" "frontdoor_policy_access" {
  scope                = azurerm_frontdoor_firewall_policy.this.id
  role_definition_name = "Contributor"
  principal_id         = var.service_principal_id
}
