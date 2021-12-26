// resource group
resource "azurerm_resource_group" "this" {
  name     = format("%s-rg", var.name)
  location = "North Europe"
}

// redis database
resource "azurerm_redis_cache" "this" {
  name                = format("%s-redis", var.name)
  resource_group_name = azurerm_resource_group.this.name
  location            = azurerm_resource_group.this.location
  capacity            = 2
  family              = "C"
  sku_name            = "standard"
  enable_non_ssl_port = true
  minimum_tls_version = "1.2"
}

// frontdoor policy
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

resource "azurerm_role_assignment" "frontdoor_policy_access" {
  scope                = azurerm_frontdoor_firewall_policy.this.id
  role_definition_name = "Contributor"
  principal_id         = var.service_principal_id
}
