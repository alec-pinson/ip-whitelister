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

output "redis" {
  value = {
    host  = azurerm_redis_cache.this.hostname
    port  = azurerm_redis_cache.this.port
    token = azurerm_redis_cache.this.primary_access_key
  }
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

// storage account
resource "azurerm_storage_account" "this" {
  name                     = join("", regexall("[a-zA-Z]+", format("st-%s", var.name)))
  resource_group_name      = azurerm_resource_group.this.name
  location                 = azurerm_resource_group.this.location
  account_tier             = "Standard"
  account_replication_type = "LRS"

  lifecycle { ignore_changes = [network_rules] }
}

output "storage_account" {
  value = {
    subscription_id = var.subscription_id
    resource_group  = azurerm_storage_account.this.resource_group_name
    name            = azurerm_storage_account.this.name
  }
}

resource "azurerm_role_assignment" "storage_account_access" {
  scope                = azurerm_storage_account.this.id
  role_definition_name = "Contributor"
  principal_id         = var.service_principal_id
}

// key vault
resource "azurerm_key_vault" "this" {
  name                = join("", regexall("[a-zA-Z]+", format("kv-%s", var.name)))
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  tenant_id           = data.azurerm_client_config.current.tenant_id
  sku_name            = "standard"

  access_policy {
    tenant_id = data.azurerm_client_config.current.tenant_id
    object_id = data.azurerm_client_config.current.object_id

    key_permissions     = ["Get"]
    secret_permissions  = ["Get"]
    storage_permissions = ["Get"]
  }

  lifecycle { ignore_changes = [network_acls] }
}

output "key_vault" {
  value = {
    subscription_id = var.subscription_id
    resource_group  = azurerm_key_vault.this.resource_group_name
    name            = azurerm_key_vault.this.name
  }
}

resource "azurerm_role_assignment" "key_vault_access" {
  scope                = azurerm_key_vault.this.id
  role_definition_name = "Contributor"
  principal_id         = var.service_principal_id
}
