resource "azurerm_cosmosdb_account" "this" {
  name                = format("%s-cosmosdb", var.name)
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  offer_type          = "Standard"

  consistency_policy {
    consistency_level       = "BoundedStaleness"
    max_interval_in_seconds = 300
    max_staleness_prefix    = 100000
  }

  geo_location {
    location          = azurerm_resource_group.this.location
    failover_priority = 0
  }

  /*
    The IP whitelist for this WAF rule is now managed by the below application:-
    https://xyz.com/ip-whitelister
  */
  lifecycle { ignore_changes = [ip_range_filter] }
}

output "cosmosdb" {
  value = {
    subscription_id = var.subscription_id
    resource_group  = azurerm_cosmosdb_account.this.resource_group_name
    name            = azurerm_cosmosdb_account.this.name
  }
}

resource "azurerm_role_assignment" "cosmosdb_access" {
  scope                = azurerm_cosmosdb_account.this.id
  role_definition_name = "Contributor"
  principal_id         = var.service_principal_id
}
