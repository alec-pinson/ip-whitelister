resource "azurerm_storage_account" "this" {
  name                     = join("", regexall("[a-zA-Z]+", format("st-%s", var.name)))
  resource_group_name      = azurerm_resource_group.this.name
  location                 = azurerm_resource_group.this.location
  account_tier             = "Standard"
  account_replication_type = "LRS"

  /*
    The IP whitelist for these rules is now managed by the below application:-
    https://xyz.com/ip-whitelister
  */
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
