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

  /*
    The IP whitelist for these rules is now managed by the below application:-
    https://xyz.com/ip-whitelister
  */
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
