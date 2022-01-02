resource "azurerm_postgresql_server" "this" {
  name                = format("%s-pg-server", var.name)
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name

  administrator_login          = "psqladmin"
  administrator_login_password = random_password.postgres_password.result

  sku_name   = "B_Gen5_1"
  version    = "11"
  storage_mb = 5120

  backup_retention_days        = 7
  geo_redundant_backup_enabled = false
  auto_grow_enabled            = false

  public_network_access_enabled    = true
  ssl_enforcement_enabled          = true
  ssl_minimal_tls_version_enforced = "TLS1_2"
}

resource "random_password" "postgres_password" {
  length           = 16
  special          = true
  override_special = "_%@"
}

output "postgres" {
  value = {
    subscription_id = var.subscription_id
    resource_group  = azurerm_postgresql_server.this.resource_group_name
    name            = azurerm_postgresql_server.this.name
  }
}

resource "azurerm_role_assignment" "postgres_access" {
  scope                = azurerm_postgresql_server.this.id
  role_definition_name = "Contributor"
  principal_id         = var.service_principal_id
}
