// redis database
resource "azurerm_redis_cache" "testing" {
  name                = format("%s-redis-testing", var.name)
  resource_group_name = azurerm_resource_group.this.name
  location            = azurerm_resource_group.this.location
  capacity            = 2
  family              = "C"
  sku_name            = "standard"
  enable_non_ssl_port = true
  minimum_tls_version = "1.2"
}

output "redis_testing" {
  value = {
    subscription_id = var.subscription_id
    resource_group  = azurerm_redis_cache.testing.resource_group_name
    name            = azurerm_redis_cache.testing.name
  }
}

resource "azurerm_role_assignment" "redis_testing_access" {
  scope                = azurerm_redis_cache.testing.id
  role_definition_name = "Contributor"
  principal_id         = var.service_principal_id
}
