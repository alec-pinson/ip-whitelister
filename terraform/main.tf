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
