output "redis" {
  value = {
    host  = azurerm_redis_cache.this.hostname
    port  = azurerm_redis_cache.this.port
    token = azurerm_redis_cache.this.primary_access_key
  }
}

output "azure_frontdoor_policy" {
  value = {
    subscription_id = var.subscription_id
    resource_group  = azurerm_frontdoor_firewall_policy.this.resource_group_name
    policy_name     = azurerm_frontdoor_firewall_policy.this.name
  }
}
