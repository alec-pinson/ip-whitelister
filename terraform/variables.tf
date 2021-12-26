variable "tenant_id" {
  description = "Azure tenant ID"
  type        = string
}

variable "subscription_id" {
  description = "Azure subscription ID"
  type        = string
}

variable "name" {
  description = "Name used for resources"
  type        = string
}

variable "service_principal_id" {
  description = "Object ID for the service principal used by the app to update the resources"
  type        = string
}
