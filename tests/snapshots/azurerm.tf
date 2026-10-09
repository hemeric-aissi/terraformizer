provider "azurerm" {
  features {}
}

data "azurerm_client_config" "current" {}

# Source : deploy.sh:10 (confiance 100%)
# Origine : az group create -n rg-demo -l westeurope
resource "azurerm_resource_group" "rg_demo" {
  name     = "rg-demo"
  location = "westeurope"
}

# Source : deploy.sh:11 (confiance 100%)
# Origine : az storage account create -n stdemo -g rg-demo --sku Standard_GRS
resource "azurerm_storage_account" "stdemo" {
  name                     = "stdemo"
  resource_group_name      = azurerm_resource_group.rg_demo.name
  location                 = azurerm_resource_group.rg_demo.location
  account_tier             = "Standard"
  account_replication_type = "GRS"
  account_kind             = "StorageV2"
}
