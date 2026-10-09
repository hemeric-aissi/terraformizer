#!/usr/bin/env bash
set -euo pipefail

# terraform import 'aws_instance.aws_instance' '<ID_A_RENSEIGNER>'
terraform import 'aws_s3_bucket.my_bucket_prod' 'my-bucket-prod'
# terraform import 'google_compute_instance.web' '<ID_A_RENSEIGNER>'
# terraform import 'google_compute_firewall.allow_web' '<ID_A_RENSEIGNER>'
# terraform import 'azurerm_resource_group.rg_demo' '<ID_A_RENSEIGNER>'
# terraform import 'azurerm_storage_account.stdemo' '<ID_A_RENSEIGNER>'
# terraform import 'aws_instance.web_01' '<ID_A_RENSEIGNER>'
# terraform import 'aws_vpc.demovpc' '<ID_A_RENSEIGNER>'
# terraform import 'aws_subnet.demosubnet' '<ID_A_RENSEIGNER>'
terraform import 'aws_s3_bucket.archivebucket' 'demo-archive'
