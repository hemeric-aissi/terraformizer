#!/usr/bin/env bash
aws ec2 run-instances \
  --image-id ami-example \
  --instance-type t3.micro \
  --security-group-ids sg-example-one sg-example-two \
  --user-data file://bootstrap.sh
aws s3 mb s3://my-bucket-prod
gcloud compute instances create web --zone europe-west1-b --machine-type e2-small --image-family debian-12 --image-project debian-cloud
gcloud compute firewall-rules create allow-web --network default --allow tcp:22,tcp:80 --source-ranges 10.0.0.0/8
az group create -n rg-demo -l westeurope
az storage account create -n stdemo -g rg-demo --sku Standard_GRS
