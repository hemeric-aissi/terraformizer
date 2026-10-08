"""Exemple boto3 destiné à l'analyse statique, pas à l'exécution."""

from __future__ import annotations

import os

import boto3

ec2 = boto3.client("ec2")
ec2.run_instances(
    ImageId=os.environ["AMI"],
    InstanceType="t3.micro",
    MinCount=1,
    MaxCount=1,
    TagSpecifications=[
        {"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": "web-01"}]}
    ],
)
