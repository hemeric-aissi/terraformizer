"""Conversion statique et prudente des modèles CloudFormation."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import yaml

from terraformizer.detectors.base import Detector, slugify
from terraformizer.detectors.python_boto3 import _dynamodb, _hcl, _literal, _Raw, _snake, _tags
from terraformizer.models import Finding

_TYPES = {
    "AWS::EC2::Instance": "aws_instance",
    "AWS::S3::Bucket": "aws_s3_bucket",
    "AWS::EC2::VPC": "aws_vpc",
    "AWS::EC2::Subnet": "aws_subnet",
    "AWS::EC2::SecurityGroup": "aws_security_group",
    "AWS::IAM::Role": "aws_iam_role",
    "AWS::Lambda::Function": "aws_lambda_function",
    "AWS::DynamoDB::Table": "aws_dynamodb_table",
    "AWS::SQS::Queue": "aws_sqs_queue",
    "AWS::SNS::Topic": "aws_sns_topic",
    "AWS::RDS::DBInstance": "aws_db_instance",
}

_FIELDS = {
    "aws_instance": {
        "ImageId": "ami",
        "InstanceType": "instance_type",
        "KeyName": "key_name",
        "SubnetId": "subnet_id",
        "SecurityGroupIds": "vpc_security_group_ids",
        "UserData": "user_data_base64",
        "IamInstanceProfile": "iam_instance_profile",
        "Monitoring": "monitoring",
        "EbsOptimized": "ebs_optimized",
        "DisableApiTermination": "disable_api_termination",
    },
    "aws_s3_bucket": {"BucketName": "bucket", "ObjectLockEnabled": "object_lock_enabled"},
    "aws_vpc": {
        "CidrBlock": "cidr_block",
        "EnableDnsSupport": "enable_dns_support",
        "EnableDnsHostnames": "enable_dns_hostnames",
        "InstanceTenancy": "instance_tenancy",
    },
    "aws_subnet": {
        "VpcId": "vpc_id",
        "CidrBlock": "cidr_block",
        "AvailabilityZone": "availability_zone",
        "MapPublicIpOnLaunch": "map_public_ip_on_launch",
        "Ipv6CidrBlock": "ipv6_cidr_block",
        "AssignIpv6AddressOnCreation": "assign_ipv6_address_on_creation",
    },
    "aws_security_group": {
        "GroupName": "name",
        "GroupDescription": "description",
        "VpcId": "vpc_id",
    },
    "aws_iam_role": {
        "RoleName": "name",
        "Path": "path",
        "Description": "description",
        "MaxSessionDuration": "max_session_duration",
        "PermissionsBoundary": "permissions_boundary",
    },
    "aws_lambda_function": {
        "FunctionName": "function_name",
        "Runtime": "runtime",
        "Handler": "handler",
        "Role": "role",
        "Timeout": "timeout",
        "MemorySize": "memory_size",
        "Description": "description",
        "Architectures": "architectures",
        "PackageType": "package_type",
        "Layers": "layers",
        "KmsKeyArn": "kms_key_arn",
    },
    "aws_dynamodb_table": {
        "TableName": "name",
        "BillingMode": "billing_mode",
        "DeletionProtectionEnabled": "deletion_protection_enabled",
    },
    "aws_sqs_queue": {
        "QueueName": "name",
        "VisibilityTimeout": "visibility_timeout_seconds",
        "MessageRetentionPeriod": "message_retention_seconds",
        "DelaySeconds": "delay_seconds",
        "MaximumMessageSize": "max_message_size",
        "ReceiveMessageWaitTimeSeconds": "receive_wait_time_seconds",
        "FifoQueue": "fifo_queue",
        "ContentBasedDeduplication": "content_based_deduplication",
        "KmsMasterKeyId": "kms_master_key_id",
    },
    "aws_sns_topic": {
        "TopicName": "name",
        "DisplayName": "display_name",
        "FifoTopic": "fifo_topic",
        "ContentBasedDeduplication": "content_based_deduplication",
        "KmsMasterKeyId": "kms_master_key_id",
    },
    "aws_db_instance": {
        "DBInstanceIdentifier": "identifier",
        "DBInstanceClass": "instance_class",
        "Engine": "engine",
        "EngineVersion": "engine_version",
        "AllocatedStorage": "allocated_storage",
        "DBName": "db_name",
        "MasterUsername": "username",
        "MasterUserPassword": "password",
        "VPCSecurityGroups": "vpc_security_group_ids",
        "DBSubnetGroupName": "db_subnet_group_name",
        "MultiAZ": "multi_az",
        "StorageType": "storage_type",
        "Port": "port",
        "PubliclyAccessible": "publicly_accessible",
        "StorageEncrypted": "storage_encrypted",
        "BackupRetentionPeriod": "backup_retention_period",
        "DeletionProtection": "deletion_protection",
    },
}


class _TemplateLoader(yaml.SafeLoader):
    """Charge les balises CloudFormation sans constructeur exécutable."""


def _intrinsic(loader: _TemplateLoader, tag: str, node: yaml.Node) -> dict[str, Any]:
    """Préserve les balises comme données ordinaires."""
    if isinstance(node, yaml.ScalarNode):
        value = loader.construct_scalar(node)
    elif isinstance(node, yaml.SequenceNode):
        value = loader.construct_sequence(node)
    else:
        value = loader.construct_mapping(node)
    return {tag if tag in ("Ref", "Condition") else f"Fn::{tag}": value}


_TemplateLoader.add_multi_constructor("!", _intrinsic)


class CloudFormationDetector(Detector):
    """Détecte les ressources et traduit les références entre ressources."""

    name = "cloudformation"
    extensions = (".yaml", ".yml", ".json", ".template")

    def detect(self, path: Path, content: str) -> list[Finding]:
        """Charge un modèle sans alias YAML et retourne ses ressources connues ou non mappées."""
        if not self.handles(path):
            return []
        try:
            # Rejeter les alias avant chargement empêche leur expansion exponentielle.
            if any(isinstance(token, yaml.AliasToken) for token in yaml.scan(content)):
                return []
            template = yaml.load(content, Loader=_TemplateLoader)
        except (yaml.YAMLError, ValueError, TypeError, RecursionError):
            return []
        if not isinstance(template, dict) or not (
            "AWSTemplateFormatVersion" in template or "Resources" in template
        ):
            return []
        resources = template.get("Resources", {})
        if not isinstance(resources, dict):
            return []
        logical_types = {
            logical: (
                _TYPES.get(resource["Type"]) if isinstance(resource.get("Type"), str) else None
            )
            for logical, resource in resources.items()
            if isinstance(logical, str) and isinstance(resource, dict)
        }
        parameters = template.get("Parameters", {})
        findings = []
        for logical, resource in resources.items():
            if not isinstance(logical, str) or not isinstance(resource, dict):
                continue
            source_type = resource.get("Type")
            tf_type = _TYPES.get(source_type) if isinstance(source_type, str) else None
            notes: list[str] = []

            def reference(target: str, attribute: str | None = None) -> dict[str, str]:
                if target.startswith("AWS::"):
                    notes.append(f"TODO : fournir la valeur du pseudo-paramètre {target}.")
                    return _Raw(f"var.{slugify(target.replace('::', '_'))}")
                mapped_type = logical_types.get(target)
                if mapped_type:
                    field = {
                        "Arn": "arn",
                        "PublicIp": "public_ip",
                        "PrivateIp": "private_ip",
                        "PublicDnsName": "public_dns",
                        "PrivateDnsName": "private_dns",
                        "DNSName": "bucket_domain_name",
                        "DomainName": "bucket_domain_name",
                        "RegionalDomainName": "bucket_regional_domain_name",
                        "Endpoint.Address": "address",
                        "Endpoint.Port": "port",
                        "QueueName": "name",
                        "Name": "name",
                        "GroupId": "id",
                        "VpcId": "id",
                    }.get(
                        attribute,
                        slugify(_snake(attribute.replace(".", "_"))) if attribute else "id",
                    )
                    if attribute is None and mapped_type == "aws_sns_topic":
                        field = "arn"
                    if attribute and attribute not in (
                        "Arn",
                        "PublicIp",
                        "PrivateIp",
                        "PublicDnsName",
                        "PrivateDnsName",
                        "DNSName",
                        "DomainName",
                        "RegionalDomainName",
                        "Endpoint.Address",
                        "Endpoint.Port",
                        "QueueName",
                        "Name",
                        "GroupId",
                        "VpcId",
                    ):
                        notes.append(f"TODO : vérifier l'attribut GetAtt {target}.{attribute}.")
                    notes.append(
                        f"TODO : vérifier l'approximation de la référence CloudFormation {target}."
                    )
                    return _Raw(f"{mapped_type}.{slugify(target)}.{field}")
                if isinstance(parameters, dict) and target in parameters and attribute is None:
                    notes.append(f"TODO : déclarer la variable du paramètre {target}.")
                    return _Raw(f"var.{slugify(target)}")
                notes.append(
                    f"TODO : référence CloudFormation introuvable ou non mappée : {target}."
                )
                suffix = slugify(_snake(attribute.replace(".", "_"))) if attribute else "id"
                return _Raw(f"aws_RESOURCE.{slugify(target)}.{suffix}")

            def resolve(value: Any) -> Any:
                if isinstance(value, _Raw):
                    return value
                if isinstance(value, list):
                    return [resolve(item) for item in value]
                if not isinstance(value, dict):
                    return value
                if len(value) == 1 and isinstance(next(iter(value)), str):
                    key, item = next(iter(value.items()))
                    if key == "Ref" and isinstance(item, str):
                        return reference(item)
                    if key == "Fn::GetAtt":
                        parts = item.split(".", 1) if isinstance(item, str) else item
                        if (
                            isinstance(parts, list)
                            and len(parts) == 2
                            and all(isinstance(part, str) for part in parts)
                        ):
                            return reference(parts[0], parts[1])
                    if key == "Fn::Sub":
                        substitutions = {}
                        text = item
                        if isinstance(item, list) and len(item) == 2:
                            text, substitutions = item
                        if isinstance(text, str) and isinstance(substitutions, dict):
                            notes.append("TODO : vérifier l'approximation de Fn::Sub.")

                            def replace(match: re.Match[str]) -> Any:
                                token = match.group(1)
                                if token.startswith("!"):
                                    return "${" + token[1:] + "}"
                                if token in substitutions:
                                    resolved = resolve(substitutions[token])
                                    if isinstance(resolved, (str, int, float)):
                                        return str(resolved)
                                    replacement = _hcl(resolved)
                                    if not isinstance(resolved, _Raw):
                                        notes.append(
                                            f"TODO : substitution complexe non convertie : {token}."
                                        )
                                        replacement = f"var.{slugify(token)}"
                                else:
                                    parts = token.split(".", 1)
                                    replacement = reference(
                                        parts[0], parts[1] if len(parts) == 2 else None
                                    )["__raw__"]
                                return _Raw(f"tostring({replacement})")

                            pieces = []
                            cursor = 0
                            for match in re.finditer(r"\$\{([^}]+)\}", text):
                                pieces.append(text[cursor : match.start()])
                                pieces.append(replace(match))
                                cursor = match.end()
                            pieces.append(text[cursor:])
                            return _Raw(f'join("", {_hcl(pieces)})')
                    if key == "Fn::Join" and isinstance(item, list) and len(item) == 2:
                        return _Raw(f"join({_hcl(resolve(item[0]))}, {_hcl(resolve(item[1]))})")
                    if key == "Fn::Base64":
                        return _Raw(f"base64encode({_hcl(resolve(item))})")
                    if key == "Condition" or key.startswith("Fn::") or key == "Ref":
                        notes.append(f"TODO : fonction intrinsèque non prise en charge : {key}.")
                        return _Raw(f"var.{slugify(key, 'intrinsic')}")
                return _literal({key: resolve(item) for key, item in value.items()}, notes)

            if tf_type is None:
                findings.append(
                    Finding(
                        provider="aws",
                        tf_type="UNMAPPED",
                        name=slugify(logical),
                        attributes={},
                        source_file=path,
                        line=self._line(content, logical),
                        original=self._original(resource),
                        confidence=0.0,
                        notes=[f"TODO : type CloudFormation non pris en charge : {source_type}."],
                    )
                )
                continue
            properties = resource.get("Properties", {})
            if not isinstance(properties, dict):
                properties = {}
                notes.append("TODO : bloc Properties non analysable.")
            try:
                values = resolve(_literal(properties, notes, logical))
            except RecursionError:
                values = {}
                notes.append("TODO : structure YAML récursive ou trop profonde non convertie.")
            attributes: dict[str, Any] = {}
            for source, value in values.items():
                if source in _FIELDS[tf_type]:
                    attributes[_FIELDS[tf_type][source]] = value
                elif source == "Tags":
                    attributes["tags"] = _tags(value, notes)
                elif tf_type == "aws_security_group" and source in (
                    "SecurityGroupIngress",
                    "SecurityGroupEgress",
                ):
                    direction = "ingress" if source.endswith("Ingress") else "egress"
                    attributes[direction] = self._rules(value, notes)
                elif tf_type == "aws_iam_role" and source == "AssumeRolePolicyDocument":
                    attributes["assume_role_policy"] = (
                        _Raw(f"jsonencode({_hcl(value)})")
                        if isinstance(value, dict) and "__raw__" not in value
                        else value
                    )
                elif tf_type == "aws_dynamodb_table" and source in (
                    "AttributeDefinitions",
                    "KeySchema",
                    "ProvisionedThroughput",
                    "GlobalSecondaryIndexes",
                    "LocalSecondaryIndexes",
                    "StreamSpecification",
                ):
                    continue
                elif tf_type == "aws_lambda_function" and source == "Environment":
                    if isinstance(value, dict) and "Variables" in value:
                        attributes["environment"] = [{"variables": _Raw(_hcl(value["Variables"]))}]
                    else:
                        notes.append("TODO : Environment non converti.")
                elif tf_type == "aws_lambda_function" and source == "Code":
                    if isinstance(value, dict) and "__raw__" not in value:
                        for key, target in (
                            ("S3Bucket", "s3_bucket"),
                            ("S3Key", "s3_key"),
                            ("S3ObjectVersion", "s3_object_version"),
                            ("ImageUri", "image_uri"),
                        ):
                            if key in value:
                                attributes[target] = value[key]
                        if "ZipFile" in value:
                            notes.append("TODO : fournir une archive pour le code Lambda inline.")
                        for key in value.keys() - {
                            "S3Bucket",
                            "S3Key",
                            "S3ObjectVersion",
                            "ImageUri",
                            "ZipFile",
                        }:
                            notes.append(f"TODO : propriété Code non prise en charge : {key}.")
                    else:
                        notes.append("TODO : Code Lambda dynamique non converti.")
                elif tf_type == "aws_sqs_queue" and source == "RedrivePolicy":
                    attributes["redrive_policy"] = _Raw(f"jsonencode({_hcl(value)})")
                else:
                    notes.append(f"TODO : propriété CloudFormation non prise en charge : {source}.")
            if tf_type == "aws_dynamodb_table":
                _dynamodb(values, attributes, notes)
            for metadata in ("Condition", "DeletionPolicy", "UpdateReplacePolicy", "DependsOn"):
                if metadata in resource:
                    notes.append(f"TODO : vérifier la directive CloudFormation {metadata}.")
            import_id = None
            if tf_type in (
                "aws_s3_bucket",
                "aws_iam_role",
                "aws_lambda_function",
                "aws_dynamodb_table",
                "aws_db_instance",
            ):
                import_id = next(
                    (
                        attributes[key]
                        for key in ("bucket", "name", "function_name", "identifier")
                        if isinstance(attributes.get(key), str)
                    ),
                    None,
                )
            findings.append(
                Finding(
                    provider="aws",
                    tf_type=tf_type,
                    name=slugify(logical),
                    attributes=attributes,
                    source_file=path,
                    line=self._line(content, logical),
                    original=self._original(resource),
                    import_id=import_id,
                    confidence=0.65 if notes else 0.95,
                    notes=notes,
                )
            )
        return findings

    @staticmethod
    def _original(resource: dict[str, Any]) -> str:
        """Préserve une représentation sans échouer sur les alias YAML récursifs."""
        try:
            return json.dumps(resource, ensure_ascii=False, default=str)
        except (ValueError, RecursionError):
            return repr(resource)

    @staticmethod
    def _line(content: str, logical: str) -> int:
        """Retrouve au mieux la ligne du nom logique."""
        for index, line in enumerate(content.splitlines(), 1):
            if re.search(rf'["\']?{re.escape(logical)}["\']?\s*:', line):
                return index
        return 1

    @staticmethod
    def _rules(value: Any, notes: list[str]) -> list[dict[str, Any]]:
        """Traduit les règles réseau en blocs ingress ou egress."""
        if not isinstance(value, list):
            notes.append("TODO : règles de groupe de sécurité dynamiques non converties.")
            return []
        rules = []
        for rule in value:
            if not isinstance(rule, dict):
                notes.append("TODO : règle de groupe de sécurité non convertie.")
                continue
            converted = {}
            for source, item in rule.items():
                if source in ("IpProtocol", "FromPort", "ToPort", "Description"):
                    converted[
                        {
                            "IpProtocol": "protocol",
                            "FromPort": "from_port",
                            "ToPort": "to_port",
                            "Description": "description",
                        }[source]
                    ] = item
                elif source in (
                    "CidrIp",
                    "CidrIpv6",
                    "SourceSecurityGroupId",
                    "DestinationSecurityGroupId",
                    "SourcePrefixListId",
                    "DestinationPrefixListId",
                ):
                    target = {
                        "CidrIp": "cidr_blocks",
                        "CidrIpv6": "ipv6_cidr_blocks",
                        "SourceSecurityGroupId": "security_groups",
                        "DestinationSecurityGroupId": "security_groups",
                        "SourcePrefixListId": "prefix_list_ids",
                        "DestinationPrefixListId": "prefix_list_ids",
                    }[source]
                    converted.setdefault(target, []).append(item)
                else:
                    notes.append(f"TODO : propriété de règle non prise en charge : {source}.")
            converted.setdefault("from_port", 0)
            converted.setdefault("to_port", 0)
            rules.append(converted)
        return rules
