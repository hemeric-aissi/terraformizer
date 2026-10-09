"""Détection statique des créations de ressources avec AWS CLI."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from terraformizer.detectors._bash import (
    BashDetector,
    commands,
    file_expression,
    finding,
    flags,
    items,
    scalar,
    shorthand,
    typed_value,
)
from terraformizer.models import Finding

# Type, nom CLI, champs CLI → Terraform, attributs requis, import par nom.
AWS_COMMANDS: dict[tuple[str, str], tuple[str, str, dict[str, str], tuple[str, ...], bool]] = {
    ("ec2", "run-instances"): (
        "aws_instance",
        "tag-specifications",
        {
            "image-id": "ami",
            "instance-type": "instance_type",
            "key-name": "key_name",
            "subnet-id": "subnet_id",
            "security-group-ids": "vpc_security_group_ids",
            "iam-instance-profile": "iam_instance_profile",
            "user-data": "user_data",
        },
        ("ami", "instance_type"),
        False,
    ),
    ("s3", "mb"): ("aws_s3_bucket", "bucket", {}, ("bucket",), True),
    ("s3api", "create-bucket"): (
        "aws_s3_bucket",
        "bucket",
        {"bucket": "bucket"},
        ("bucket",),
        True,
    ),
    ("ec2", "create-security-group"): (
        "aws_security_group",
        "group-name",
        {"group-name": "name", "description": "description", "vpc-id": "vpc_id"},
        ("name", "description"),
        False,
    ),
    ("ec2", "create-vpc"): (
        "aws_vpc",
        "cidr-block",
        {"cidr-block": "cidr_block", "instance-tenancy": "instance_tenancy"},
        ("cidr_block",),
        False,
    ),
    ("ec2", "create-subnet"): (
        "aws_subnet",
        "cidr-block",
        {
            "cidr-block": "cidr_block",
            "vpc-id": "vpc_id",
            "availability-zone": "availability_zone",
            "ipv6-cidr-block": "ipv6_cidr_block",
        },
        ("cidr_block", "vpc_id"),
        False,
    ),
    ("iam", "create-role"): (
        "aws_iam_role",
        "role-name",
        {
            "role-name": "name",
            "assume-role-policy-document": "assume_role_policy",
            "description": "description",
            "path": "path",
            "max-session-duration": "max_session_duration",
        },
        ("name", "assume_role_policy"),
        True,
    ),
    ("iam", "create-user"): (
        "aws_iam_user",
        "user-name",
        {"user-name": "name", "path": "path"},
        ("name",),
        True,
    ),
    ("iam", "create-policy"): (
        "aws_iam_policy",
        "policy-name",
        {
            "policy-name": "name",
            "policy-document": "policy",
            "description": "description",
            "path": "path",
        },
        ("name", "policy"),
        False,
    ),
    ("rds", "create-db-instance"): (
        "aws_db_instance",
        "db-instance-identifier",
        {
            "db-instance-identifier": "identifier",
            "db-instance-class": "instance_class",
            "engine": "engine",
            "engine-version": "engine_version",
            "master-username": "username",
            "master-user-password": "password",
            "manage-master-user-password": "manage_master_user_password",
            "allocated-storage": "allocated_storage",
            "db-name": "db_name",
            "db-subnet-group-name": "db_subnet_group_name",
            "vpc-security-group-ids": "vpc_security_group_ids",
            "publicly-accessible": "publicly_accessible",
            "multi-az": "multi_az",
            "storage-type": "storage_type",
            "storage-encrypted": "storage_encrypted",
        },
        ("identifier", "instance_class", "engine", "allocated_storage", "username"),
        True,
    ),
    ("lambda", "create-function"): (
        "aws_lambda_function",
        "function-name",
        {
            "function-name": "function_name",
            "runtime": "runtime",
            "role": "role",
            "handler": "handler",
            "description": "description",
            "timeout": "timeout",
            "memory-size": "memory_size",
            "zip-file": "filename",
            "package-type": "package_type",
        },
        ("function_name", "role"),
        True,
    ),
    ("dynamodb", "create-table"): (
        "aws_dynamodb_table",
        "table-name",
        {"table-name": "name", "billing-mode": "billing_mode"},
        ("name", "hash_key", "attribute"),
        True,
    ),
    ("sqs", "create-queue"): (
        "aws_sqs_queue",
        "queue-name",
        {"queue-name": "name"},
        ("name",),
        False,
    ),
    ("sns", "create-topic"): (
        "aws_sns_topic",
        "name",
        {"name": "name"},
        ("name",),
        False,
    ),
    ("ecr", "create-repository"): (
        "aws_ecr_repository",
        "repository-name",
        {"repository-name": "name", "image-tag-mutability": "image_tag_mutability"},
        ("name",),
        True,
    ),
    ("ecs", "create-cluster"): (
        "aws_ecs_cluster",
        "cluster-name",
        {"cluster-name": "name"},
        ("name",),
        True,
    ),
    ("eks", "create-cluster"): (
        "aws_eks_cluster",
        "name",
        {"name": "name", "role-arn": "role_arn", "kubernetes-version": "version"},
        ("name", "role_arn", "vpc_config"),
        True,
    ),
    ("kms", "create-key"): (
        "aws_kms_key",
        "description",
        {
            "description": "description",
            "key-usage": "key_usage",
            "key-spec": "customer_master_key_spec",
            "multi-region": "multi_region",
            "policy": "policy",
        },
        (),
        False,
    ),
    ("logs", "create-log-group"): (
        "aws_cloudwatch_log_group",
        "log-group-name",
        {
            "log-group-name": "name",
            "kms-key-id": "kms_key_id",
            "retention-in-days": "retention_in_days",
        },
        ("name",),
        True,
    ),
}


def _entries(value: Any) -> list[dict[str, Any]]:
    """Lit une liste JSON ou la notation abrégée AWS."""
    if isinstance(value, list) and len(value) == 1:
        value = value[0]
    if isinstance(value, str) and value.startswith("["):
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, list) else []
        except json.JSONDecodeError:
            return []
    return [shorthand(part) for part in (value if isinstance(value, list) else [value])]


def _object(value: Any) -> dict[str, Any]:
    """Lit un objet JSON ou les paramètres abrégés d'une option AWS."""
    if isinstance(value, str) and value.startswith("{"):
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, dict) else {}
        except json.JSONDecodeError:
            return {}
    return shorthand(value)


class BashAWSDetector(BashDetector):
    """Convertit les commandes de création AWS CLI reconnues."""

    name = "bash_aws"

    def detect(self, path: Path, content: str) -> list[Finding]:
        """Retourne les ressources AWS, avec les limites de conversion."""
        results: list[Finding] = []
        for command in commands(content, "aws"):
            # Les options globales sont également autorisées avant le service.
            words = command.words[1:]
            while words and words[0].split("=")[0] in (
                "--profile",
                "--region",
                "--output",
                "--no-cli-pager",
            ):
                words = words[1:] if "=" in words[0] or words[0] == "--no-cli-pager" else words[2:]
            if len(words) < 2:
                continue
            spec = AWS_COMMANDS.get((words[0], words[1]))
            if spec is None:
                continue
            values, positional = flags(words[2:])
            tf_type, name_flag, mapping, required, import_by_name = spec
            attrs = {
                target: typed_value(target, values[source])
                for source, target in mapping.items()
                if source in values
            }
            known = set(mapping)
            notes: list[str] = []
            for field in ("vpc_security_group_ids",):
                if field in attrs:
                    attrs[field] = items(attrs[field])
            for field in ("user_data", "assume_role_policy", "policy"):
                if field in attrs:
                    attrs[field] = file_expression(attrs[field])
            if tf_type == "aws_s3_bucket" and words[0] == "s3" and positional:
                attrs["bucket"] = positional[0].removeprefix("s3://").rstrip("/")
                values["bucket"] = attrs["bucket"]
                known.add("bucket")
            if tf_type == "aws_instance":
                if "iam_instance_profile" in attrs:
                    profile = shorthand(attrs["iam_instance_profile"])
                    if "Name" in profile:
                        attrs["iam_instance_profile"] = profile["Name"]
                    elif "Arn" in profile:
                        attrs["iam_instance_profile"] = profile["Arn"].rsplit("/", 1)[-1]
                for count in ("count", "min-count", "max-count"):
                    if count in values:
                        known.add(count)
                        notes.append("Nombre d'instances à vérifier : une ressource est proposée.")
                if "tag-specifications" in values:
                    known.add("tag-specifications")
                    notes.append("Tags AWS à transcrire manuellement.")
            if tf_type == "aws_lambda_function" and "filename" in attrs:
                attrs["filename"] = str(attrs["filename"]).removeprefix("fileb://")
            if tf_type == "aws_db_instance" and not (
                attrs.get("password") or attrs.get("manage_master_user_password")
            ):
                notes.append("Attribut requis absent : password ou manage_master_user_password")
            if tf_type == "aws_lambda_function":
                if "code" in values:
                    known.add("code")
                    config = _object(values["code"])
                    for source, target in (
                        ("S3Bucket", "s3_bucket"),
                        ("S3Key", "s3_key"),
                        ("S3ObjectVersion", "s3_object_version"),
                        ("ImageUri", "image_uri"),
                    ):
                        if source in config:
                            attrs[target] = config[source]
                if attrs.get("package_type") != "Image":
                    for attribute in ("runtime", "handler"):
                        if not attrs.get(attribute):
                            notes.append(f"Attribut requis absent : {attribute}")
                if not any(attrs.get(key) for key in ("filename", "s3_bucket", "image_uri")):
                    notes.append("Attribut requis absent : filename, s3_bucket ou image_uri")
            if tf_type == "aws_dynamodb_table":
                self._dynamodb(values, attrs, known)
                if attrs.get("billing_mode") != "PAY_PER_REQUEST":
                    for attribute in ("read_capacity", "write_capacity"):
                        if not attrs.get(attribute):
                            notes.append(f"Attribut requis absent : {attribute}")
            if tf_type == "aws_eks_cluster" and "resources-vpc-config" in values:
                known.add("resources-vpc-config")
                config = _object(values["resources-vpc-config"])
                block: dict[str, Any] = {}
                for source, target in (
                    ("subnetIds", "subnet_ids"),
                    ("securityGroupIds", "security_group_ids"),
                ):
                    if source in config:
                        block[target] = items(config[source])
                for source, target in (
                    ("endpointPublicAccess", "endpoint_public_access"),
                    ("endpointPrivateAccess", "endpoint_private_access"),
                ):
                    if source in config:
                        block[target] = scalar(config[source])
                attrs["vpc_config"] = [block]
                if not block.get("subnet_ids"):
                    notes.append("Attribut requis absent : vpc_config.subnet_ids")
            if tf_type == "aws_ecr_repository" and "image-scanning-configuration" in values:
                known.add("image-scanning-configuration")
                config = _object(values["image-scanning-configuration"])
                attrs["image_scanning_configuration"] = [
                    {"scan_on_push": scalar(config.get("scanOnPush", "false"))}
                ]
            if tf_type in ("aws_sqs_queue", "aws_sns_topic") and "attributes" in values:
                known.add("attributes")
                config = _object(values["attributes"])
                attribute_mapping = (
                    {
                        "DelaySeconds": "delay_seconds",
                        "MaximumMessageSize": "max_message_size",
                        "MessageRetentionPeriod": "message_retention_seconds",
                        "ReceiveMessageWaitTimeSeconds": "receive_wait_time_seconds",
                        "VisibilityTimeout": "visibility_timeout_seconds",
                        "FifoQueue": "fifo_queue",
                        "ContentBasedDeduplication": "content_based_deduplication",
                        "KmsMasterKeyId": "kms_master_key_id",
                        "Policy": "policy",
                        "RedrivePolicy": "redrive_policy",
                    }
                    if tf_type == "aws_sqs_queue"
                    else {
                        "DisplayName": "display_name",
                        "FifoTopic": "fifo_topic",
                        "ContentBasedDeduplication": "content_based_deduplication",
                        "KmsMasterKeyId": "kms_master_key_id",
                        "Policy": "policy",
                    }
                )
                for source, value in config.items():
                    if source in attribute_mapping:
                        attrs[attribute_mapping[source]] = typed_value(
                            attribute_mapping[source], value
                        )
                    else:
                        notes.append(f"Flag non mappé : --attributes.{source}")
            name = values.get(name_flag) or attrs.get("bucket") or tf_type
            import_id = str(name) if import_by_name and values.get(name_flag) else None
            results.append(
                finding(
                    path=path,
                    command=command,
                    provider="aws",
                    tf_type=tf_type,
                    name=name,
                    attributes=attrs,
                    values=values,
                    known=known,
                    ignored={"profile", "region", "output", "no-cli-pager"},
                    required=required,
                    import_id=import_id,
                    notes=notes,
                )
            )
        return results

    @staticmethod
    def _dynamodb(values: dict[str, Any], attrs: dict[str, Any], known: set[str]) -> None:
        """Traduit le schéma de clés et le débit provisionné DynamoDB."""
        for key in ("attribute-definitions", "key-schema", "provisioned-throughput"):
            if key in values:
                known.add(key)
        if "attribute-definitions" in values:
            attrs["attribute"] = [
                {"name": entry["AttributeName"], "type": entry["AttributeType"]}
                for entry in _entries(values["attribute-definitions"])
                if "AttributeName" in entry and "AttributeType" in entry
            ]
        if "key-schema" in values:
            for entry in _entries(values["key-schema"]):
                if entry.get("KeyType") in ("HASH", "RANGE") and "AttributeName" in entry:
                    attrs["hash_key" if entry["KeyType"] == "HASH" else "range_key"] = entry[
                        "AttributeName"
                    ]
        if "provisioned-throughput" in values:
            throughput = shorthand(values["provisioned-throughput"])
            for source, target in (
                ("ReadCapacityUnits", "read_capacity"),
                ("WriteCapacityUnits", "write_capacity"),
            ):
                if source in throughput:
                    attrs[target] = typed_value(target, throughput[source])
