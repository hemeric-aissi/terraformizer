"""Convertit statiquement les appels de création boto3 en ressources candidates.

Entrées : chemin et texte Python ; sorties : objets Finding avec attributs Terraform,
identifiant d'import éventuel et TODO pour les approximations. L'AST est lu sans
importer le programme, exécuter ses appels ni contacter le cloud. Les expressions
dynamiques deviennent des variables à compléter, jamais du code Python évalué.
Les marqueurs HCL internes restent distincts des dictionnaires issus de la source.
"""

from __future__ import annotations

import ast
import json
import math
import re
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from terraformizer.detectors.base import Detector, slugify
from terraformizer.models import Finding

# Méthode boto3 -> (service attendu, type Terraform) : sélection, pas schéma AWS complet.
_RESOURCES = {
    "run_instances": ("ec2", "aws_instance"),
    "create_bucket": ("s3", "aws_s3_bucket"),
    "create_security_group": ("ec2", "aws_security_group"),
    "create_vpc": ("ec2", "aws_vpc"),
    "create_subnet": ("ec2", "aws_subnet"),
    "create_role": ("iam", "aws_iam_role"),
    "create_user": ("iam", "aws_iam_user"),
    "create_db_instance": ("rds", "aws_db_instance"),
    "create_function": ("lambda", "aws_lambda_function"),
    "create_table": ("dynamodb", "aws_dynamodb_table"),
    "create_queue": ("sqs", "aws_sqs_queue"),
    "create_topic": ("sns", "aws_sns_topic"),
    "create_repository": ("ecr", "aws_ecr_repository"),
    # ECS par défaut ; detect distingue EKS grâce au service du client.
    "create_cluster": ("ecs", "aws_ecs_cluster"),
    "create_log_group": ("logs", "aws_cloudwatch_log_group"),
}

# Méthode -> {argument AWS: attribut Terraform} pour les correspondances directes.
# Les blocs imbriqués, tags et politiques sont traités à part ; l'inconnu devient TODO.
_FIELDS = {
    "run_instances": {
        "ImageId": "ami",
        "InstanceType": "instance_type",
        "KeyName": "key_name",
        "SubnetId": "subnet_id",
        "SecurityGroupIds": "vpc_security_group_ids",
        "UserData": "user_data",
        "Monitoring": "monitoring",  # Enabled est extrait du dictionnaire AWS.
        "IamInstanceProfile": "iam_instance_profile",  # Terraform attend le nom, pas l'ARN.
        "EbsOptimized": "ebs_optimized",
    },
    "create_bucket": {"Bucket": "bucket", "ObjectLockEnabledForBucket": "object_lock_enabled"},
    "create_security_group": {
        "GroupName": "name",
        "Description": "description",
        "VpcId": "vpc_id",
    },
    "create_vpc": {
        "CidrBlock": "cidr_block",
        "InstanceTenancy": "instance_tenancy",
        "AmazonProvidedIpv6CidrBlock": "assign_generated_ipv6_cidr_block",
    },
    "create_subnet": {
        "VpcId": "vpc_id",
        "CidrBlock": "cidr_block",
        "AvailabilityZone": "availability_zone",
        "Ipv6CidrBlock": "ipv6_cidr_block",
    },
    "create_role": {
        "RoleName": "name",
        "AssumeRolePolicyDocument": "assume_role_policy",  # Un dictionnaire exige jsonencode.
        "Path": "path",
        "Description": "description",
        "MaxSessionDuration": "max_session_duration",
        "PermissionsBoundary": "permissions_boundary",
    },
    "create_user": {
        "UserName": "name",
        "Path": "path",
        "PermissionsBoundary": "permissions_boundary",
    },
    "create_db_instance": {
        "DBInstanceIdentifier": "identifier",
        "DBInstanceClass": "instance_class",
        "Engine": "engine",
        "EngineVersion": "engine_version",
        "AllocatedStorage": "allocated_storage",
        "DBName": "db_name",
        "MasterUsername": "username",
        "MasterUserPassword": "password",
        "VpcSecurityGroupIds": "vpc_security_group_ids",
        "DBSubnetGroupName": "db_subnet_group_name",
        "MultiAZ": "multi_az",
        "StorageType": "storage_type",
        "PubliclyAccessible": "publicly_accessible",
        "Port": "port",
        "BackupRetentionPeriod": "backup_retention_period",
        "StorageEncrypted": "storage_encrypted",
        "DeletionProtection": "deletion_protection",
    },
    "create_function": {
        "FunctionName": "function_name",
        "Runtime": "runtime",
        "Role": "role",
        "Handler": "handler",
        "Description": "description",
        "Timeout": "timeout",
        "MemorySize": "memory_size",
        "Architectures": "architectures",
        "PackageType": "package_type",
        "Layers": "layers",
        "KMSKeyArn": "kms_key_arn",
    },
    "create_table": {
        "TableName": "name",
        "BillingMode": "billing_mode",
        "DeletionProtectionEnabled": "deletion_protection_enabled",
    },
    "create_queue": {"QueueName": "name"},
    "create_topic": {"Name": "name"},
    "create_repository": {
        "repositoryName": "name",
        "imageTagMutability": "image_tag_mutability",
    },
    # Union ECS/EKS : clusterName appartient à ECS, name et roleArn à EKS.
    "create_cluster": {"clusterName": "name", "name": "name", "roleArn": "role_arn"},
    "create_log_group": {
        "logGroupName": "name",
        "kmsKeyId": "kms_key_id",
        "logGroupClass": "log_group_class",
    },
}


def _snake(value: str) -> str:
    """Sépare les mots CamelCase avant de normaliser leur casse.

    Args:
        value: Nom de champ à convertir, éventuellement avec un sigle ou des chiffres.

    Returns:
        Nom en minuscules avec underscores aux frontières reconnues par les deux regex.

    La première regex sépare un mot capitalisé après un caractère ; la seconde
    sépare une majuscule après une minuscule ou un chiffre. Les sigles consécutifs
    ne sont pas découpés lettre par lettre ; chaîne vide et séparateurs restent admis.
    """
    value = re.sub(r"(.)([A-Z][a-z]+)", r"\1_\2", value)
    return re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", value).lower()


class _Raw(dict[str, str]):
    """Marque une expression HCL construite en interne, non une valeur de la source.

    La sous-classe dict accepte la reconstruction par dataclasses.asdict ; JSON
    conserve sa clé __raw__, mais pas son identité de classe. Ce format reste lisible
    par le générateur. Il ne constitue pas une validation d'une expression arbitraire.
    """

    def __init__(self, expression: str | dict[str, str] | Iterable[tuple[str, str]]) -> None:
        """Accepte le texte HCL ou les paires utilisées pour reconstruire le dict.

        Args:
            expression: Texte interne, dictionnaire ou itérable de paires clé/valeur.
        """
        super().__init__({"__raw__": expression} if isinstance(expression, str) else expression)


def _literal(value: Any, notes: list[str] | None = None, label: str = "literal") -> Any:
    """Neutralise les valeurs source pouvant être confondues avec du HCL interne.

    Args:
        value: Valeur littérale ou marqueur _Raw déjà produit par le détecteur.
        notes: Liste de TODO enrichie sur place, si fournie.
        label: Contexte servant à nommer les variables de remplacement.

    Returns:
        Valeur récursivement normalisée ou _Raw pointant vers une variable.

    Un dict source contenant __raw__ est remplacé pour éviter une injection HCL.
    Pour les tags, cette clé reste une donnée grâce à une sérialisation sûre.
    Ensembles triés, tuples en listes et scalaires non représentables (dont
    NaN/infini) sont normalisés ; seuls les _Raw internes passent tels quels.
    """
    if isinstance(value, _Raw):
        return value
    if isinstance(value, dict):
        if "__raw__" in value:
            if label.lower() == "tags":
                tags = {key: _literal(item, notes, str(key)) for key, item in value.items()}
                return _Raw(_hcl(tags))
            variable = slugify(f"{label}_reserved_raw")
            if notes is not None:
                notes.append(f"TODO : dictionnaire source avec clé réservée __raw__ : {label}.")
            return _Raw(f"var.{variable}")
        return {key: _literal(item, notes, str(key)) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_literal(item, notes, label) for item in value]
    if isinstance(value, set):
        return [_literal(item, notes, label) for item in sorted(value, key=repr)]
    if (
        value is None
        or isinstance(value, (str, bool, int))
        or isinstance(value, float)
        and math.isfinite(value)
    ):
        return value
    variable = slugify(f"{label}_value")
    if notes is not None:
        notes.append(
            f"TODO : valeur de type {type(value).__name__} non représentable en HCL ; "
            f"fournir var.{variable}."
        )
    return _Raw(f"var.{variable}")


def _hcl(value: Any) -> str:
    """Sérialise des valeurs normalisées sans activer leurs interpolations source.

    Args:
        value: Scalaire JSON, liste, dict ou expression interne _Raw.

    Returns:
        Texte HCL : seul un _Raw à clé unique __raw__ sort sans guillemets.

    Les séquences ${ et %{ des chaînes sont échappées pour rester littérales.
    Les autres scalaires passent par JSON ; normaliser la source avec _literal
    avant cet appel évite notamment les nombres non finis et objets arbitraires.
    """
    if isinstance(value, _Raw) and set(value) == {"__raw__"}:
        return value["__raw__"]
    if isinstance(value, dict):
        return "{" + ", ".join(f"{_hcl(k)} = {_hcl(v)}" for k, v in value.items()) + "}"
    if isinstance(value, list):
        return "[" + ", ".join(_hcl(item) for item in value) + "]"
    if isinstance(value, str):
        value = value.replace("${", "$${").replace("%{", "%%{")
    return json.dumps(value, ensure_ascii=False)


def _tags(value: Any, notes: list[str]) -> Any:
    """Convertit les tags sans transformer une clé réservée en expression source.

    Args:
        value: Dict normalisé ou liste AWS de paires Key/Value.
        notes: Liste enrichie pour les tags incomplets ou dynamiques.

    Returns:
        Dict de tags (dernier doublon gagnant), _Raw sûr si __raw__ est une clé,
        ou valeur initiale avec TODO si sa forme n'est pas reconnue.
    """
    if isinstance(value, dict):
        return value
    if isinstance(value, list):
        result = {}
        for tag in value:
            if isinstance(tag, dict) and isinstance(tag.get("Key"), str) and "Value" in tag:
                result[tag["Key"]] = tag["Value"]
            else:
                notes.append("TODO : tag dynamique ou incomplet non converti.")
        return _Raw(_hcl(result)) if "__raw__" in result else result
    notes.append("TODO : vérifier les tags dynamiques.")
    return value


def _dynamodb(values: dict[str, Any], attributes: dict[str, Any], notes: list[str]) -> None:
    """Complète sur place les blocs DynamoDB que le simple renommage ne couvre pas.

    Args:
        values: Arguments AWS normalisés, éventuellement ceux d'un index secondaire.
        attributes: Attributs Terraform à enrichir : clés, capacités, index et flux.
        notes: TODO pour les éléments incomplets, dynamiques ou non pris en charge.

    Les clés HASH/RANGE deviennent hash_key/range_key ; les index réutilisent cette
    conversion. Les structures absentes sont ignorées, les listes partielles filtrées.
    StreamViewType suffit à déduire stream_enabled si StreamEnabled est absent.
    """
    definitions = values.get("AttributeDefinitions")
    if isinstance(definitions, list):
        attributes["attribute"] = [
            {"name": item["AttributeName"], "type": item["AttributeType"]}
            for item in definitions
            if isinstance(item, dict) and "AttributeName" in item and "AttributeType" in item
        ]
        if len(attributes["attribute"]) != len(definitions):
            notes.append("TODO : définition d'attribut DynamoDB incomplète.")
    elif definitions is not None:
        notes.append("TODO : AttributeDefinitions dynamique non converti.")
    schema = values.get("KeySchema")
    if isinstance(schema, list):
        for key in schema:
            if (
                isinstance(key, dict)
                and key.get("KeyType") in ("HASH", "RANGE")
                and "AttributeName" in key
            ):
                attributes["hash_key" if key["KeyType"] == "HASH" else "range_key"] = key.get(
                    "AttributeName"
                )
            else:
                notes.append("TODO : clé DynamoDB non convertie.")
    elif schema is not None:
        notes.append("TODO : KeySchema dynamique non converti.")
    throughput = values.get("ProvisionedThroughput")
    if isinstance(throughput, dict) and "__raw__" not in throughput:
        for source, target in (
            ("ReadCapacityUnits", "read_capacity"),
            ("WriteCapacityUnits", "write_capacity"),
        ):
            if source in throughput:
                attributes[target] = throughput[source]
    elif throughput is not None:
        notes.append("TODO : ProvisionedThroughput dynamique non converti.")
    for source, target in (
        ("GlobalSecondaryIndexes", "global_secondary_index"),
        ("LocalSecondaryIndexes", "local_secondary_index"),
    ):
        indexes = values.get(source)
        if indexes is None:
            continue
        if not isinstance(indexes, list):
            notes.append(f"TODO : {source} dynamique non converti.")
            continue
        converted_indexes = []
        for index in indexes:
            if not isinstance(index, dict) or "IndexName" not in index:
                notes.append(f"TODO : index {source} incomplet.")
                continue
            converted = {"name": index["IndexName"]}
            _dynamodb(
                {
                    key: item
                    for key, item in index.items()
                    if key in ("KeySchema", "ProvisionedThroughput")
                },
                converted,
                notes,
            )
            projection = index.get("Projection", {})
            if isinstance(projection, dict) and "ProjectionType" in projection:
                converted["projection_type"] = projection["ProjectionType"]
                if "NonKeyAttributes" in projection:
                    converted["non_key_attributes"] = projection["NonKeyAttributes"]
            else:
                notes.append(f"TODO : projection d'index {source} non convertie.")
            for key in index.keys() - {
                "IndexName",
                "KeySchema",
                "Projection",
                "ProvisionedThroughput",
            }:
                notes.append(f"TODO : propriété d'index non prise en charge : {key}.")
            converted_indexes.append(converted)
        attributes[target] = converted_indexes
    stream = values.get("StreamSpecification")
    if isinstance(stream, dict) and "__raw__" not in stream:
        attributes["stream_enabled"] = stream.get("StreamEnabled", "StreamViewType" in stream)
        if "StreamViewType" in stream:
            attributes["stream_view_type"] = stream["StreamViewType"]
    elif stream is not None:
        notes.append("TODO : StreamSpecification dynamique non converti.")


class PythonBoto3Detector(Detector):
    """Reconnaît les créations boto3 par AST, avec suivi approximatif des clients.

    Les alias importés, sessions et liaisons locales limitent les faux positifs ;
    un récepteur non identifié reste candidat avec TODO, pas preuve d'un appel AWS.
    """

    name = "python_boto3"
    extensions = (".py",)

    def detect(self, path: Path, content: str) -> list[Finding]:
        """Analyse les créations sans évaluer les expressions du programme.

        Args:
            path: Chemin de provenance et filtre d'extension, sans lecture du fichier.
            content: Texte Python à analyser avec ast.parse.

        Returns:
            Findings AWS, ou liste vide pour une source hors périmètre ou invalide.
            Les valeurs dynamiques deviennent var.* avec TODO ; les **kwargs et
            arguments positionnels de création ne sont pas développés. Le suivi
            des liaisons ne simule ni l'ordre d'exécution ni les branches Python.
        """
        if not self.handles(path) or not re.search(r"\bboto3\b|\bbotocore\b", content):
            return []
        try:
            tree = ast.parse(content)
        except SyntaxError:
            return []
        modules: set[str] = set()
        factories: dict[str, str] = {}
        foreign: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                modules.update(
                    alias.asname or alias.name.split(".")[0]
                    for alias in node.names
                    if alias.name.split(".")[0] in ("boto3", "botocore")
                )
                foreign.update(
                    alias.asname or alias.name.split(".")[0]
                    for alias in node.names
                    if alias.name.split(".")[0] not in ("boto3", "botocore")
                )
            elif isinstance(node, ast.ImportFrom) and node.module in (
                "boto3",
                "boto3.session",
                "botocore.session",
            ):
                factories.update(
                    {
                        alias.asname or alias.name: alias.name
                        for alias in node.names
                        if alias.name in ("client", "resource", "Session", "get_session")
                    }
                )
        parents = {
            child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)
        }

        def scopes(node: ast.AST) -> list[ast.AST]:
            """Ordonne les portées englobantes pour rechercher la liaison la plus proche.

            Args:
                node: Nœud de l'arbre analysé.

            Returns:
                Fonctions, classes et lambdas, de l'intérieur vers le module final.
                Cette approximation ne reproduit pas toutes les règles lexicales Python.
            """
            result = []
            while node in parents:
                node = parents[node]
                if isinstance(
                    node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)
                ):
                    result.append(node)
            return [*result, tree]

        # La portée fait partie de la clé pour ne pas confondre deux clients homonymes.
        clients: dict[tuple[ast.AST, str], str | None] = {}
        # Ces liaisons bloquent un candidat masqué par une valeur non reconnue.
        foreign_names: set[tuple[ast.AST, str]] = set()
        # Les noms de sessions et d'imports restent globaux à cette analyse approximative.
        sessions: set[str] = set()

        def factory(call: ast.AST) -> tuple[bool, str | None]:
            """Reconnaît une fabrique importée ou chaînée sans appeler boto3/botocore.

            Args:
                call: Nœud candidat, y compris une fabrique sur une session inline.

            Returns:
                Couple (reconnu, service) ; __session__ marque une session,
                None un service dynamique ou un appel non reconnu selon le booléen.
                Seul le nom de service littéral, positionnel ou service_name, est lu.
            """
            if not isinstance(call, ast.Call):
                return False, None
            function = call.func
            if isinstance(function, ast.Name):
                recognized = function.id in factories
                is_session = factories.get(function.id) in ("Session", "get_session")
            elif isinstance(function, ast.Attribute):
                root = function.value
                while isinstance(root, ast.Attribute):
                    root = root.value
                recognized = (isinstance(root, ast.Name) and root.id in modules | sessions) or (
                    isinstance(root, ast.Call) and factory(root)[0]
                )
                is_session = function.attr in ("Session", "get_session")
                recognized = recognized and function.attr in (
                    "client",
                    "resource",
                    "create_client",
                    "Session",
                    "get_session",
                )
            else:
                return False, None
            if not recognized:
                return False, None
            if is_session:
                return True, "__session__"
            service_node = (
                call.args[0]
                if call.args
                else next((kw.value for kw in call.keywords if kw.arg == "service_name"), None)
            )
            if isinstance(service_node, ast.Constant) and isinstance(service_node.value, str):
                return True, service_node.value
            return True, None

        for node in ast.walk(tree):
            if not isinstance(node, (ast.Assign, ast.AnnAssign)):
                continue
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            names = [ast.unparse(target) for target in targets]
            recognized, service = factory(node.value)
            for name in names:
                binding = (scopes(node)[0], name)
                if recognized:
                    clients[binding] = service
                    if service == "__session__":
                        sessions.add(name)
                elif isinstance(node.value, (ast.Constant, ast.Dict, ast.List, ast.Call)):
                    foreign_names.add(binding)
        findings = []
        for call in ast.walk(tree):
            if not isinstance(call, ast.Call) or not isinstance(call.func, ast.Attribute):
                continue
            method = call.func.attr
            if method not in _RESOURCES:
                continue
            receiver = ast.unparse(call.func.value)
            binding = next(
                (
                    (scope, receiver)
                    for scope in scopes(call)
                    if (scope, receiver) in clients or (scope, receiver) in foreign_names
                ),
                None,
            )
            receiver_root = call.func.value
            while isinstance(receiver_root, ast.Attribute):
                receiver_root = receiver_root.value
            if (
                binding in foreign_names
                or receiver in foreign
                or (isinstance(receiver_root, ast.Name) and receiver_root.id in foreign)
            ):
                continue
            recognized, direct_service = factory(call.func.value)
            if isinstance(call.func.value, ast.Call) and not recognized:
                continue
            service = clients.get(binding, direct_service if recognized else None)
            expected_service, tf_type = _RESOURCES[method]
            # La même méthode existe dans ECS et EKS : le client tranche, pas son nom.
            if method == "create_cluster" and service == "eks":
                tf_type = "aws_eks_cluster"
            elif service is not None and service != expected_service:
                continue
            notes: list[str] = []
            if binding not in clients and not recognized:
                notes.append("TODO : vérifier que cet appel utilise un client boto3.")

            def value(node: ast.AST, label: str = "literal") -> Any:
                """Conserve les littéraux sûrs et remplace les expressions par des variables.

                Args:
                    node: Expression d'argument, jamais exécutée par literal_eval.
                    label: Contexte transmis à la neutralisation des clés réservées.

                Returns:
                    Valeur normalisée ; les listes/tuples et dicts à clés textuelles
                    constantes restent partiellement convertibles malgré leurs éléments
                    dynamiques. Les autres expressions donnent un _Raw var.* avec TODO.
                """
                try:
                    return _literal(ast.literal_eval(node), notes, label)
                except (ValueError, TypeError):
                    if isinstance(node, (ast.List, ast.Tuple)):
                        return [value(item) for item in node.elts]
                    if isinstance(node, ast.Dict) and all(
                        isinstance(key, ast.Constant) and isinstance(key.value, str)
                        for key in node.keys
                    ):
                        return _literal(
                            {
                                key.value: value(item, key.value)
                                for key, item in zip(node.keys, node.values)
                            },
                            notes,
                            label,
                        )
                    expression = ast.unparse(node)
                    variable = slugify(expression, "value")
                    notes.append(
                        f"TODO : remplacer var.{variable} (expression Python : {expression})."
                    )
                    return _Raw(f"var.{variable}")

            kwargs: dict[str, Any] = {}
            for keyword in call.keywords:
                if keyword.arg is None:
                    notes.append(
                        "TODO : les arguments **kwargs ne sont pas analysables statiquement."
                    )
                else:
                    kwargs[keyword.arg] = value(keyword.value, keyword.arg)
            if call.args:
                notes.append("TODO : arguments positionnels de l'appel de création non convertis.")
            attributes = {}
            for source, item in kwargs.items():
                if source in _FIELDS[method]:
                    if method == "create_cluster" and (
                        (service == "ecs" and source in ("name", "roleArn"))
                        or (service == "eks" and source == "clusterName")
                    ):
                        notes.append(f"TODO : propriété du cluster non prise en charge : {source}.")
                        continue
                    target = _FIELDS[method][source]
                    if source == "Monitoring" and isinstance(item, dict):
                        item = item.get("Enabled", item)
                    elif source == "IamInstanceProfile" and isinstance(item, dict):
                        item = item.get("Name", item)
                        if isinstance(item, dict) and "Arn" in item:
                            notes.append("TODO : remplacer l'ARN du profil IAM par son nom.")
                    attributes[target] = item
                elif source in ("Tags", "tags"):
                    attributes["tags"] = _tags(item, notes)
                elif source == "TagSpecifications" and isinstance(item, list):
                    # Ne pas appliquer aux instances les tags de volumes créés en parallèle.
                    resource_kind = {
                        "run_instances": "instance",
                        "create_security_group": "security-group",
                        "create_vpc": "vpc",
                        "create_subnet": "subnet",
                    }.get(method)
                    for specification in item:
                        if (
                            isinstance(specification, dict)
                            and specification.get("ResourceType") == resource_kind
                        ):
                            attributes["tags"] = _tags(specification.get("Tags", []), notes)
                        else:
                            notes.append("TODO : TagSpecifications secondaire non converti.")
                elif method == "create_table" and source in (
                    "AttributeDefinitions",
                    "KeySchema",
                    "ProvisionedThroughput",
                    "GlobalSecondaryIndexes",
                    "LocalSecondaryIndexes",
                    "StreamSpecification",
                ):
                    continue
                elif method == "create_function" and source == "Environment":
                    if isinstance(item, dict) and "Variables" in item:
                        attributes["environment"] = [{"variables": _Raw(_hcl(item["Variables"]))}]
                    else:
                        notes.append("TODO : Environment dynamique non converti.")
                elif method == "create_function" and source == "Code":
                    if isinstance(item, dict):
                        for key, target in (
                            ("S3Bucket", "s3_bucket"),
                            ("S3Key", "s3_key"),
                            ("S3ObjectVersion", "s3_object_version"),
                            ("ImageUri", "image_uri"),
                        ):
                            if key in item:
                                attributes[target] = item[key]
                        if "ZipFile" in item or "__raw__" in item:
                            notes.append("TODO : fournir une archive Lambda via filename ou S3.")
                    else:
                        notes.append("TODO : Code Lambda non converti.")
                elif source in ("MinCount", "MaxCount") and item == 1:
                    # Un Finding représente une ressource ; les autres cardinalités exigent TODO.
                    continue
                else:
                    notes.append(f"TODO : propriété boto3 non prise en charge : {source}.")
            if method == "create_table":
                _dynamodb(kwargs, attributes, notes)
            if method == "create_cluster" and service is None:
                notes.append("TODO : service create_cluster inconnu ; ECS supposé, vérifier EKS.")
            if (
                method == "create_role"
                and isinstance(attributes.get("assume_role_policy"), dict)
                and "__raw__" not in attributes["assume_role_policy"]
            ):
                attributes["assume_role_policy"] = _Raw(
                    f"jsonencode({_hcl(attributes['assume_role_policy'])})"
                )
            tag_name = (
                attributes.get("tags", {}).get("Name")
                if isinstance(attributes.get("tags"), dict)
                else None
            )
            resource_name = next(
                (
                    attributes[key]
                    for key in ("name", "bucket", "identifier", "function_name")
                    if isinstance(attributes.get(key), str)
                ),
                tag_name if isinstance(tag_name, str) else f"{method}_{call.lineno}",
            )
            import_id = None
            if tf_type in (
                "aws_s3_bucket",
                "aws_iam_role",
                "aws_iam_user",
                "aws_db_instance",
                "aws_lambda_function",
                "aws_dynamodb_table",
                "aws_ecr_repository",
                "aws_cloudwatch_log_group",
            ) or (tf_type in ("aws_ecs_cluster", "aws_eks_cluster") and service in ("ecs", "eks")):
                import_id = next(
                    (
                        attributes[key]
                        for key in ("name", "bucket", "identifier", "function_name")
                        if isinstance(attributes.get(key), str)
                    ),
                    None,
                )
            findings.append(
                Finding(
                    provider="aws",
                    tf_type=tf_type,
                    name=slugify(resource_name),
                    attributes=attributes,
                    source_file=path,
                    line=call.lineno,
                    original=ast.get_source_segment(content, call) or ast.unparse(call),
                    import_id=import_id,
                    confidence=0.65 if notes else 0.95,
                    notes=notes,
                )
            )
        return findings
