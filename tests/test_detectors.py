"""Vérifier l'analyse statique des commandes Bash AWS, Google Cloud et Azure.

Entrées : scripts en mémoire ; sorties : assertions sur les ressources,
arguments, limites et échappements.
Sécurité : aucun accès cloud ni exécution des scripts analysés ; les appels
d'exécution interdits sont remplacés par un piège dans le test dédié.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from terraformizer.detectors._bash import BashDetector, _parse_flags, commands
from terraformizer.detectors.bash_aws import BashAWSDetector
from terraformizer.detectors.bash_az import BashAzDetector
from terraformizer.detectors.bash_gcloud import BashGcloudDetector

SOURCE = Path("infra.sh")


@pytest.mark.parametrize(
    "filename",
    [
        "infra.sh",
        "infra.bash",
        "infra.zsh",
        "infra.yml",
        "infra.yaml",
        "infra.mk",
        "Makefile",
        "Jenkinsfile",
        "Dockerfile",
    ],
)
def test_extensions(filename: str) -> None:
    """Tous les fichiers d'automatisation demandés sont pris en charge."""
    assert BashAWSDetector().handles(Path(filename))
    assert BashGcloudDetector().handles(Path(filename))
    assert BashAzDetector().handles(Path(filename))
    assert not BashAWSDetector().handles(Path("infra.py"))


def test_continuations_and_boundaries() -> None:
    """Les lignes d'origine restent exactes, y compris après continuation."""
    content = (
        "# préparation\n"
        "aws ec2 run-instances \\\n"
        ' --image-id ami-123 --instance-type "t3.micro" \\\n'
        " --security-group-ids sg-one sg-two --profile sandbox --region eu-west-1\n"
        "true && aws s3 mb s3://first || aws s3api create-bucket --bucket=second;"
        " aws iam create-user --user-name alice\n"
    )
    results = BashAWSDetector().detect(SOURCE, content)
    assert len(results) == 4
    instance = results[0]
    assert instance.line == 2
    assert instance.source_file == SOURCE
    assert instance.original == "\n".join(content.splitlines()[1:4])
    assert instance.attributes["vpc_security_group_ids"] == ["sg-one", "sg-two"]
    assert instance.attributes["ami"] == "ami-123"
    assert instance.confidence == 1.0
    assert instance.import_id is None
    assert [result.import_id for result in results[1:]] == ["first", "second", "alice"]
    assert all(result.line == 5 for result in results[1:])


@pytest.mark.parametrize(
    "source",
    [
        "BUCKET=$(aws s3 mb s3://demo)",
        "BUCKET=`aws s3 mb s3://demo`",
        'echo "$(aws s3 mb s3://demo)"',
        "  - aws s3 mb s3://demo",
        "\t@aws s3 mb s3://demo",
        "RUN aws s3 mb s3://demo",
        "sh 'aws s3 mb s3://demo'",
        'sh "aws s3 mb s3://demo"',
        "sh('aws s3 mb s3://demo')",
        "  run: aws s3 mb s3://demo",
        '  run: "aws s3 mb s3://demo"',
    ],
)
def test_shell_wrappers(source: str) -> None:
    """Les substitutions, recettes et enveloppes courantes sont détectées."""
    result = BashAWSDetector().detect(SOURCE, source)
    assert len(result) == 1
    assert result[0].attributes == {"bucket": "demo"}
    assert not result[0].notes


@pytest.mark.parametrize(
    "source",
    [
        "# aws s3 mb s3://demo",
        "# true && aws s3 mb s3://demo",
        'echo "aws s3 mb s3://demo"',
        'echo "true && aws s3 mb s3://demo"',
        "echo ok # && aws s3 mb s3://demo",
        "notaws s3 mb s3://demo",
        "awsx s3 mb s3://demo",
        "aws s3 ls",
    ],
)
def test_non_commands_are_ignored(source: str) -> None:
    """Les commentaires, chaînes et opérations non créatrices sont ignorés."""
    assert BashAWSDetector().detect(SOURCE, source) == []


def test_fallback_unknown_and_missing_flags() -> None:
    """Une commande mal citée reste visible, avec des avertissements français."""
    result = BashAWSDetector().detect(
        SOURCE, "aws ec2 run-instances --mystery=yes --key-name 'broken"
    )[0]
    assert result.confidence < 1
    assert any("analyse de secours" in note for note in result.notes)
    assert "Flag non mappé : --mystery" in result.notes
    assert "Attribut requis absent : ami" in result.notes
    assert "Attribut requis absent : instance_type" in result.notes


def test_aws_file_expressions_and_profile() -> None:
    """Les fichiers deviennent du HCL brut sans lecture ni exécution."""
    instance = BashAWSDetector().detect(
        SOURCE,
        "aws --profile=dev --region eu-west-1 ec2 run-instances --image-id ami-test "
        "--instance-type=t3.micro --user-data file://bootstrap.sh "
        "--iam-instance-profile Name=runner --security-group-ids=sg-a,sg-b",
    )[0]
    assert instance.attributes["user_data"] == {"__raw__": 'file("bootstrap.sh")'}
    assert instance.attributes["iam_instance_profile"] == "runner"
    assert instance.attributes["vpc_security_group_ids"] == ["sg-a", "sg-b"]
    assert not instance.notes
    role = BashAWSDetector().detect(
        SOURCE,
        "aws iam create-role --role-name worker --assume-role-policy-document file://trust.json",
    )[0]
    assert role.attributes["assume_role_policy"] == {"__raw__": 'file("trust.json")'}
    assert role.import_id == "worker"
    policy = BashAWSDetector().detect(
        SOURCE,
        "aws iam create-policy --policy-name access --policy-document file://access.json",
    )[0]
    assert policy.attributes["policy"] == {"__raw__": 'file("access.json")'}
    assert policy.import_id is None
    assert not policy.notes


@pytest.mark.parametrize(
    ("command", "tf_type", "import_id"),
    [
        (
            "ec2 create-security-group --group-name web --description web --vpc-id vpc-real",
            "aws_security_group",
            None,
        ),
        ("ec2 create-vpc --cidr-block 10.0.0.0/16", "aws_vpc", None),
        ("ec2 create-subnet --vpc-id vpc-real --cidr-block 10.0.1.0/24", "aws_subnet", None),
        ("iam create-user --user-name alice", "aws_iam_user", "alice"),
        (
            "iam create-policy --policy-name access --policy-document file://access.json",
            "aws_iam_policy",
            None,
        ),
        (
            "rds create-db-instance --db-instance-identifier db --db-instance-class db.t3.micro "
            "--engine postgres --allocated-storage 20 --publicly-accessible "
            "--master-username admin --manage-master-user-password",
            "aws_db_instance",
            "db",
        ),
        (
            "lambda create-function --function-name worker --runtime python3.12 --role arn:aws:iam::1:"
            "role/worker --handler main.handler --zip-file fileb://app.zip",
            "aws_lambda_function",
            "worker",
        ),
        (
            "dynamodb create-table --table-name events --billing-mode PAY_PER_REQUEST "
            "--attribute-definitions AttributeName=id,AttributeType=S "
            "--key-schema AttributeName=id,KeyType=HASH",
            "aws_dynamodb_table",
            "events",
        ),
        ("sqs create-queue --queue-name events", "aws_sqs_queue", None),
        ("sns create-topic --name events", "aws_sns_topic", None),
        ("ecr create-repository --repository-name app", "aws_ecr_repository", "app"),
        ("ecs create-cluster --cluster-name apps", "aws_ecs_cluster", "apps"),
        (
            "eks create-cluster --name apps --role-arn arn:aws:iam::1:role/apps "
            "--resources-vpc-config subnetIds=subnet-a,subnet-b,securityGroupIds=sg-a",
            "aws_eks_cluster",
            "apps",
        ),
        ("kms create-key --description encryption", "aws_kms_key", None),
        (
            "logs create-log-group --log-group-name /app/service",
            "aws_cloudwatch_log_group",
            "/app/service",
        ),
    ],
)
def test_aws_resource_table(command: str, tf_type: str, import_id: str | None) -> None:
    """Toutes les familles AWS sont reconnues sans inventer d'identifiant."""
    result = BashAWSDetector().detect(SOURCE, f"aws {command}")[0]
    assert result.tf_type == tf_type
    assert result.import_id == import_id
    assert not result.notes


def test_dynamodb_multiple_keys_and_eks_lists() -> None:
    """Les arguments de listes AWS conservent tous leurs éléments."""
    table = BashAWSDetector().detect(
        SOURCE,
        "aws dynamodb create-table --table-name events "
        "--attribute-definitions AttributeName=id,AttributeType=S "
        "AttributeName=date,AttributeType=N "
        "--key-schema AttributeName=id,KeyType=HASH AttributeName=date,KeyType=RANGE "
        "--provisioned-throughput ReadCapacityUnits=5,WriteCapacityUnits=10",
    )[0]
    assert table.attributes["attribute"] == [
        {"name": "id", "type": "S"},
        {"name": "date", "type": "N"},
    ]
    assert table.attributes["hash_key"] == "id"
    assert table.attributes["range_key"] == "date"
    assert table.attributes["read_capacity"] == 5
    cluster = BashAWSDetector().detect(
        SOURCE,
        "aws eks create-cluster --name demo --role-arn arn:role "
        "--resources-vpc-config subnetIds=subnet-a,subnet-b,securityGroupIds=sg-a,"
        "endpointPublicAccess=false",
    )[0]
    assert cluster.attributes["vpc_config"] == [
        {
            "subnet_ids": ["subnet-a", "subnet-b"],
            "security_group_ids": ["sg-a"],
            "endpoint_public_access": False,
        }
    ]


def test_aws_json_options() -> None:
    """Les mêmes options AWS sont acceptées dans leur représentation JSON."""
    table = BashAWSDetector().detect(
        SOURCE,
        "aws dynamodb create-table --table-name events --billing-mode PAY_PER_REQUEST "
        """--attribute-definitions '[{"AttributeName":"id","AttributeType":"S"}]' """
        """--key-schema '[{"AttributeName":"id","KeyType":"HASH"}]'""",
    )[0]
    assert table.attributes["attribute"] == [{"name": "id", "type": "S"}]
    assert table.attributes["hash_key"] == "id"
    ecr = BashAWSDetector().detect(
        SOURCE,
        "aws ecr create-repository --repository-name app "
        """--image-scanning-configuration '{"scanOnPush":true}'""",
    )[0]
    assert ecr.attributes["image_scanning_configuration"] == [{"scan_on_push": True}]
    queue = BashAWSDetector().detect(
        SOURCE,
        "aws sqs create-queue --queue-name work "
        """--attributes '{"VisibilityTimeout":"30","FifoQueue":"true"}'""",
    )[0]
    assert queue.attributes["visibility_timeout_seconds"] == 30
    assert queue.attributes["fifo_queue"] is True
    assert queue.import_id is None


def test_multiple_commands_in_continuations_keep_line_numbers() -> None:
    """Chaque commande garde sa ligne réelle au sein d'une ligne logique."""
    results = BashAWSDetector().detect(
        SOURCE,
        "aws s3 mb s3://one && \\\n  aws s3 mb s3://two && \\\n  aws s3 mb s3://three",
    )
    assert [result.line for result in results] == [1, 2, 3]
    results = BashAWSDetector().detect(
        SOURCE,
        "aws ec2 run-instances \\\n"
        " --image-id ami-test --instance-type t3.micro; aws s3 mb s3://second",
    )
    assert [result.line for result in results] == [1, 2]


def test_gcloud_instance_nested_blocks() -> None:
    """Disque, famille d'image et réseau sont des blocs Terraform imbriqués."""
    result = BashGcloudDetector().detect(
        SOURCE,
        "gcloud compute instances create web --machine-type=e2-small "
        "--zone europe-west1-b --image-family debian-12 --image-project debian-cloud "
        "--boot-disk-size 20GB --network apps --subnet private --no-address "
        "--project sandbox --quiet --format=json",
    )[0]
    assert result.attributes["boot_disk"] == {
        "initialize_params": {
            "image": "debian-cloud/debian-12",
            "size": 20,
        }
    }
    assert result.attributes["network_interface"] == {"network": "apps", "subnetwork": "private"}
    assert not result.notes
    assert result.import_id is None
    assert "project" not in result.attributes


def test_gcloud_image_and_firewall() -> None:
    """Les images explicites et les plages de ports sont préservées."""
    instance = BashGcloudDetector().detect(
        SOURCE,
        "gcloud compute instances create web --machine-type e2-small "
        "--zone us-central1-a --image ubuntu-v1 --image-project ubuntu-cloud",
    )[0]
    assert instance.attributes["boot_disk"]["initialize_params"]["image"] == (
        "ubuntu-cloud/ubuntu-v1"
    )
    firewall = BashGcloudDetector().detect(
        SOURCE,
        "gcloud compute firewall-rules create web --network apps "
        "--allow tcp:80,tcp:443,tcp:8000-9000,udp:53,icmp --source-ranges 10.0.0.0/8",
    )[0]
    assert firewall.attributes["allow"] == [
        {"protocol": "tcp", "ports": ["80", "443", "8000-9000"]},
        {"protocol": "udp", "ports": ["53"]},
        {"protocol": "icmp"},
    ]
    assert firewall.attributes["source_ranges"] == ["10.0.0.0/8"]


@pytest.mark.parametrize(
    ("command", "tf_type"),
    [
        ("compute networks create apps --subnet-mode custom", "google_compute_network"),
        ("storage buckets create gs://demo --location EU", "google_storage_bucket"),
        (
            "container clusters create apps --zone europe-west1-b --num-nodes 2",
            "google_container_cluster",
        ),
        (
            "sql instances create db --database-version POSTGRES_15 --region europe-west1 "
            "--tier db-custom-1-3840",
            "google_sql_database_instance",
        ),
        ("pubsub topics create events", "google_pubsub_topic"),
        ("iam service-accounts create runner --display-name Runner", "google_service_account"),
    ],
)
def test_gcloud_resource_table(command: str, tf_type: str) -> None:
    """Les autres familles Google Cloud sont reconnues."""
    result = BashGcloudDetector().detect(SOURCE, f"gcloud {command}")[0]
    assert result.tf_type == tf_type
    assert not result.notes
    if tf_type == "google_compute_network":
        assert result.attributes["auto_create_subnetworks"] is False
    if tf_type == "google_sql_database_instance":
        assert result.attributes["settings"] == {"tier": "db-custom-1-3840"}
    if tf_type == "google_service_account":
        assert result.attributes["account_id"] == "runner"
    if tf_type == "google_storage_bucket":
        assert result.import_id == "demo"


def test_azure_group_references_and_storage() -> None:
    """Les alias courts et les références HCL aux groupes sont convertis."""
    group, storage = BashAzDetector().detect(
        SOURCE,
        "az group create -n My-Group -l westeurope\n"
        "az storage account create -n mystorage -g My-Group --sku Premium_ZRS",
    )
    assert group.attributes == {"name": "My-Group", "location": "westeurope"}
    assert storage.attributes["resource_group_name"] == {
        "__raw__": "azurerm_resource_group.my_group.name"
    }
    assert storage.attributes["location"] == {"__raw__": "azurerm_resource_group.my_group.location"}
    assert storage.attributes["account_tier"] == "Premium"
    assert storage.attributes["account_replication_type"] == "ZRS"
    assert not storage.notes
    assert storage.import_id is None


def test_azure_vm_safe_defaults_and_missing_network() -> None:
    """Les blocs VM requis sont présents ; les IDs manquants ne sont pas inventés."""
    result = BashAzDetector().detect(SOURCE, "az vm create -n web -g apps")[0]
    assert result.attributes["os_disk"] == [
        {"caching": "ReadWrite", "storage_account_type": "Standard_LRS"}
    ]
    assert result.attributes["source_image_reference"][0]["publisher"] == "Canonical"
    assert result.attributes["network_interface_ids"] == []
    assert any("TODO" in note for note in result.notes)
    assert any("admin_ssh_key" in note for note in result.notes)
    assert result.confidence < 1
    assert result.import_id is None


def test_azure_vm_explicit_inputs() -> None:
    """Les images URN, clés publiques et IDs NIC explicites sont conservés."""
    nic = (
        "/subscriptions/real/resourceGroups/apps/providers/Microsoft.Network/networkInterfaces/web"
    )
    result = BashAzDetector().detect(
        SOURCE,
        f"az vm create -n web -g apps --nics {nic} "
        "--image Canonical:offer:sku:version --admin-username deploy "
        "--ssh-key-values ~/.ssh/id_ed25519.pub -l northeurope",
    )[0]
    assert result.attributes["network_interface_ids"] == [nic]
    assert result.attributes["source_image_reference"][0]["version"] == "version"
    assert result.attributes["admin_ssh_key"] == [
        {"username": "deploy", "public_key": {"__raw__": 'file("~/.ssh/id_ed25519.pub")'}}
    ]
    assert result.attributes["location"] == "northeurope"
    assert not result.notes


def test_azure_multiple_nic_ids() -> None:
    """Le flag --nics accepte plusieurs IDs, comme les autres listes CLI."""
    prefix = (
        "/subscriptions/real/resourceGroups/apps/providers/Microsoft.Network/networkInterfaces/"
    )
    ids = [f"{prefix}web", f"{prefix}private"]
    vm = BashAzDetector().detect(
        SOURCE,
        f"az vm create -n web -g apps --nics {' '.join(ids)} --ssh-key-values public.pub",
    )[0]
    assert vm.attributes["network_interface_ids"] == ids
    assert not vm.notes


def test_azure_vnet_aks_keyvault() -> None:
    """VNet, AKS et Key Vault ont leurs blocs et références Azure nécessaires."""
    vnet, aks, vault = BashAzDetector().detect(
        SOURCE,
        "az network vnet create -n apps -g rg --address-prefixes 10.0.0.0/16 "
        "10.1.0.0/16 --subnet-name private --subnet-prefix 10.0.1.0/24\n"
        "az aks create -n apps -g rg --node-count 2 --node-vm-size Standard_D2_v2\n"
        "az keyvault create -n secrets -g rg --sku premium",
    )
    assert vnet.attributes["address_space"] == ["10.0.0.0/16", "10.1.0.0/16"]
    assert vnet.attributes["subnet"] == [{"name": "private", "address_prefixes": ["10.0.1.0/24"]}]
    assert aks.attributes["default_node_pool"] == [
        {"name": "default", "node_count": 2, "vm_size": "Standard_D2_v2"}
    ]
    assert aks.attributes["identity"] == [{"type": "SystemAssigned"}]
    assert vault.attributes["tenant_id"] == {
        "__raw__": "data.azurerm_client_config.current.tenant_id"
    }
    assert vault.attributes["sku_name"] == "premium"
    assert any("data azurerm_client_config" in note for note in vault.notes)


@pytest.mark.parametrize(
    ("detector", "source"),
    [
        (BashAWSDetector(), "aws s3api create-bucket --bucket demo --unknown value"),
        (BashGcloudDetector(), "gcloud pubsub topics create demo --unknown value"),
        (BashAzDetector(), "az group create -n demo -l eu --unknown value"),
    ],
)
def test_unknown_flags_lower_confidence(detector: BashDetector, source: str) -> None:
    """Chaque fournisseur signale les flags qu'il ne sait pas convertir."""
    result = detector.detect(SOURCE, source)[0]
    assert result.confidence < 1
    assert "Flag non mappé : --unknown" in result.notes


def test_missing_names_and_dynamic_values() -> None:
    """Aucun identifiant d'import fictif n'est produit à partir d'une variable."""
    for detector, source in (
        (BashAWSDetector(), "aws iam create-user"),
        (BashGcloudDetector(), "gcloud pubsub topics create"),
        (BashAzDetector(), "az group create"),
    ):
        result = detector.detect(SOURCE, source)[0]
        assert result.import_id is None
        assert any("Attribut requis absent" in note for note in result.notes)
    dynamic = BashAWSDetector().detect(SOURCE, 'aws s3 mb "s3://$BUCKET"')[0]
    assert dynamic.import_id is None
    assert any("Valeur shell dynamique" in note for note in dynamic.notes)


def test_boolean_flags_do_not_eat_positional_names() -> None:
    """Les flags booléens placés avant les noms n'absorbent pas les noms."""
    topic = BashGcloudDetector().detect(SOURCE, "gcloud pubsub topics create --quiet events")[0]
    assert topic.attributes["name"] == "events"
    assert not topic.notes
    group = BashAzDetector().detect(
        SOURCE, "az group create --only-show-errors -n apps -l westeurope"
    )[0]
    assert not group.notes


def test_ignored_dynamic_flags_do_not_change_confidence() -> None:
    """Les options globales ignorées n'affectent ni conversion ni import."""
    bucket = BashAWSDetector().detect(
        SOURCE, "aws s3 mb s3://demo --region $AWS_REGION --profile $AWS_PROFILE"
    )[0]
    assert bucket.import_id == "demo"
    assert bucket.confidence == 1
    topic = BashGcloudDetector().detect(
        SOURCE, "gcloud pubsub topics create events --project $PROJECT --format $FORMAT"
    )[0]
    assert topic.confidence == 1


def test_raw_hcl_file_paths_escape_templates_and_quotes() -> None:
    """Les chemins ne peuvent pas injecter de code ou de templates HCL."""
    instance = BashAWSDetector().detect(
        SOURCE,
        """aws ec2 run-instances --image-id ami-safe --instance-type t3.micro """
        """--user-data 'file://x${var.secret}%{if true}"\\file.txt'""",
    )[0]
    assert instance.attributes["user_data"] == {
        "__raw__": 'file("x$${var.secret}%%{if true}\\"\\\\file.txt")'
    }
    vm = BashAzDetector().detect(
        SOURCE,
        """az vm create -n web -g '1 invalid.${payload}' """
        """--ssh-key-values 'keys/${var.secret}%{if true}.pub'""",
    )[0]
    assert vm.attributes["resource_group_name"] == {
        "__raw__": "azurerm_resource_group.resource_1_invalid___payload.name"
    }
    assert vm.attributes["admin_ssh_key"][0]["public_key"] == {
        "__raw__": 'file("keys/$${var.secret}%%{if true}.pub")'
    }


@pytest.mark.parametrize("name", ["123", "true", "false"])
def test_string_attributes_never_become_numbers_or_booleans(name: str) -> None:
    """Les noms et identifiants restent des chaînes même lorsqu'ils semblent typés."""
    bucket = BashAWSDetector().detect(SOURCE, f"aws s3api create-bucket --bucket {name}")[0]
    assert bucket.attributes["bucket"] == name
    assert isinstance(bucket.attributes["bucket"], str)
    instance = BashAWSDetector().detect(
        SOURCE, f"aws ec2 run-instances --image-id {name} --instance-type {name}"
    )[0]
    assert instance.attributes["ami"] == name
    assert instance.attributes["instance_type"] == name
    group = BashAzDetector().detect(SOURCE, f"az group create -n {name} -l {name}")[0]
    assert group.attributes["name"] == name
    assert group.attributes["location"] == name
    service_account = BashGcloudDetector().detect(
        SOURCE, f"gcloud iam service-accounts create {name} --display-name {name}"
    )[0]
    assert service_account.attributes["display_name"] == name


def test_single_pipes_background_and_inline_comments() -> None:
    """Les frontières non citées et les commentaires terminent la commande."""
    for separator in ("|", "&"):
        bucket = BashAWSDetector().detect(
            SOURCE, f"aws s3 mb s3://demo {separator} echo --unknown value"
        )[0]
        assert not bucket.notes
        assert bucket.attributes == {"bucket": "demo"}
    bucket = BashAWSDetector().detect(SOURCE, "aws s3 mb s3://demo # ; aws s3 mb s3://commented")
    assert len(bucket) == 1
    quoted = BashAWSDetector().detect(SOURCE, """aws iam create-user --user-name 'a|b&c'""")[0]
    assert quoted.attributes["name"] == "a|b&c"


def test_parse_flags_alias_and_split_fallback() -> None:
    """Le helper attendu et le repli str.split restent disponibles."""
    assert _parse_flags(["--name=x", "--quiet"]) == ({"name": "x", "quiet": True}, [])
    command = commands("aws iam create-user --user-name 'broken", "aws")[0]
    assert command.words == ["aws", "iam", "create-user", "--user-name", "'broken"]


def test_source_is_never_executed(monkeypatch: pytest.MonkeyPatch) -> None:
    """Une substitution malveillante reste une simple chaîne de caractères."""
    import os
    import subprocess

    def forbidden(*args: object, **kwargs: object) -> None:
        """Faire échouer le test pour tout appel d'exécution, quels que soient ses arguments."""
        raise AssertionError("Le détecteur ne doit jamais lancer un processus.")

    monkeypatch.setattr(os, "system", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    results = BashAWSDetector().detect(
        SOURCE,
        "aws ec2 run-instances --image-id $(touch forbidden) "
        "--instance-type t3.micro --user-data file://missing-file",
    )
    assert len(results) == 1
    assert results[0].attributes["user_data"] == {"__raw__": 'file("missing-file")'}
    assert commands("# aucun code", "aws") == []
