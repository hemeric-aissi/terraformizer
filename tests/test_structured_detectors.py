"""Tests ciblés des détecteurs boto3 et CloudFormation."""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

import pytest

from terraformizer.detectors.cloudformation import CloudFormationDetector
from terraformizer.detectors.python_boto3 import PythonBoto3Detector


def test_python_literals_tags_and_import() -> None:
    source = """
import boto3
s3 = boto3.client('s3')
s3.create_bucket(Bucket='my-bucket')
ec2 = boto3.client('ec2')
ec2.run_instances(ImageId='ami-123', InstanceType='t3.micro', MinCount=1, MaxCount=1,
    TagSpecifications=[{'ResourceType': 'instance',
                        'Tags': [{'Key': 'Name', 'Value': 'Web Server'}]}])
"""
    bucket, instance = PythonBoto3Detector().detect(Path("main.py"), source)
    assert bucket.tf_type == "aws_s3_bucket"
    assert bucket.import_id == "my-bucket"
    assert bucket.attributes["bucket"] == "my-bucket"
    assert instance.name == "web_server"
    assert instance.attributes["tags"] == {"Name": "Web Server"}
    assert instance.attributes["ami"] == "ami-123"
    assert instance.import_id is None
    assert not instance.notes


def test_python_dynamic_nested_and_kwargs() -> None:
    source = """
import boto3
client = boto3.client('ec2')
client.run_instances(ImageId=config.ami, SecurityGroupIds=[group_id], **settings)
"""
    (finding,) = PythonBoto3Detector().detect(Path("app.py"), source)
    assert finding.attributes["ami"] == {"__raw__": "var.config_ami"}
    assert finding.attributes["vpc_security_group_ids"] == [{"__raw__": "var.group_id"}]
    assert any("**kwargs" in note for note in finding.notes)
    assert finding.confidence < 0.95
    assert "#" not in finding.attributes["vpc_security_group_ids"][0]["__raw__"]


def test_python_services_and_non_boto_calls() -> None:
    source = """
import boto3
session = boto3.Session()
eks = session.client('eks')
ecs = boto3.client('ecs')
other = object()
eks.create_cluster(name='kube', roleArn='role')
ecs.create_cluster(clusterName='containers')
other.create_bucket(Bucket='not-aws')
ecs.create_bucket(Bucket='wrong-service')
"""
    findings = PythonBoto3Detector().detect(Path("main.py"), source)
    assert [finding.tf_type for finding in findings] == ["aws_eks_cluster", "aws_ecs_cluster"]
    assert findings[0].attributes["role_arn"] == "role"
    assert [finding.import_id for finding in findings] == ["kube", "containers"]


@pytest.mark.parametrize("source", ["import boto3\nif (", "x.create_bucket(Bucket='x')"])
def test_python_ignored(source: str) -> None:
    assert PythonBoto3Detector().detect(Path("main.py"), source) == []


@pytest.mark.parametrize(
    ("method", "service", "arguments", "tf_type", "import_id"),
    [
        (
            "create_security_group",
            "ec2",
            "GroupName='web', Description='web'",
            "aws_security_group",
            None,
        ),
        ("create_vpc", "ec2", "CidrBlock='10.0.0.0/16'", "aws_vpc", None),
        ("create_subnet", "ec2", "VpcId='vpc-x', CidrBlock='10.0.1.0/24'", "aws_subnet", None),
        (
            "create_role",
            "iam",
            "RoleName='role', AssumeRolePolicyDocument='{}'",
            "aws_iam_role",
            "role",
        ),
        ("create_user", "iam", "UserName='user'", "aws_iam_user", "user"),
        ("create_db_instance", "rds", "DBInstanceIdentifier='db'", "aws_db_instance", "db"),
        ("create_function", "lambda", "FunctionName='fn'", "aws_lambda_function", "fn"),
        ("create_table", "dynamodb", "TableName='table'", "aws_dynamodb_table", "table"),
        ("create_queue", "sqs", "QueueName='queue'", "aws_sqs_queue", None),
        ("create_topic", "sns", "Name='topic'", "aws_sns_topic", None),
        ("create_repository", "ecr", "repositoryName='repo'", "aws_ecr_repository", "repo"),
        ("create_log_group", "logs", "logGroupName='logs'", "aws_cloudwatch_log_group", "logs"),
    ],
)
def test_python_creation_mapping(
    method: str,
    service: str,
    arguments: str,
    tf_type: str,
    import_id: str | None,
) -> None:
    source = f"import boto3\nclient = boto3.client('{service}')\nclient.{method}({arguments})"
    (finding,) = PythonBoto3Detector().detect(Path("main.py"), source)
    assert finding.tf_type == tf_type
    assert finding.import_id == import_id


def test_cloudformation_references_rules_and_tags() -> None:
    source = """
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  Network:
    Type: AWS::EC2::VPC
    Properties:
      CidrBlock: 10.0.0.0/16
  Firewall:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: accès web
      VpcId: !Ref Network
      SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: 443
          ToPort: 443
          CidrIp: 0.0.0.0/0
      Tags:
        - Key: Name
          Value: pare-feu
  Machine:
    Type: AWS::EC2::Instance
    Properties:
      ImageId: ami-123
      SecurityGroupIds: [!GetAtt Firewall.GroupId]
      SubnetId: !Ref MissingSubnet
"""
    network, firewall, machine = CloudFormationDetector().detect(Path("stack.yaml"), source)
    assert network.tf_type == "aws_vpc"
    assert firewall.attributes["vpc_id"] == {"__raw__": "aws_vpc.network.id"}
    assert firewall.attributes["tags"] == {"Name": "pare-feu"}
    assert firewall.attributes["ingress"] == [
        {
            "protocol": "tcp",
            "from_port": 443,
            "to_port": 443,
            "cidr_blocks": ["0.0.0.0/0"],
        }
    ]
    assert machine.attributes["vpc_security_group_ids"] == [
        {"__raw__": "aws_security_group.firewall.id"},
    ]
    assert machine.attributes["subnet_id"] == {"__raw__": "aws_RESOURCE.missingsubnet.id"}
    assert any("MissingSubnet" in note for note in machine.notes)
    assert "#" not in machine.attributes["subnet_id"]["__raw__"]


def test_cloudformation_json_intrinsics_and_sub() -> None:
    source = json.dumps(
        {
            "Resources": {
                "Role": {
                    "Type": "AWS::IAM::Role",
                    "Properties": {
                        "RoleName": "role",
                        "AssumeRolePolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [],
                        },
                    },
                },
                "Function": {
                    "Type": "AWS::Lambda::Function",
                    "Properties": {
                        "FunctionName": {"Fn::Sub": "${Role}-fn"},
                        "Role": {"Fn::GetAtt": ["Role", "Arn"]},
                        "Code": {"S3Bucket": "code", "S3Key": "code.zip"},
                        "Environment": {"Variables": {"ROLE": {"Ref": "Role"}}},
                    },
                },
            },
        }
    )
    role, function = CloudFormationDetector().detect(Path("stack.json"), source)
    assert role.import_id == "role"
    assert role.attributes["assume_role_policy"]["__raw__"].startswith("jsonencode(")
    assert function.attributes["role"] == {"__raw__": "aws_iam_role.role.arn"}
    assert function.attributes["function_name"] == {
        "__raw__": 'join("", ["", tostring(aws_iam_role.role.id), "-fn"])',
    }
    assert function.attributes["environment"] == [
        {"variables": {"__raw__": '{"ROLE" = aws_iam_role.role.id}'}},
    ]
    assert function.import_id is None
    assert any("Fn::Sub" in note for note in function.notes)


def test_cloudformation_dynamodb_blocks() -> None:
    source = """
Resources:
  Table:
    Type: AWS::DynamoDB::Table
    Properties:
      TableName: events
      AttributeDefinitions:
        - AttributeName: pk
          AttributeType: S
        - AttributeName: sk
          AttributeType: N
      KeySchema:
        - AttributeName: pk
          KeyType: HASH
        - AttributeName: sk
          KeyType: RANGE
      ProvisionedThroughput:
        ReadCapacityUnits: 5
        WriteCapacityUnits: 10
"""
    (finding,) = CloudFormationDetector().detect(Path("stack.yml"), source)
    assert finding.attributes["attribute"] == [
        {"name": "pk", "type": "S"},
        {"name": "sk", "type": "N"},
    ]
    assert finding.attributes["hash_key"] == "pk"
    assert finding.attributes["range_key"] == "sk"
    assert finding.attributes["read_capacity"] == 5
    assert finding.attributes["write_capacity"] == 10
    assert finding.import_id == "events"


def test_cloudformation_unmapped_and_unsupported() -> None:
    source = """
Resources:
  Unknown:
    Type: AWS::Something::Unknown
  Bucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: existing-bucket
      VersioningConfiguration:
        Status: Enabled
"""
    unknown, bucket = CloudFormationDetector().detect(Path("stack.yml"), source)
    assert unknown.tf_type == "UNMAPPED"
    assert unknown.confidence == 0
    assert bucket.confidence < 0.95
    assert any("VersioningConfiguration" in note for note in bucket.notes)
    assert bucket.import_id == "existing-bucket"


@pytest.mark.parametrize(
    "type_name,property_name",
    [
        ("AWS::SQS::Queue", "QueueName"),
        ("AWS::SNS::Topic", "TopicName"),
    ],
)
def test_cloudformation_queue_topic_are_not_imported_by_name(
    type_name: str,
    property_name: str,
) -> None:
    source = json.dumps(
        {
            "Resources": {
                "Messaging": {
                    "Type": type_name,
                    "Properties": {property_name: "messages"},
                }
            }
        }
    )
    (finding,) = CloudFormationDetector().detect(Path("stack.json"), source)
    assert finding.import_id is None


@pytest.mark.parametrize(
    "source",
    [
        "ordinary: configuration",
        "Resources: [invalid",
        "!!python/object/apply:os.system ['false']",
        "Resources: []",
    ],
)
def test_cloudformation_ignores_invalid_or_unsafe_documents(source: str) -> None:
    assert CloudFormationDetector().detect(Path("stack.yaml"), source) == []


def test_cloudformation_unknown_yaml_tag_is_only_data() -> None:
    source = """
Resources:
  Bucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: !Exploit anything
"""
    (finding,) = CloudFormationDetector().detect(Path("stack.yaml"), source)
    assert finding.attributes["bucket"] == {"__raw__": "var.fn__exploit"}
    assert any("Fn::Exploit" in note for note in finding.notes)


def test_python_session_alias_and_botocore_client() -> None:
    source = """
from boto3 import Session as AwsSession
import botocore.session
session = AwsSession()
eks = session.client('eks')
core = botocore.session.get_session()
s3 = core.create_client('s3')
eks.create_cluster(name='kube')
s3.create_bucket(Bucket='core-bucket')
object().create_bucket(Bucket='not-aws')
"""
    cluster, bucket = PythonBoto3Detector().detect(Path("main.py"), source)
    assert cluster.tf_type == "aws_eks_cluster"
    assert bucket.tf_type == "aws_s3_bucket"
    assert not cluster.notes
    assert not bucket.notes


def test_python_dynamodb_indexes_and_stream() -> None:
    source = """
import boto3
db = boto3.client('dynamodb')
db.create_table(
    TableName='events',
    KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
    StreamSpecification={'StreamEnabled': True, 'StreamViewType': 'NEW_IMAGE'},
    GlobalSecondaryIndexes=[{
        'IndexName': 'by-date',
        'KeySchema': [{'AttributeName': 'date', 'KeyType': 'HASH'}],
        'Projection': {'ProjectionType': 'INCLUDE', 'NonKeyAttributes': ['body']},
        'ProvisionedThroughput': {'ReadCapacityUnits': 2, 'WriteCapacityUnits': 3}
    }])
"""
    (finding,) = PythonBoto3Detector().detect(Path("main.py"), source)
    assert finding.attributes["stream_enabled"] is True
    assert finding.attributes["stream_view_type"] == "NEW_IMAGE"
    assert finding.attributes["global_secondary_index"] == [
        {
            "name": "by-date",
            "hash_key": "date",
            "projection_type": "INCLUDE",
            "non_key_attributes": ["body"],
            "read_capacity": 2,
            "write_capacity": 3,
        }
    ]


def test_python_clients_in_different_scopes() -> None:
    source = """
import boto3
def bucket():
    client = boto3.client('s3')
    client.create_bucket(Bucket='assets')
def table():
    client = boto3.client('dynamodb')
    client.create_table(TableName='events')
"""
    findings = PythonBoto3Detector().detect(Path("main.py"), source)
    assert [finding.tf_type for finding in findings] == ["aws_s3_bucket", "aws_dynamodb_table"]


def test_cloudformation_substitution_map_and_intrinsic_join() -> None:
    source = """
Parameters:
  Stage:
    Type: String
Resources:
  Bucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: !Sub
        - '${Prefix}-${Stage}'
        - Prefix: production
      Tags:
        - Key: Joined
          Value: !Join ['-', ['prefix', !Ref Stage]]
"""
    (finding,) = CloudFormationDetector().detect(Path("stack.yaml"), source)
    assert finding.attributes["bucket"] == {
        "__raw__": 'join("", ["", "production", "-", tostring(var.stage), ""])',
    }
    assert finding.attributes["tags"]["Joined"] == {
        "__raw__": 'join("-", ["prefix", var.stage])',
    }
    assert all("#" not in value["__raw__"] for value in finding.attributes["tags"].values())


def test_cloudformation_invalid_type_is_unmapped() -> None:
    source = "Resources:\n  Invalid:\n    Type: [not, a, type]\n"
    (finding,) = CloudFormationDetector().detect(Path("stack.yml"), source)
    assert finding.tf_type == "UNMAPPED"
    assert finding.confidence == 0


def test_cloudformation_recursive_yaml_does_not_crash() -> None:
    source = """
Resources:
  Bucket:
    Type: AWS::S3::Bucket
    Properties: &recursive
      Tags: *recursive
"""
    assert CloudFormationDetector().detect(Path("stack.yml"), source) == []


def test_cloudformation_rejects_alias_graph_before_loading(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = """
Metadata:
  Base: &base [x, x, x, x]
  Doubled: &doubled [*base, *base, *base, *base]
  Expanded: &expanded [*doubled, *doubled, *doubled, *doubled]
Resources:
  Bucket:
    Type: AWS::S3::Bucket
    Properties:
      Tags: *expanded
"""

    def forbidden_load(*args: object, **kwargs: object) -> None:
        pytest.fail("Le chargement ne doit jamais développer les alias YAML.")

    monkeypatch.setattr("terraformizer.detectors.cloudformation.yaml.load", forbidden_load)
    assert CloudFormationDetector().detect(Path("stack.yml"), source) == []


def test_cloudformation_raw_strings_and_identifiers_are_safe() -> None:
    source = json.dumps(
        {
            "Resources": {
                "Role": {"Type": "AWS::IAM::Role"},
                "Bucket": {
                    "Type": "AWS::S3::Bucket",
                    "Properties": {
                        "BucketName": {
                            "Fn::Join": [
                                "-",
                                [
                                    '${file("secrets")}',
                                    "%{if true}",
                                    {"Ref": "AWS::Region"},
                                ],
                            ]
                        },
                        "Tags": [
                            {
                                "Key": "bad",
                                "Value": {
                                    "Fn::GetAtt": [
                                        "Role",
                                        'Arn); file("secrets") #',
                                    ]
                                },
                            }
                        ],
                    },
                },
            }
        }
    )
    _, bucket = CloudFormationDetector().detect(Path("stack.json"), source)
    expression = bucket.attributes["bucket"]["__raw__"]
    assert "$${file(" in expression
    assert "%%{if true}" in expression
    assert "var.aws_region" in expression
    assert bucket.attributes["tags"]["bad"]["__raw__"].startswith("aws_iam_role.role.arn")
    assert "#" not in bucket.attributes["tags"]["bad"]["__raw__"]
    assert '"' not in bucket.attributes["tags"]["bad"]["__raw__"]
    assert any("pseudo-paramètre" in note for note in bucket.notes)


def test_cloudformation_sub_literal_cannot_inject_interpolation() -> None:
    source = json.dumps(
        {
            "Resources": {
                "Bucket": {
                    "Type": "AWS::S3::Bucket",
                    "Properties": {
                        "BucketName": {
                            "Fn::Sub": [
                                "${Prefix}-%{if true}-${!Literal}",
                                {"Prefix": '${file("secrets")}'},
                            ]
                        }
                    },
                }
            }
        }
    )
    (finding,) = CloudFormationDetector().detect(Path("stack.json"), source)
    expression = finding.attributes["bucket"]["__raw__"]
    assert "$${file(" in expression
    assert "%%{if true}" in expression
    assert "$${Literal}" in expression


def test_python_policy_literals_cannot_supply_raw_expressions() -> None:
    source = """
import boto3
iam = boto3.client('iam')
iam.create_role(RoleName='role', AssumeRolePolicyDocument={
    'Resource': '${file("secrets")}',
    'Metadata': {'__raw__': 'file("secrets")'}
})
"""
    (finding,) = PythonBoto3Detector().detect(Path("main.py"), source)
    expression = finding.attributes["assume_role_policy"]["__raw__"]
    assert "$${file(" in expression
    assert 'Metadata" = var.metadata_reserved_raw' in expression
    assert 'Metadata" = file(' not in expression
    assert any("clé réservée __raw__" in note for note in finding.notes)


def test_python_tuples_and_sets_become_lists() -> None:
    source = """
import boto3
ec2 = boto3.client('ec2')
ec2.run_instances(ImageId='ami-x', SecurityGroupIds=('sg-a', 'sg-b'))
ec2.run_instances(ImageId='ami-x', SecurityGroupIds={'sg-b', 'sg-a'})
"""
    tuple_finding, set_finding = PythonBoto3Detector().detect(Path("main.py"), source)
    assert tuple_finding.attributes["vpc_security_group_ids"] == ["sg-a", "sg-b"]
    assert set_finding.attributes["vpc_security_group_ids"] == ["sg-a", "sg-b"]


def test_python_fixture_style_tags_and_environment_expression() -> None:
    source = """
import os
import boto3
ec2 = boto3.client('ec2')
ec2.run_instances(
    ImageId=os.environ["AMI"],
    TagSpecifications=[{
        "ResourceType": "instance",
        "Tags": [{"Key": "Name", "Value": "web-01"}]
    }])
"""
    (finding,) = PythonBoto3Detector().detect(Path("infra.py"), source)
    assert finding.name == "web_01"
    assert finding.attributes["tags"] == {"Name": "web-01"}
    assert finding.attributes["ami"]["__raw__"].startswith("var.os_environ")
    assert "#" not in finding.attributes["ami"]["__raw__"]
    assert any("os.environ" in note for note in finding.notes)


def test_python_lambda_publish_and_environment_object() -> None:
    source = """
import boto3
client = boto3.client('lambda')
client.create_function(
    FunctionName='worker', Publish=True,
    Environment={'Variables': {'CONFIG': '${file("secrets")}', 'STAGE': 'prod'}}
)
"""
    (finding,) = PythonBoto3Detector().detect(Path("main.py"), source)
    assert "publish" not in finding.attributes
    assert any("Publish" in note for note in finding.notes)
    variables = finding.attributes["environment"][0]["variables"]["__raw__"]
    assert variables.startswith("{")
    assert "$${file(" in variables


@pytest.mark.parametrize(
    "properties",
    [
        {"BucketName": {"__raw__": 'file("secrets")', "other": "value"}},
    ],
)
def test_cloudformation_reserved_source_maps_become_variables(properties: dict) -> None:
    source = json.dumps(
        {
            "Resources": {
                "Bucket": {
                    "Type": "AWS::S3::Bucket",
                    "Properties": properties,
                }
            }
        }
    )
    (finding,) = CloudFormationDetector().detect(Path("stack.json"), source)
    assert any("clé réservée __raw__" in note for note in finding.notes)
    for value in finding.attributes.values():
        assert value["__raw__"].startswith("var.")
        assert "file(" not in value["__raw__"]


def test_python_reserved_tag_key_remains_literal() -> None:
    source = """
import boto3
client = boto3.client('s3')
client.create_bucket(Bucket='bucket', Tags=[{'Key': '__raw__', 'Value': 'file("secrets")'}])
"""
    (finding,) = PythonBoto3Detector().detect(Path("main.py"), source)
    assert finding.attributes["tags"] == {
        "__raw__": '{"__raw__" = "file(\\"secrets\\")"}',
    }


def test_generated_raw_survives_dataclass_json_export() -> None:
    source = """
import boto3
client = boto3.client('ec2')
client.run_instances(ImageId=ami)
"""
    (finding,) = PythonBoto3Detector().detect(Path("main.py"), source)
    row = asdict(finding)
    row["source_file"] = str(row["source_file"])
    exported = json.loads(json.dumps(row))
    assert exported["attributes"]["ami"] == {"__raw__": "var.ami"}


@pytest.mark.parametrize(
    "tags",
    [
        [{"Key": "__raw__", "Value": '${file("secrets")}'}],
        {"__raw__": '${file("secrets")}'},
    ],
)
def test_cloudformation_reserved_tag_key_remains_literal(tags: list | dict) -> None:
    source = json.dumps(
        {
            "Resources": {
                "Bucket": {
                    "Type": "AWS::S3::Bucket",
                    "Properties": {"Tags": tags},
                }
            }
        }
    )
    (finding,) = CloudFormationDetector().detect(Path("stack.json"), source)
    assert finding.attributes["tags"] == {
        "__raw__": '{"__raw__" = "$${file(\\"secrets\\")}"}',
    }


def test_python_reserved_tag_key_preserves_dynamic_value() -> None:
    source = """
import boto3
client = boto3.client('s3')
client.create_bucket(Bucket='bucket', Tags=[{'Key': '__raw__', 'Value': dynamic_tag}])
"""
    (finding,) = PythonBoto3Detector().detect(Path("main.py"), source)
    assert finding.attributes["tags"] == {
        "__raw__": '{"__raw__" = var.dynamic_tag}',
    }


@pytest.mark.parametrize("literal", ["b'bytes'", "1j", "1e999"])
def test_python_unsupported_literal_scalars_become_variables(literal: str) -> None:
    source = f"""
import boto3
client = boto3.client('ec2')
client.run_instances(ImageId={literal})
"""
    (finding,) = PythonBoto3Detector().detect(Path("main.py"), source)
    assert finding.attributes["ami"] == {"__raw__": "var.imageid_value"}
    assert any("non représentable en HCL" in note for note in finding.notes)
    row = asdict(finding)
    row["source_file"] = str(row["source_file"])
    json.dumps(row, allow_nan=False)


@pytest.mark.parametrize("scalar", ["2026-01-01", "2026-01-01T10:30:00Z", ".nan", ".inf"])
def test_cloudformation_unsupported_yaml_scalars_become_variables(scalar: str) -> None:
    source = f"""
Resources:
  Bucket:
    Type: AWS::S3::Bucket
    Properties:
      Tags:
        - Key: Created
          Value: {scalar}
"""
    (finding,) = CloudFormationDetector().detect(Path("stack.yml"), source)
    assert finding.attributes["tags"]["Created"] == {"__raw__": "var.value_value"}
    assert any("non représentable en HCL" in note for note in finding.notes)
    row = asdict(finding)
    row["source_file"] = str(row["source_file"])
    json.dumps(row, allow_nan=False)
