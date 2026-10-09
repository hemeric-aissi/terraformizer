provider "aws" {
  region = var.aws_region
}

# Source : deploy.sh:2 (confiance 100%)
# Origine : aws ec2 run-instances \   --image-id ami-example \   --instance-type t3.micro \   --security-group-ids sg-example-one sg
resource "aws_instance" "aws_instance" {
  ami                    = "ami-example"
  instance_type          = "t3.micro"
  vpc_security_group_ids = ["sg-example-one", "sg-example-two"]
  user_data              = file("bootstrap.sh")
}

# Source : deploy.sh:7 (confiance 100%)
# Origine : aws s3 mb s3://my-bucket-prod
resource "aws_s3_bucket" "my_bucket_prod" {
  bucket = "my-bucket-prod"
}

# Source : infra.py:10 (confiance 65%)
# Origine : ec2.run_instances(     ImageId=os.environ["AMI"],     InstanceType="t3.micro",     MinCount=1,     MaxCount=1,     TagSp
# TODO : TODO : remplacer var.os_environ__ami (expression Python : os.environ['AMI']).
resource "aws_instance" "web_01" {
  ami           = var.os_environ__ami
  instance_type = "t3.micro"
  tags = {
    "Name" = "web-01"
  }
}

# Source : template.yaml:3 (confiance 95%)
# Origine : {"Type": "AWS::EC2::VPC", "Properties": {"CidrBlock": "10.0.0.0/16", "Tags": [{"Key": "Name", "Value": "demo"}]}}
resource "aws_vpc" "demovpc" {
  cidr_block = "10.0.0.0/16"
  tags = {
    "Name" = "demo"
  }
}

# Source : template.yaml:10 (confiance 65%)
# Origine : {"Type": "AWS::EC2::Subnet", "Properties": {"VpcId": {"Ref": "DemoVpc"}, "CidrBlock": "10.0.1.0/24"}}
# TODO : TODO : vérifier l'approximation de la référence CloudFormation DemoVpc.
resource "aws_subnet" "demosubnet" {
  vpc_id     = aws_vpc.demovpc.id
  cidr_block = "10.0.1.0/24"
}

# Source : template.yaml:15 (confiance 95%)
# Origine : {"Type": "AWS::S3::Bucket", "Properties": {"BucketName": "demo-archive"}}
resource "aws_s3_bucket" "archivebucket" {
  bucket = "demo-archive"
}
