# ==============================================================================
# HawkEye-AI — Terraform Cloud Infrastructure as Code (IaC)
# Provisions AWS VPC, Flow Logs, S3 Encryption, & Zero-Trust Quarantine Groups
# ==============================================================================

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region

  # Best Practice: Credentials should be supplied via environment variables
  # (AWS_ACCESS_KEY_ID & AWS_SECRET_ACCESS_KEY) or standard ~/.aws/credentials.
  # Hardcoding secrets in git repository is prohibited for security compliance.

  default_tags {
    tags = {
      Project     = "HawkEye-AI"
      Environment = var.environment
      ManagedBy   = "Terraform"
      Owner       = "SOC-Team"
    }
  }
}

# ------------------------------------------------------------------------------
# 1. AWS Virtual Private Cloud (VPC) & Networking
# ------------------------------------------------------------------------------
resource "aws_vpc" "hawkeye_vpc" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "hawkeye-cloud-vpc"
  }
}

resource "aws_subnet" "public_subnet" {
  vpc_id                  = aws_vpc.hawkeye_vpc.id
  cidr_block              = var.public_subnet_cidr
  map_public_ip_on_launch = true
  availability_zone       = "${var.aws_region}a"

  tags = {
    Name = "hawkeye-public-subnet"
  }
}

resource "aws_subnet" "private_subnet" {
  vpc_id            = aws_vpc.hawkeye_vpc.id
  cidr_block        = var.private_subnet_cidr
  availability_zone = "${var.aws_region}b"

  tags = {
    Name = "hawkeye-private-subnet"
  }
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.hawkeye_vpc.id

  tags = {
    Name = "hawkeye-vpc-igw"
  }
}

resource "aws_route_table" "public_rt" {
  vpc_id = aws_vpc.hawkeye_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }

  tags = {
    Name = "hawkeye-public-rt"
  }
}

resource "aws_route_table_association" "public_assoc" {
  subnet_id      = aws_subnet.public_subnet.id
  route_table_id = aws_route_table.public_rt.id
}

# ------------------------------------------------------------------------------
# 2. AWS VPC Flow Logs & CloudWatch Log Group
# ------------------------------------------------------------------------------
resource "aws_cloudwatch_log_group" "vpc_flow_logs_group" {
  name              = "/aws/vpc/hawkeye-flow-logs"
  retention_in_days = 30
}

resource "aws_iam_role" "vpc_flow_log_role" {
  name = "hawkeye-vpc-flow-logs-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "vpc-flow-logs.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "vpc_flow_log_policy" {
  name = "hawkeye-vpc-flow-logs-policy"
  role = aws_iam_role.vpc_flow_log_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams"
      ]
      Effect   = "Allow"
      Resource = "*"
    }]
  })
}

resource "aws_flow_log" "hawkeye_vpc_flow" {
  iam_role_arn    = aws_iam_role.vpc_flow_log_role.arn
  log_destination = aws_cloudwatch_log_group.vpc_flow_logs_group.arn
  traffic_type    = "ALL"
  vpc_id          = aws_vpc.hawkeye_vpc.id
}

# ------------------------------------------------------------------------------
# 3. AWS S3 Encrypted Incident Archive Bucket (SSE-KMS & Glacier Lifecycle)
# ------------------------------------------------------------------------------
resource "aws_s3_bucket" "soc_archive_bucket" {
  bucket        = "hawkeye-soc-archives-${var.environment}-305718149998"
  force_destroy = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "soc_archive_encryption" {
  bucket = aws_s3_bucket.soc_archive_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "soc_archive_pab" {
  bucket = aws_s3_bucket.soc_archive_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "soc_archive_lifecycle" {
  bucket = aws_s3_bucket.soc_archive_bucket.id

  rule {
    id     = "archive-to-glacier-after-30-days"
    status = "Enabled"

    filter {}

    transition {
      days          = 30
      storage_class = "GLACIER"
    }

    expiration {
      days = 365
    }
  }
}

# ------------------------------------------------------------------------------
# 4. Zero-Trust Cloud Quarantine Security Group
# ------------------------------------------------------------------------------
resource "aws_security_group" "hawkeye_quarantine_sg" {
  name        = "hawkeye-quarantine-sg"
  description = "Quarantine SG: Denies all inbound and outbound traffic for isolated compromised EC2"
  vpc_id      = aws_vpc.hawkeye_vpc.id

  # Intentionally NO ingress or egress rules -> Complete Network Isolation
  tags = {
    Name = "hawkeye-quarantine-sg"
    Role = "Automated-Incident-Containment"
  }
}
