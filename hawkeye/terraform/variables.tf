variable "aws_region" {
  description = "AWS deployment region"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Deployment environment (production / staging / lab)"
  type        = string
  default     = "staging"
}

variable "vpc_cidr" {
  description = "CIDR block for the HawkEye Cloud VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "public_subnet_cidr" {
  description = "CIDR block for Public Subnet"
  type        = string
  default     = "10.0.1.0/24"
}

variable "private_subnet_cidr" {
  description = "CIDR block for Private Subnet"
  type        = string
  default     = "10.0.2.0/24"
}
