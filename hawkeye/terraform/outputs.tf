output "vpc_id" {
  description = "HawkEye VPC ID"
  value       = aws_vpc.hawkeye_vpc.id
}

output "public_subnet_id" {
  description = "Public Subnet ID for HawkEye Dashboard"
  value       = aws_subnet.public_subnet.id
}

output "flow_log_group" {
  description = "CloudWatch Log Group capturing VPC Flow Logs"
  value       = aws_cloudwatch_log_group.vpc_flow_logs_group.name
}

output "soc_archive_bucket" {
  description = "S3 Bucket storing encrypted incident telemetry"
  value       = aws_s3_bucket.soc_archive_bucket.bucket
}

output "quarantine_security_group_id" {
  description = "Zero-trust quarantine security group ID for compromised EC2 isolation"
  value       = aws_security_group.hawkeye_quarantine_sg.id
}
