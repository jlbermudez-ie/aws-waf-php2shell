variable "web_acl_name" {
  description = "Name of the WAF Web ACL"
  type        = string
  default     = "php2shell-rce-mitigation-acl"
}

variable "web_acl_description" {
  description = "Description of the Web ACL"
  type        = string
  default     = "Web ACL to apply edge-level mitigations for RCE vulnerabilities CVE-2026-109618 and CVE-2026-109619"
}

variable "web_acl_scope" {
  description = "Scope of the Web ACL (REGIONAL or CLOUDFRONT). Use CLOUDFRONT only for CloudFront distributions in us-east-1"
  type        = string
  default     = "REGIONAL"

  validation {
    condition     = contains(["REGIONAL", "CLOUDFRONT"], var.web_acl_scope)
    error_message = "web_acl_scope must be either REGIONAL or CLOUDFRONT"
  }
}

variable "enable_cloudwatch_metrics" {
  description = "Enable CloudWatch metrics for the Web ACL"
  type        = bool
  default     = true
}

variable "enable_sampled_requests" {
  description = "Enable collection of sampled requests"
  type        = bool
  default     = true
}

variable "metric_name" {
  description = "CloudWatch metric name for the WAF Web ACL"
  type        = string
  default     = "Php2ShellMitigationMetric"
}

variable "rule_priority" {
  description = "Priority for the RCE blocking rule (lower = higher priority)"
  type        = number
  default     = 1

  validation {
    condition     = var.rule_priority >= 0
    error_message = "rule_priority must be a non-negative integer"
  }
}

variable "aws_region" {
  description = "AWS region for deployment"
  type        = string
  default     = "us-east-1"
}

variable "tags" {
  description = "Common tags to apply to all resources"
  type        = map(string)
  default = {
    Environment = "production"
    Project     = "security-php2shell-mitigation"
    ManagedBy   = "terraform"
  }
}
