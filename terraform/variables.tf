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

variable "rule_action" {
  description = "Action for every PHP2Shell rule. Start with COUNT, review matches, then switch to BLOCK"
  type        = string
  default     = "COUNT"

  validation {
    condition     = contains(["COUNT", "BLOCK"], var.rule_action)
    error_message = "rule_action must be either COUNT or BLOCK"
  }
}

variable "php_managed_rule_group_version" {
  description = "Version of AWSManagedRulesPHPRuleSet. Must be Version_2.3 or later to include PHP2Shell_BODY"
  type        = string
  default     = "Version_2.3"
}

variable "enable_oversize_body_block" {
  description = "Add a rule matching request bodies larger than max_body_size_bytes (CVE-2026-109618). Breaks large uploads"
  type        = bool
  default     = true
}

variable "max_body_size_bytes" {
  description = "Body size threshold for the oversize body rule. AWS WAF inspects only the first 8 KB of the body on ALB"
  type        = number
  default     = 8192
}

variable "enable_multipart_block" {
  description = "Add a rule matching every multipart request. Breaks file uploads and multipart forms"
  type        = bool
  default     = true
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
