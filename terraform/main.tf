terraform {
  required_version = ">= 1.0.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# AWS WAFv2 Web ACL for Regional usage (e.g., Application Load Balancer, API Gateway)
# Change scope to "CLOUDFRONT" if protecting a CloudFront distribution (must be created in us-east-1)
resource "aws_wafv2_web_acl" "rce_mitigation_acl" {
  name        = var.web_acl_name
  description = var.web_acl_description
  scope       = var.web_acl_scope

  default_action {
    allow {}
  }

  visibility_config {
    cloudwatch_metrics_enabled = var.enable_cloudwatch_metrics
    metric_name                = var.metric_name
    sampled_requests_enabled   = var.enable_sampled_requests
  }

  tags = var.tags

  # Custom Rule to detect and block suspicious RCE patterns in query strings or bodies
  rule {
    name     = "BlockSuspiciousRCEPatterns"
    priority = var.rule_priority

    action {
      block {}
    }

    statement {
      or_statement {
        statement {
          byte_match_statement {
            search_string         = "system("
            position_constraint   = "CONTAINS"
            field_to_match {
              query_string {}
            }
            text_transformation {
              priority = 0
              type     = "URL_DECODE"
            }
            text_transformation {
              priority = 1
              type     = "LOWERCASE"
            }
          }
        }
        statement {
          byte_match_statement {
            search_string         = "passthru("
            position_constraint   = "CONTAINS"
            field_to_match {
              query_string {}
            }
            text_transformation {
              priority = 0
              type     = "URL_DECODE"
            }
            text_transformation {
              priority = 1
              type     = "LOWERCASE"
            }
          }
        }
        # Add additional byte_match or regex statements here based on specific threat intel 
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "BlockSuspiciousRCEPatternsMetric"
      sampled_requests_enabled   = true
    }
  }
}

