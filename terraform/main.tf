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

data "aws_region" "current" {}

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

  # AWS managed PHP rule group. Version_2.3 adds PHP2Shell_BODY (CVE-2026-109619); Version_2.2 and older do not.
  rule {
    name     = "php2shell-AWS-PHP-Managed-Rules"
    priority = 0

    override_action {
      dynamic "none" {
        for_each = var.rule_action == "BLOCK" ? [1] : []
        content {}
      }
      dynamic "count" {
        for_each = var.rule_action == "COUNT" ? [1] : []
        content {}
      }
    }

    statement {
      managed_rule_group_statement {
        vendor_name = "AWS"
        name        = "AWSManagedRulesPHPRuleSet"
        version     = var.php_managed_rule_group_version
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "php2shell-AWS-PHP-Managed-Rules"
      sampled_requests_enabled   = true
    }
  }

  # User-Agent sent by the public php2shell exploit tool. Trivial to change, so treat as a low-cost extra signal.
  rule {
    name     = "php2shell-UserAgent-Block"
    priority = 1

    action {
      dynamic "block" {
        for_each = var.rule_action == "BLOCK" ? [1] : []
        content {}
      }
      dynamic "count" {
        for_each = var.rule_action == "COUNT" ? [1] : []
        content {}
      }
    }

    statement {
      byte_match_statement {
        search_string         = "php2shell"
        positional_constraint = "STARTS_WITH"
        field_to_match {
          single_header {
            name = "user-agent"
          }
        }
        text_transformation {
          priority = 0
          type     = "LOWERCASE"
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "php2shell-UserAgent-Block"
      sampled_requests_enabled   = true
    }
  }

  # Multipart boundaries hardcoded in the public exploit tool; modified copies usually keep them.
  rule {
    name     = "php2shell-Exploit-Boundary-Block"
    priority = 2

    action {
      dynamic "block" {
        for_each = var.rule_action == "BLOCK" ? [1] : []
        content {}
      }
      dynamic "count" {
        for_each = var.rule_action == "COUNT" ? [1] : []
        content {}
      }
    }

    statement {
      or_statement {
        statement {
          byte_match_statement {
            search_string         = "b7kqpoc618"
            positional_constraint = "CONTAINS"
            field_to_match {
              single_header {
                name = "content-type"
              }
            }
            text_transformation {
              priority = 0
              type     = "LOWERCASE"
            }
          }
        }
        statement {
          byte_match_statement {
            search_string         = "b7kqpoc619"
            positional_constraint = "CONTAINS"
            field_to_match {
              single_header {
                name = "content-type"
              }
            }
            text_transformation {
              priority = 0
              type     = "LOWERCASE"
            }
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "php2shell-Exploit-Boundary-Block"
      sampled_requests_enabled   = true
    }
  }

  # CVE-2026-109619 entry point: a POST using PHP's session upload progress field together with a session ID.
  rule {
    name     = "php2shell-Upload-Progress-Block"
    priority = 3

    action {
      dynamic "block" {
        for_each = var.rule_action == "BLOCK" ? [1] : []
        content {}
      }
      dynamic "count" {
        for_each = var.rule_action == "COUNT" ? [1] : []
        content {}
      }
    }

    statement {
      and_statement {
        statement {
          byte_match_statement {
            search_string         = "POST"
            positional_constraint = "EXACTLY"
            field_to_match {
              method {}
            }
            text_transformation {
              priority = 0
              type     = "NONE"
            }
          }
        }
        statement {
          byte_match_statement {
            search_string         = "php_session_upload_progress"
            positional_constraint = "CONTAINS"
            field_to_match {
              body {
                oversize_handling = "CONTINUE"
              }
            }
            text_transformation {
              priority = 0
              type     = "LOWERCASE"
            }
          }
        }
        statement {
          or_statement {
            statement {
              byte_match_statement {
                search_string         = "phpsessid"
                positional_constraint = "CONTAINS"
                field_to_match {
                  single_header {
                    name = "cookie"
                  }
                }
                text_transformation {
                  priority = 0
                  type     = "LOWERCASE"
                }
              }
            }
            statement {
              byte_match_statement {
                search_string         = "phpsessid"
                positional_constraint = "CONTAINS"
                field_to_match {
                  body {
                    oversize_handling = "CONTINUE"
                  }
                }
                text_transformation {
                  priority = 0
                  type     = "LOWERCASE"
                }
              }
            }
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "php2shell-Upload-Progress-Block"
      sampled_requests_enabled   = true
    }
  }

  # CVE-2026-109618 needs a large body to exhaust memory during request setup. Breaks large uploads on unscoped paths.
  dynamic "rule" {
    for_each = var.enable_oversize_body_block ? [1] : []
    content {
      name     = "php2shell-Oversize-Body-Block"
      priority = 4

      action {
        dynamic "block" {
          for_each = var.rule_action == "BLOCK" ? [1] : []
          content {}
        }
        dynamic "count" {
          for_each = var.rule_action == "COUNT" ? [1] : []
          content {}
        }
      }

      statement {
        size_constraint_statement {
          comparison_operator = "GT"
          size                = var.max_body_size_bytes
          field_to_match {
            body {
              oversize_handling = "MATCH"
            }
          }
          text_transformation {
            priority = 0
            type     = "NONE"
          }
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "php2shell-Oversize-Body-Block"
        sampled_requests_enabled   = true
      }
    }
  }

  # Every known trigger is multipart. Blocking breaks all file uploads and multipart forms; use only on apps without them.
  dynamic "rule" {
    for_each = var.enable_multipart_block ? [1] : []
    content {
      name     = "php2shell-Temporary-Multipart-Block"
      priority = 5

      action {
        dynamic "block" {
          for_each = var.rule_action == "BLOCK" ? [1] : []
          content {}
        }
        dynamic "count" {
          for_each = var.rule_action == "COUNT" ? [1] : []
          content {}
        }
      }

      statement {
        byte_match_statement {
          search_string         = "multipart/"
          positional_constraint = "CONTAINS"
          field_to_match {
            single_header {
              name = "content-type"
            }
          }
          text_transformation {
            priority = 0
            type     = "LOWERCASE"
          }
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "php2shell-Temporary-Multipart-Block"
        sampled_requests_enabled   = true
      }
    }
  }
}
