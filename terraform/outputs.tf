output "web_acl_arn" {
  description = "ARN of the WAF Web ACL - use this to associate with ALB, API Gateway, or CloudFront"
  value       = aws_wafv2_web_acl.rce_mitigation_acl.arn
}

output "web_acl_id" {
  description = "ID of the WAF Web ACL"
  value       = aws_wafv2_web_acl.rce_mitigation_acl.id
}

output "web_acl_name" {
  description = "Name of the WAF Web ACL"
  value       = aws_wafv2_web_acl.rce_mitigation_acl.name
}

output "web_acl_scope" {
  description = "Scope of the WAF Web ACL (REGIONAL or CLOUDFRONT)"
  value       = aws_wafv2_web_acl.rce_mitigation_acl.scope
}

output "cloudwatch_metric_name" {
  description = "CloudWatch metric name for monitoring WAF activity"
  value       = aws_wafv2_web_acl.rce_mitigation_acl.visibility_config[0].metric_name
}

output "associate_with_alb_command" {
  description = "CLI command to associate WAF with an Application Load Balancer"
  value       = "aws wafv2 associate-web-acl --web-acl-arn ${aws_wafv2_web_acl.rce_mitigation_acl.arn} --resource-arn <ALB_ARN> --region ${data.aws_caller_identity.current.account_id} --region ${data.aws_region_name.current.name}"
}

output "associate_with_api_gateway_command" {
  description = "CLI command to associate WAF with an API Gateway"
  value       = "aws wafv2 associate-web-acl --web-acl-arn ${aws_wafv2_web_acl.rce_mitigation_acl.arn} --resource-arn arn:aws:apigateway:<region>::/restapis/<api-id>/stages/<stage-name> --region ${data.aws_region_name.current.name}"
}
