# AWS WAF PHP2Shell Mitigation - Security Best Practices

This document outlines security best practices for deploying and maintaining this WAF solution.

## 1. Deployment Best Practices

### Before Deployment

- [ ] **Review Rules**: Understand each WAF rule before deployment
- [ ] **Test in Non-Production**: Deploy to dev/staging first
- [ ] **Plan Maintenance Window**: Schedule deployment during low-traffic periods
- [ ] **Backup Configuration**: Version control your Terraform state
- [ ] **Notify Teams**: Alert application teams about WAF changes

### Deployment Process

```bash
# 1. Validate syntax
terraform validate

# 2. Preview changes
terraform plan -out=tfplan

# 3. Review output carefully
cat tfplan

# 4. Apply with confirmation
terraform apply tfplan
```

### Post-Deployment Verification

```bash
# Verify WAF is deployed
aws wafv2 list-web-acls --scope REGIONAL

# Associate with resources
aws wafv2 associate-web-acl \
  --web-acl-arn <YOUR_WAF_ARN> \
  --resource-arn <YOUR_ALB_ARN> \
  --region us-east-1

# Monitor initial traffic
aws wafv2 get-sampled-requests \
  --web-acl-arn <YOUR_WAF_ARN> \
  --rule-metric-name BlockSuspiciousRCEPatternsMetric \
  --scope REGIONAL \
  --time-window StartTime=$(date -u -d '10 minutes ago' +%s),EndTime=$(date -u +%s) \
  --max-items 50
```

---

## 2. Monitoring & Alerting

### CloudWatch Metrics to Monitor

Create CloudWatch alarms for:

1. **Blocked Requests Spike**
   - Threshold: > 100 requests/hour
   - Action: Notify security team

2. **Allowed Requests Pattern Change**
   - Detect unusual increases in traffic
   - May indicate WAF bypass attempts

3. **Rule Errors**
   - Monitor for WAF evaluation errors
   - May indicate rule configuration issues

### CloudWatch Logs Insights Queries

**Find Top Attack Sources:**
```
fields @timestamp, httpRequest.clientIp, action, httpRequest.uri
| filter action = "BLOCK"
| stats count() as blocked_count by clientIp
| sort blocked_count desc
| limit 10
```

**Identify False Positives:**
```
fields @timestamp, httpRequest.clientIp, httpRequest.uri, action
| filter action = "BLOCK"
| stats count() as attempts by httpRequest.uri
| filter attempts > 10
```

**Track Blocked Patterns:**
```
fields @timestamp, action, terminatingRuleId
| filter action = "BLOCK"
| stats count() as blocks by terminatingRuleId
| sort blocks desc
```

---

## 3. Logging Configuration

### Enable Full Request/Response Logging

```hcl
# In terraform/main.tf, add logging configuration:
resource "aws_cloudwatch_log_group" "waf_logs" {
  name              = "/aws/waf/php2shell-rce"
  retention_in_days = 30
  
  tags = var.tags
}

resource "aws_wafv2_web_acl_logging_configuration" "waf_logging" {
  resource_arn            = aws_wafv2_web_acl.rce_mitigation_acl.arn
  log_destination_configs = [aws_cloudwatch_log_group.waf_logs.arn]
  
  logging_filter {
    default_behavior = "KEEP"
    
    filter {
      behavior = "KEEP"
      
      condition {
        action_condition {
          action = "BLOCK"
        }
      }
      
      requirement = "MEETS_ANY"
    }
  }
}
```

---

## 4. Rule Tuning & Optimization

### False Positive Mitigation

1. **Monitor Initial Traffic**
   - Use `COUNT` action initially (non-blocking)
   - Observe patterns for 24-48 hours

2. **Identify Legitimate Traffic**
   - Create allowlist rules for known legitimate patterns
   - Example: Admin panels with legitimate command parameters

3. **Gradual Rollout**
   ```hcl
   # For API endpoints that legitimately use "system" keyword:
   rule {
     name     = "AllowSystemEndpoint"
     priority = 0  # Higher priority = evaluated first
     
     action {
       allow {}
     }
     
     statement {
       byte_match_statement {
         search_string       = "/api/system-status"
         position_constraint = "STARTS_WITH"
         field_to_match {
           uri_path {}
         }
       }
     }
   }
   ```

### Performance Optimization

- **Rule Priority**: Order rules by frequency of match (most common first)
- **Text Transformations**: Keep transforms minimal for performance
- **Sampling**: Adjust sampled requests rate based on traffic volume

### Scaling Considerations

- WAF scales automatically with traffic
- Monitor CloudWatch metrics for throttling
- No per-rule pricing; cost is per Web ACL

---

## 5. Incident Response

### If Legitimate Traffic Gets Blocked

1. **Immediate Action**:
   ```bash
   # Create a temporary whitelist rule
   aws wafv2 update-web-acl \
     --name php2shell-rce-mitigation-acl \
     --scope REGIONAL \
     --id <WEB_ACL_ID> \
     --default-action '{"Allow":{}}' \
     --rules file://whitelist-rule.json \
     --visibility-config SampledRequestsEnabled=true,CloudWatchMetricsEnabled=true,MetricName=Php2ShellMitigationMetric
   ```

2. **Investigate**:
   ```bash
   # Check blocked request details
   aws wafv2 get-sampled-requests \
     --web-acl-arn <WAF_ARN> \
     --rule-metric-name BlockSuspiciousRCEPatternsMetric \
     --scope REGIONAL \
     --time-window StartTime=$(date -u -d '1 hour ago' +%s),EndTime=$(date -u +%s) \
     --max-items 100
   ```

3. **Create Exception Rule**:
   - Add whitelist rule with high priority
   - Document the exception
   - Schedule permanent fix

4. **Verify & Communicate**:
   - Test with actual traffic patterns
   - Notify stakeholders of resolution
   - Update incident log

### If Real Attack Is Detected

1. **Alert Security Team** (immediately)
2. **Escalate Investigation**:
   - Retrieve full request logs
   - Contact AWS Support (enterprise)
   - Begin incident response procedures
3. **Forensics**:
   - Preserve CloudWatch logs
   - Capture WAF sampled requests
   - Document attacker patterns
4. **Remediation**:
   - Patch vulnerable systems immediately
   - Review other security logs (WAF, ALB, application logs)
   - Implement additional detection rules

---

## 6. Compliance & Audit

### Documentation

- [ ] WAF rules documented in change log
- [ ] Access logs retained for 90 days
- [ ] Regular security audits scheduled
- [ ] Incident response procedures tested

### Compliance Checks

```bash
# Verify logging is enabled
aws wafv2 get-logging-configuration --resource-arn <WAF_ARN>

# List all WAF rules
aws wafv2 get-web-acl --id <WEB_ACL_ID> --scope REGIONAL --name <WEB_ACL_NAME>

# Verify tags
aws wafv2 list-tags-for-resource --resource-arn <WAF_ARN>
```

### Change Control

- All WAF changes must:
  - Go through version control (Git)
  - Be reviewed via pull request
  - Have supporting documentation
  - Include testing results

### Audit Trail

Enable CloudTrail to capture all WAF API calls:

```bash
# View recent WAF changes
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=UpdateWebACL \
  --max-results 10
```

---

## 7. Maintenance Schedule

### Daily
- Monitor CloudWatch dashboard
- Check for alarms/alerts
- Review blocked request summary

### Weekly
- Analyze blocked traffic patterns
- Check for false positives
- Review security bulletins for new CVEs

### Monthly
- Review WAF rule effectiveness
- Update documentation
- Assess rule changes needed
- Verify logging is working

### Quarterly
- Full security audit
- Penetration testing (if applicable)
- Review and update incident response procedures
- Assess coverage against new threats

---

## 8. Cost Optimization

### Cost Breakdown

- **Web ACL**: $5/month
- **Rules**: $1/month per rule
- **Requests**: $0.60 per million requests
- **CloudWatch Logs**: ~$0.50 per GB

### Ways to Optimize

1. **Adjust Sampling Rate**:
   ```hcl
   sampled_requests_enabled = true  # Set to false if costs are high
   ```

2. **Retention Policy**:
   ```hcl
   retention_in_days = 7  # Reduce CloudWatch retention
   ```

3. **Regional vs CloudFront**:
   - REGIONAL: Better for ALB/API Gateway
   - CLOUDFRONT: Only if needed for CDN

---

## 9. Disaster Recovery

### Backup & Restore

```bash
# Export WAF configuration
aws wafv2 get-web-acl \
  --id <WEB_ACL_ID> \
  --scope REGIONAL \
  --name <WEB_ACL_NAME> > waf-backup.json

# Maintain Terraform state backups
terraform state pull > terraform.state.backup

# Use S3 for state backup
# Enable versioning on S3 state bucket
```

### Recovery Procedure

1. Restore from Terraform state
2. Re-associate with resources
3. Verify in CloudWatch
4. Test with sample traffic

---

## 10. Security Incident Contacts

**Internal Security Team**: [Contact Information]  
**AWS Support**: [Your AWS Support Plan Contact]  
**External Incident Response**: [If applicable]

---

**Last Updated**: 2026-10-23  
**Review Cycle**: Quarterly

