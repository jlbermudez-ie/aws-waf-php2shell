# AWS WAF PHP2Shell RCE Mitigation

> **Proof of concept only**  
> This repository is a demonstration project for educational purposes. It is not intended for production use without thorough review, testing, and customization for your specific environment and security requirements.

**Rapid-response edge-level defense against CVE-2026-109618 and CVE-2026-109619 RCE vulnerabilities using AWS WAF.**

## Overview

This repository demonstrates how to leverage **AWS WAF (Web Application Firewall)** to provide immediate, defense-in-depth protection against Remote Code Execution (RCE) vulnerabilities affecting PHP environments—specifically CVE-2026-109618 and CVE-2026-109619 (PHP2Shell).

While patching remains the ultimate solution, patch deployment takes time. This solution enables security and DevOps teams to **block malicious payloads at the edge** within minutes, before they reach your application servers.

### Key features

- **Custom WAF rules**: Pattern-matching rules targeting RCE exploit signatures
- **Multi-layer detection**: Query string, headers, and request body inspection
- **Real-time monitoring**: CloudWatch integration for traffic analysis and threat detection
- **Infrastructure-as-code**: Terraform configuration for easy deployment and version control
- **Quick deployment**: Deploy in minutes, not hours

---

## Architecture

```
Incoming HTTP/HTTPS Request
          ↓
    AWS WAF Web ACL
          ↓
    Inspect & Decode
          ↓
    Pattern Matching
    (system( / passthru()...)
          ↓
    ┌─────────────┬──────────────┐
    ↓             ↓
BLOCK         ALLOW
(Log)          (Forward)
    ↓             ↓
CloudWatch   Application Backend
Metrics
```

See [Architecture Diagram](docs/ARCHITECTURE.md) for detailed flow visualization.

---

## Quick start

### Prerequisites

- AWS Account with IAM permissions for WAF, CloudWatch
- Terraform >= 1.0.0
- AWS Provider ~> 5.0
- An existing ALB, API Gateway, or CloudFront distribution to protect

### 1. Deploy the WAF Configuration

Clone this repository:

```bash
git clone https://github.com/jlbermudez-ie/aws-waf-php2shell.git
cd aws-waf-php2shell
```

Configure Terraform variables:

```bash
cd terraform
```

Update `terraform.tfvars` (create if not present):

```hcl
# Set your AWS region
aws_region = "us-east-1"  # Change as needed
```

Deploy:

```bash
terraform init
terraform plan
terraform apply
```

> **Important**: The Terraform configuration creates the WAF Web ACL but does **not** automatically associate it with any resource. You must manually associate it with your ALB, API Gateway, or CloudFront distribution (see next section).

### 2. Associate the WAF with your protected resource

After deployment, retrieve the Web ACL ARN from Terraform outputs:

```bash
terraform output -raw web_acl_arn
```

Then associate the WAF with your resource:

#### For Application Load Balancer (ALB)

First, get your ALB ARN:
```bash
aws elbv2 describe-load-balancers --query 'LoadBalancers[0].LoadBalancerArn' --output text
```

Then associate:
```bash
aws wafv2 associate-web-acl \
  --web-acl-arn arn:aws:wafv2:us-east-1:ACCOUNT_ID:regional/webacl/php2shell-rce-mitigation-acl/ID \
  --resource-arn arn:aws:elasticloadbalancing:us-east-1:ACCOUNT_ID:loadbalancer/app/my-alb/1234567890abcdef \
  --region us-east-1
```

#### For API Gateway

Get your API Gateway ARN:
```bash
aws apigateway get-rest-apis --query 'items[0].id' --output text
```

Associate:
```bash
aws wafv2 associate-web-acl \
  --web-acl-arn arn:aws:wafv2:us-east-1:ACCOUNT_ID:regional/webacl/php2shell-rce-mitigation-acl/ID \
  --resource-arn arn:aws:apigateway:us-east-1::/restapis/API_ID/stages/STAGE_NAME \
  --region us-east-1
```

#### For CloudFront

1. Update Terraform to use CloudFront scope in [terraform/main.tf](terraform/main.tf):
   ```hcl
   scope = "CLOUDFRONT"
   ```

2. Deploy in `us-east-1` region (CloudFront WAF requirement):
   ```bash
   terraform apply -var="aws_region=us-east-1"
   ```

3. In AWS Console, navigate to your CloudFront distribution:
   - Go to Settings → Security
   - Select the WAF Web ACL you created
   - Save changes

Or use AWS CLI:
```bash
aws cloudfront update-distribution \
  --id DISTRIBUTION_ID \
  --distribution-config '{
    "WebACLId": "arn:aws:wafv2:us-east-1:ACCOUNT_ID:global/webacl/php2shell-rce-mitigation-acl/ID"
  }'
```

---

## Monitoring and response

### View CloudWatch Metrics

```bash
# List all blocked requests in the last hour
aws cloudwatch get-metric-statistics \
  --namespace AWS/WAFV2 \
  --metric-name BlockedRequests \
  --dimensions Name=WebACL,Value=php2shell-rce-mitigation-acl \
  --start-time $(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%S) \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
  --period 300 \
  --statistics Sum
```

### Analyze Sampled Requests

```bash
# Get sampled blocked requests
aws wafv2 get-sampled-requests \
  --web-acl-arn <WAF_ACL_ARN> \
  --rule-metric-name BlockSuspiciousRCEPatternsMetric \
  --scope REGIONAL \
  --time-window StartTime=$(date -u -d '30 minutes ago' +%s),EndTime=$(date -u +%s) \
  --max-items 100
```

### CloudWatch Logs Insights Query

```
fields @timestamp, httpRequest.clientIp, action, httpRequest.uri
| filter action = "BLOCK"
| stats count() by clientIp, httpRequest.uri
| sort count() desc
```

---

## Configuration details

### WAF rules explained

**Rule: BlockSuspiciousRCEPatterns**

Detects and blocks requests containing:
- `system(` — PHP system command execution
- `passthru(` — PHP passthrough command execution

Each pattern is processed through:
1. **URL_DECODE**: Converts URL-encoded payloads to plain text
2. **LOWERCASE**: Normalizes case variations (e.g., `System(`, `SYSTEM(`)

**Match Scope**: Query strings (extend to headers/body as needed)

### Extending the WAF

To add more patterns, edit [terraform/main.tf](terraform/main.tf):

```hcl
statement {
  byte_match_statement {
    search_string         = "exec("
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
```

For regex-based detection:
```hcl
regex_match_statement {
  regex_string = "(?i)(system|passthru|exec|proc_open)\\s*\\("
  field_to_match {
    query_string {}
  }
}
```

---

## Repository structure

```
aws-waf-php2shell/
├── README.md                      # This file
├── docs/
│   ├── ARCHITECTURE.md           # WAF flow diagram
│   ├── LINKEDIN_POST.md          # Original LinkedIn post
│   └── BEST_PRACTICES.md         # Security recommendations
├── terraform/
│   ├── main.tf                   # WAF Web ACL configuration
│   ├── variables.tf              # Variable definitions
│   ├── outputs.tf                # Output definitions
│   └── terraform.tfvars.example  # Example variables
├── examples/
│   └── payloads.txt              # Test payloads (for authorized testing)
└── .gitignore                    # Git ignore patterns
```

---

## Important considerations

### 1. This is not a replacement for patching
   - WAF rules are a **temporary shield**, not a permanent fix
   - Prioritize patching your PHP runtimes and frameworks immediately
   - Use WAF as part of a **defense-in-depth strategy**

### 2. False positives
   - Monitor CloudWatch logs for legitimate requests that may be blocked
   - Adjust rule patterns based on your application's specific needs
   - Use the `COUNT` action instead of `BLOCK` for testing

### 3. Performance impact
   - WAF inspection adds minimal latency (typically <10ms)
   - CloudWatch logging may increase costs; review sampling settings
   - Use sampled requests for cost optimization

### 4. Scope selection
   - **REGIONAL**: For ALB, Network Load Balancer (NLB), API Gateway, AppSync
   - **CLOUDFRONT**: For CloudFront distributions (must be created in us-east-1)

---

## Security best practices

1. **Enable CloudWatch Logging**: Track all allowed and blocked requests
2. **Implement Rate Limiting**: Add additional WAF rules for brute-force protection
3. **Use AWS Managed Rules**: Consider AWS Managed Rules for OWASP Top 10 protection
4. **Regular Audits**: Review WAF logs weekly for pattern anomalies
5. **Least Privilege**: Apply WAF only where needed; avoid over-blocking
6. **Version Control**: Maintain Terraform configurations in Git with review process

---

## Testing and validation

### Test the WAF rules (authorized testing only)

**Only perform this against environments you own and control.**

```bash
# This should be BLOCKED
curl "https://your-alb-domain.com/?cmd=system(whoami)"

# This should be BLOCKED
curl "https://your-alb-domain.com/?param=passthru(id)"

# This should be ALLOWED
curl "https://your-alb-domain.com/?search=normal+query"
```

Check CloudWatch Logs for evidence of blocking:
```bash
aws wafv2 get-sampled-requests --web-acl-arn <ARN> --rule-metric-name BlockSuspiciousRCEPatternsMetric --scope REGIONAL --time-window StartTime=$(date -u -d '5 minutes ago' +%s),EndTime=$(date -u +%s) --max-items 10
```

---

## Additional resources

- [AWS WAF Developer Guide](https://docs.aws.amazon.com/waf/latest/developerguide/)
- [WAF Rule Statements Reference](https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-statements.html)
- [CVE-2026-109618 Details](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-109618)
- [CVE-2026-109619 Details](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-109619)
- [PHP Security Best Practices](https://www.php.net/manual/en/security.php)

---

---

## Connect and discuss

This project was inspired by real-world security challenges. If you found this helpful:

- **Star this repository** on GitHub
- **Share on LinkedIn** (original post available in [docs/LINKEDIN_POST.md](docs/LINKEDIN_POST.md))
- **Open an issue** with questions or improvements
- **Report security concerns** responsibly to your AWS account team

---

## Quick reference

| Action | Command |
|--------|---------|
| Deploy WAF | `cd terraform && terraform apply` |
| View blocked requests | `aws wafv2 get-sampled-requests --web-acl-arn <ARN> ...` |
| Destroy WAF | `cd terraform && terraform destroy` |
| Monitor metrics | AWS Console → CloudWatch → Metrics → AWS/WAFV2 |
| Test rules | `curl "https://domain/?cmd=system(whoami)"` |

---

**Last Updated**: 2026-10-23  
**Maintainer**: Jose Bermudez (@jlbermudez-ie)

