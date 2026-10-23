# AWS WAF PHP2Shell RCE mitigation

> **Proof of concept only**  
> This repository is a demonstration project for educational purposes. It is not intended for production use without thorough review, testing, and customization for your specific environment and security requirements.

**Temporary edge-level mitigations for the PHP2Shell vulnerabilities (CVE-2026-109618 and CVE-2026-109619) using AWS WAF.**

## Overview

PHP2Shell is the name given to two critical PHP core vulnerabilities disclosed on 2026-10-21. Both allow unauthenticated remote code execution with the privileges of the PHP worker (CVSS v4.0 9.2).

| CVE | Root cause | How it is triggered |
|-----|------------|---------------------|
| CVE-2026-109618 | Memory corruption when PHP runs out of memory while setting up a request | A large request body that exhausts memory before application code runs |
| CVE-2026-109619 | A PHP worker reuses stale state from a previous request | PHP's session upload progress feature (`PHP_SESSION_UPLOAD_PROGRESS`) in multipart requests |

Both flaws trigger while PHP parses the request body, **before your application code runs**. The attacker's command does not appear in the URL, so signatures such as `system(` in the query string do not detect this exploit.

**The only fix is to upgrade PHP** to 8.5.12, 8.4.27, 8.3.36 or 8.2.35 (or a vendor backport) and restart every PHP worker. This repository deploys AWS WAF rules that reduce exposure while you patch.

### What gets deployed

- AWS managed PHP rule group (`AWSManagedRulesPHPRuleSet` `Version_2.3`), which adds `PHP2Shell_BODY` for CVE-2026-109619
- Custom rules for the public exploit tool's User-Agent and multipart boundaries
- A custom rule for the session upload progress entry point (CVE-2026-109619)
- Optional rules for oversize bodies (CVE-2026-109618) and all multipart requests
- A global `rule_action` switch so every rule starts in `COUNT` and moves to `BLOCK` after review

---

## Architecture

```
Incoming HTTP/HTTPS request
          ↓
    AWS WAF Web ACL
          ↓
    0  AWS managed PHP rules (PHP2Shell_BODY)
    1  User-Agent starts with "php2shell"
    2  Exploit tool multipart boundary
    3  POST + PHP_SESSION_UPLOAD_PROGRESS + PHPSESSID
    4  Body larger than 8 KB              (optional)
    5  Any multipart request               (optional)
          ↓
    ┌─────────────┬──────────────┐
    ↓             ↓
  MATCH        NO MATCH
COUNT/BLOCK     ALLOW
    ↓             ↓
CloudWatch   Application backend
metrics
```
---

## Quick start

### Prerequisites

- AWS account with IAM permissions for WAF and CloudWatch
- Terraform >= 1.0.0
- AWS provider ~> 5.0
- An existing ALB, API Gateway, or CloudFront distribution to protect

### 1. Deploy the WAF configuration

```bash
git clone https://github.com/jlbermudez-ie/aws-waf-php2shell.git
cd aws-waf-php2shell/terraform
cp terraform.tfvars.example terraform.tfvars
```

Edit `terraform.tfvars`. The main settings are:

```hcl
aws_region    = "us-east-1"
web_acl_scope = "REGIONAL"   # "CLOUDFRONT" for CloudFront (requires us-east-1)

rule_action = "COUNT"        # Switch to "BLOCK" after reviewing matches

enable_oversize_body_block = true   # Set false if the app accepts uploads larger than 8 KB
enable_multipart_block     = true   # Set false if the app accepts file uploads or multipart forms
```

Deploy:

```bash
terraform init
terraform plan
terraform apply
```

> **Important**: The Terraform configuration creates the WAF Web ACL but does **not** associate it with any resource. Until you associate it with your ALB, API Gateway, or CloudFront distribution (see next section), it protects nothing.

### 2. Associate the WAF with your protected resource

Retrieve the Web ACL ARN from the Terraform outputs:

```bash
terraform output -raw web_acl_arn
```

#### For Application Load Balancer (ALB)

Find your ALB ARN:
```bash
aws elbv2 describe-load-balancers \
  --query 'LoadBalancers[].[LoadBalancerName,LoadBalancerArn]' --output table
```

Associate:
```bash
aws wafv2 associate-web-acl \
  --web-acl-arn "$(terraform output -raw web_acl_arn)" \
  --resource-arn arn:aws:elasticloadbalancing:REGION:ACCOUNT_ID:loadbalancer/app/my-alb/1234567890abcdef \
  --region REGION
```

#### For API Gateway (REST API)

Find your API ID and stage:
```bash
aws apigateway get-rest-apis --query 'items[].[name,id]' --output table
aws apigateway get-stages --rest-api-id API_ID --query 'item[].stageName'
```

Associate:
```bash
aws wafv2 associate-web-acl \
  --web-acl-arn "$(terraform output -raw web_acl_arn)" \
  --resource-arn arn:aws:apigateway:REGION::/restapis/API_ID/stages/STAGE_NAME \
  --region REGION
```

#### For CloudFront

1. Set the scope and region in `terraform.tfvars`, then apply:
   ```hcl
   aws_region    = "us-east-1"
   web_acl_scope = "CLOUDFRONT"
   ```

2. Attach the Web ACL to the distribution. `associate-web-acl` does not work for CloudFront; the Web ACL is set on the distribution itself.

   In the AWS Console: CloudFront → your distribution → **General** → **Edit** → **AWS WAF web ACL** → select the Web ACL → **Save changes**.

   Or with the AWS CLI:
   ```bash
   aws cloudfront get-distribution-config --id DISTRIBUTION_ID > dist.json
   ETAG=$(jq -r '.ETag' dist.json)
   jq --arg acl "$(terraform output -raw web_acl_arn)" \
     '.DistributionConfig.WebACLId = $acl | .DistributionConfig' dist.json > dist-config.json
   aws cloudfront update-distribution \
     --id DISTRIBUTION_ID \
     --if-match "$ETAG" \
     --distribution-config file://dist-config.json
   ```

### 3. Review matches, then block

All rules start in `COUNT`. Review the sampled requests (see below) for 24 to 48 hours, disable any optional rule that matches legitimate traffic, then set `rule_action = "BLOCK"` and apply again.

---

## Monitoring and response

### View CloudWatch metrics

Each rule publishes a metric with the same name as the rule. While rules are in `COUNT`, look at `CountedRequests`; after switching to `BLOCK`, look at `BlockedRequests`.

```bash
aws cloudwatch get-metric-statistics \
  --namespace AWS/WAFV2 \
  --metric-name CountedRequests \
  --dimensions Name=WebACL,Value=php2shell-rce-mitigation-acl Name=Region,Value=REGION Name=Rule,Value=php2shell-Upload-Progress-Block \
  --start-time $(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%S) \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
  --period 300 \
  --statistics Sum
```

### Analyze sampled requests

```bash
aws wafv2 get-sampled-requests \
  --web-acl-arn "$(terraform output -raw web_acl_arn)" \
  --rule-metric-name php2shell-Upload-Progress-Block \
  --scope REGIONAL \
  --time-window StartTime=$(date -u -d '30 minutes ago' +%s),EndTime=$(date -u +%s) \
  --max-items 100
```

Rule metric names: `php2shell-AWS-PHP-Managed-Rules`, `php2shell-UserAgent-Block`, `php2shell-Exploit-Boundary-Block`, `php2shell-Upload-Progress-Block`, `php2shell-Oversize-Body-Block`, `php2shell-Temporary-Multipart-Block`.

### CloudWatch Logs Insights query

Requires WAF logging to be enabled on the Web ACL (not configured by this Terraform).

```
fields @timestamp, httpRequest.clientIp, action, terminatingRuleId, httpRequest.uri
| filter action = "BLOCK" or ispresent(nonTerminatingMatchingRules.0.ruleId)
| stats count() by httpRequest.clientIp, terminatingRuleId
| sort count() desc
```

---

## Configuration details

### WAF rules explained

| Priority | Rule | Matches | Covers | Caveats |
|----------|------|---------|--------|---------|
| 0 | `php2shell-AWS-PHP-Managed-Rules` | AWS managed PHP rule group, including `PHP2Shell_BODY` | CVE-2026-109619 | Requires `Version_2.3` or later. 100 WCUs |
| 1 | `php2shell-UserAgent-Block` | `User-Agent` starting with `php2shell` | Public exploit tool | Attackers can change the User-Agent trivially |
| 2 | `php2shell-Exploit-Boundary-Block` | Multipart boundary `B7kQpoc618` or `B7kQpoc619` in `Content-Type` | Public exploit tool | Modified tools may change the boundary |
| 3 | `php2shell-Upload-Progress-Block` | `POST` + `PHP_SESSION_UPLOAD_PROGRESS` in body + `PHPSESSID` in cookie or body | CVE-2026-109619 | Blocks legitimate upload progress bars. Misses servers that renamed `session.upload_progress.name` |
| 4 | `php2shell-Oversize-Body-Block` (optional) | Body larger than `max_body_size_bytes` (8 KB) | CVE-2026-109618 | Breaks uploads and large forms |
| 5 | `php2shell-Temporary-Multipart-Block` (optional) | Any `multipart/` `Content-Type` | Every known trigger | Breaks all file uploads and multipart forms |

### Inspection limits

AWS WAF inspects only the first 8 KB of the body on ALB and AppSync (16 KB by default on CloudFront and API Gateway, configurable up to 64 KB). Content after that limit is not inspected by the body match rules. The oversize body rule uses `oversize_handling = "MATCH"`, so any body beyond the limit matches it.

### Server-side mitigations

Apply these on the PHP servers as well, then restart every worker:

```ini
session.upload_progress.enabled = 0
; PHP 8.5 only
fatal_error_backtraces = 0
```

---

## Repository structure

```
aws-waf-php2shell/
├── README.md                      # This file
├── docs/
│   └── LINKEDIN_POST.md          # Original LinkedIn post
├── terraform/
│   ├── main.tf                   # WAF Web ACL configuration
│   ├── variables.tf              # Variable definitions
│   ├── outputs.tf                # Output definitions
│   └── terraform.tfvars.example  # Example variables
├── examples/
│   └── payloads.txt              # Signature test requests (for authorized testing)
└── .gitignore                    # Git ignore patterns
```

---

## Important considerations

### 1. This is not a replacement for patching
   - WAF rules are a **temporary shield**, not a fix. PHP states that no configuration change fully mitigates these vulnerabilities
   - Upgrade to PHP 8.5.12, 8.4.27, 8.3.36 or 8.2.35 and restart all workers
   - PHP 8.1 and older have no official fix; upgrade or use a vendor backport
   - If a system cannot be patched quickly, restrict internet access to it

### 2. Signatures can be bypassed
   - The User-Agent and boundary rules only catch the unmodified public tool
   - Attackers are already changing payloads to evade signatures
   - Requests whose malicious content sits beyond the WAF body inspection limit are only caught by the oversize body rule

### 3. False positives
   - The multipart, oversize body and upload progress rules all affect legitimate uploads
   - Keep `rule_action = "COUNT"` until you have reviewed sampled requests
   - Disable `enable_multipart_block` and `enable_oversize_body_block` on apps that accept uploads, or scope them to non-upload paths

### 4. Scope selection
   - **REGIONAL**: For ALB, API Gateway, AppSync
   - **CLOUDFRONT**: For CloudFront distributions (must be created in us-east-1)

---

## Security best practices

1. **Enable CloudWatch logging**: Track all allowed and blocked requests
2. **Pin managed rule versions deliberately**: Never pin `AWSManagedRulesPHPRuleSet` below `Version_2.3`
3. **Implement rate limiting**: Add a rate-based rule for POST requests based on your normal traffic
4. **Regular audits**: Review WAF logs for new exploit variants
5. **Version control**: Maintain Terraform configurations in Git with a review process

---

## Testing and validation

### Test the WAF rules (authorized testing only)

**Only perform this against environments you own and control.** These requests only carry the signatures the rules look for; they do not contain an exploit.

```bash
# User-Agent rule: should match
curl -A "php2shell-test" "https://your-domain.com/"

# Exploit boundary rule: should match
curl -H "Content-Type: multipart/form-data; boundary=B7kQpoc618" \
  --data-binary $'--B7kQpoc618\r\nContent-Disposition: form-data; name="a"\r\n\r\n1\r\n--B7kQpoc618--\r\n' \
  "https://your-domain.com/"

# Upload progress rule: should match
curl -b "PHPSESSID=test" -F "PHP_SESSION_UPLOAD_PROGRESS=test" "https://your-domain.com/"

# Normal request: should be allowed
curl "https://your-domain.com/?search=normal+query"
```

In `COUNT` mode every request returns normally; check the sampled requests instead. In `BLOCK` mode the matching requests return `403 Forbidden`.

See [examples/payloads.txt](examples/payloads.txt) for more test cases.

---

## Additional resources

- [CVE-2026-109618](https://nvd.nist.gov/vuln/detail/cve-2026-109618)
- [CVE-2026-109619](https://nvd.nist.gov/vuln/detail/cve-2026-109619)
---

## Connect and discuss

This project was inspired by real-world security challenges. If you found this helpful:

- **Star this repository** on GitHub
---

## Quick reference

| Action | Command |
|--------|---------|
| Deploy WAF | `cd terraform && terraform apply` |
| Switch to blocking | `terraform apply -var="rule_action=BLOCK"` |
| View matched requests | `aws wafv2 get-sampled-requests --web-acl-arn <ARN> ...` |
| Destroy WAF | `cd terraform && terraform destroy` |
| Monitor metrics | AWS Console → CloudWatch → Metrics → AWS/WAFV2 |

---

**Last updated**: 2026-10-23  
**Maintainer**: Jose Bermudez (@jlbermudez-ie)
