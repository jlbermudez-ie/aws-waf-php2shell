# AWS WAF PHP2Shell RCE Mitigation - Architecture

## Overview Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                    Incoming HTTP/HTTPS Request                  │
└──────────────────────────┬──────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│         AWS Resource (ALB, API Gateway, or CloudFront)          │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐  │
│  │         AWS WAFv2 Web ACL (Regional/CloudFront)        │  │
│  │                                                         │  │
│  │  ┌──────────────────────────────────────────────────┐  │  │
│  │  │  Rule Priority 1: BlockSuspiciousRCEPatterns     │  │  │
│  │  │  ├─ Inspect: Query String                        │  │  │
│  │  │  ├─ Pattern 1: "system("                          │  │  │
│  │  │  │  ├─ Transform: URL_DECODE                      │  │  │
│  │  │  │  └─ Transform: LOWERCASE                       │  │  │
│  │  │  │                                                │  │  │
│  │  │  ├─ Pattern 2: "passthru("                         │  │  │
│  │  │  │  ├─ Transform: URL_DECODE                      │  │  │
│  │  │  │  └─ Transform: LOWERCASE                       │  │  │
│  │  │  │                                                │  │  │
│  │  │  └─ [Add additional patterns as needed]           │  │  │
│  │  └──────────────────────────────────────────────────┘  │  │
│  │                   │                  │                  │  │
│  │           ┌───────┴─────────┬────────┴──────────┐       │  │
│  │           │                 │                   │       │  │
│  │        MATCH              NO MATCH         (Error)      │  │
│  │           │                 │                   │       │  │
│  │           ▼                 ▼                   ▼       │  │
│  │        ┌─────┐           ┌──────┐          ┌──────┐   │  │
│  │        │BLOCK│           │ALLOW │          │BLOCK │   │  │
│  │        └─────┘           └──────┘          └──────┘   │  │
│  │                                                        │  │
│  │  ┌────────────────────────────────────────────────┐   │  │
│  │  │      Visibility Configuration                  │   │  │
│  │  ├─ CloudWatch Metrics: Enabled                   │   │  │
│  │  ├─ Metric Name: Php2ShellMitigationMetric        │   │  │
│  │  ├─ Sampled Requests: Enabled                     │   │  │
│  │  └─ CloudWatch Logs: Optional (configure as needed)   │  │
│  │                                                         │  │
│  └─────────────────────────────────────────────────────┘  │
│                                                            │
└────────────────────────────────────────────────────────────┘
         │                                          │
         │                                          │
   ┌─────┴──────────┐                        ┌─────┴──────┐
   │                │                        │            │
   ▼                ▼                        ▼            ▼
┌────────┐   ┌──────────────┐        ┌────────────┐  ┌─────────┐
│ ALLOW  │   │ Application  │        │ CloudWatch │  │ CloudWatch
│Request │   │   Backend    │        │  Metrics   │  │  Logs
│        │   │              │        │            │  │ (optional)
│ Logs   │   │ • ALB        │        │  • Blocked │  │
│        │   │ • API GW     │        │    Requests│  │ • Full
│        │   │ • Origin App │        │  • Allowed │  │   Requests
└────────┘   │              │        │    Requests│  │ • Patterns
             └──────────────┘        └────────────┘  │ • IPs
                                                     │ • URIs
                                                     └─────────┘
```

---

## Request Flow Diagram

### Normal Request (Allowed)

```
GET /products?id=123
          ↓
    AWS WAF Inspection
    ├─ Extract Query String: id=123
    ├─ URL Decode: id=123
    ├─ Lowercase: id=123
    ├─ Check for "system(": NO
    └─ Check for "passthru(": NO
          ↓
    Default Allow Action
          ↓
    Forward to Application (200 OK)
          ↓
    CloudWatch Metrics: AllowedRequests +1
```

### Malicious Request (Blocked)

```
GET /api/cmd?action=system(whoami)
          ↓
    AWS WAF Inspection
    ├─ Extract Query String: action=system(whoami)
    ├─ URL Decode: action=system(whoami)
    ├─ Lowercase: action=system(whoami)
    └─ Check for "system(": YES ✓ MATCH
          ↓
    BLOCK ACTION TRIGGERED
          ↓
    Return 403 Forbidden
          ↓
    CloudWatch Metrics & Logs
    ├─ BlockedRequests +1
    └─ Sampled Request captured
```

---

## Text Transformation Pipeline

### URL_DECODE → LOWERCASE Pipeline

```
Input:  action=SyStEm%28whoami%29
         ↓ (URL_DECODE)
         action=SyStEm(whoami)
         ↓ (LOWERCASE)
Output: action=system(whoami)
         ↓
         Pattern Match Check: "system("
         ↓
         MATCH FOUND → BLOCK REQUEST
```

---

## CloudWatch Integration

### Metrics Published

- **AllowedRequests**: Count of allowed requests
- **BlockedRequests**: Count of blocked requests
- **SampledRequests**: Sample of matched requests for analysis

### Log Structure

```json
{
  "timestamp": 1698079205000,
  "action": "BLOCK",
  "terminatingRuleId": "BlockSuspiciousRCEPatterns",
  "httpRequest": {
    "clientIp": "203.0.113.42",
    "uri": "/api/cmd?action=system(whoami)",
    "args": "action=system(whoami)",
    "httpMethod": "GET"
  }
}
```

---

**Last Updated**: 2026-10-23
