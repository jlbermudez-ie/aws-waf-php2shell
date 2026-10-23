PHP2Shell (CVE-2026-109618 and CVE-2026-109619) is a pair of critical PHP core vulnerabilities that allow unauthenticated remote code execution. Both trigger while PHP parses the request body, before any application code runs, and exploitation has already been reported in the wild.

The fix is available: PHP 8.5.12, 8.4.27, 8.3.36 and 8.2.35. But patch deployment takes time, and in high-stakes security scenarios, defense-in-depth is non-negotiable.

How can security and DevOps teams buy critical time? Edge-level mitigation.

With AWS WAF, you can inspect incoming HTTP/HTTPS traffic and stop known PHP2Shell exploit requests before they reach your origin servers.

Key steps to protect your environment:

    Patch first: Upgrade PHP to a fixed release and restart every PHP worker. The flaw is in PHP itself, so updating frameworks or application code does not fix it. PHP 8.1 and older have no official fix.
    Deploy AWS WAF rules: Use the AWS managed PHP rule group (Version_2.3 or later, which adds PHP2Shell_BODY), plus custom rules for the session upload progress entry point, oversized request bodies, and the public exploit tool's signatures. Start in Count mode, then switch to Block.
    Harden the server: Set session.upload_progress.enabled = 0 until you have patched.
    Audit and monitor: Use Amazon CloudWatch and AWS WAF logs to spot probing and exploitation attempts.

WAF rules are a shield, not a cure: signatures can be bypassed, and only the PHP upgrade closes the flaw.

I put together a proof-of-concept Terraform configuration with these rules: https://github.com/jlbermudez-ie/aws-waf-php2shell

Security is a team sport, and layered defenses keep us a step ahead of threat actors. How is your team handling rapid-response mitigations at the edge? Let's discuss in the comments!

#CyberSecurity #AWS #CloudSecurity #AWSWAF #Infosec #VulnerabilityManagement #PHP #PHP2Shell
