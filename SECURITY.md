# Security Policy

## Supported Versions

Only the latest release of `patch-tuesday-mcp` (PyPI package and Docker image)
receives security fixes.

## Reporting a Vulnerability

Please report vulnerabilities privately via GitHub's security advisory form:

https://github.com/jonnybottles/patch-tuesday-mcp/security/advisories/new

Do **not** open a public issue for security reports. You can expect an
acknowledgment within 7 days.

## Scope

- The `patch-tuesday-mcp` PyPI package (stdio transport)
- The `xxbutler21xx/patch-tuesday-mcp` Docker image (HTTP transport)
- The hosted endpoint
  `https://patch-tuesday-mcp.happyrock-b60185ec.eastus.azurecontainerapps.io/mcp`

The hosted endpoint is intentionally unauthenticated and rate-limited; it only
serves public MSRC/EPSS/KEV data. Testing that stays within the rate limits is
fine — please do not run sustained high-volume or availability (DoS) testing
against it.

## Hardening documentation

Deployment hardening guidance (CORS allowlist, proxy trust, rate/body/response
limits) lives in the README under "Hardening a public HTTP deployment".
