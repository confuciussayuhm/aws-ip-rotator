# AWS IP Rotator

A Burp Suite extension that manages AWS API Gateway proxies for IP rotation. Create, configure, and delete gateways directly from Burp — no external tools or Python dependencies needed. Every request to a configured domain is automatically rewritten to route through AWS API Gateway, rotating your source IP with each request.

Inspired by [fireprox](https://github.com/ustayready/fireprox) by [@ustayready](https://github.com/ustayready).

## Features

**Gateway Management**
- Create/update/delete API Gateways directly from Burp
- Bulk multi-region creation — spin up gateways in up to 16 AWS regions with one click
- Parallel operations — all AWS calls run in background threads (6-16x faster, never freezes Burp)
- Configurable stage names with built-in security blacklist
- Mass gateway setup via context menu with progress dialog and cancel support

**IP Rotation**
- Multiple gateways per domain for maximum IP diversity
- Three rotation strategies: Round Robin, Random, and Weighted Random
- Per-domain strategy configuration with adjustable gateway weights (1-100)
- Thread-safe rotation across concurrent Burp tools

**Request Routing**
- Automatic request rewriting (host, path, SNI) for configured domains
- Multiple simultaneous target domains, each with independent routing
- Optional `X-Original-Host` header for debugging
- Master enable/disable switch for instant kill

**Context Menu (right-click)**
- **Send to AWS IP Rotator > Create Gateways** — extract domains from selected requests, bulk-create gateways across regions, and auto-configure domain mappings
- **Send to AWS IP Rotator > Add Domain Mappings** — import domains without AWS credentials or gateway creation

**Persistence**
- Domain mappings, gateway assignments, rotation strategies, and enable state are saved to the Burp project file and restored on load

## Prerequisites

1. **Java 17+**
2. **Maven** (build from source)
3. **Burp Suite** Professional or Community
4. **AWS IAM user** with `apigateway:*` permissions (or scoped GET/POST/PUT/DELETE/PATCH)

## Building

```bash
cd aws-ip-rotator
mvn clean package
# Output: target/aws-ip-rotator-1.0.0.jar
```

## Installation

1. In Burp Suite, go to **Extensions > Installed > Add**
2. Set type to **Java**, select `target/aws-ip-rotator-1.0.0.jar`
3. Confirm "AWS IP Rotator loaded successfully!" in the Output tab

## Usage

### 1. Configure AWS Credentials

Open the **AWS IP Rotator** tab > **AWS Configuration** sub-tab. Choose an authentication method:

| Method | Source |
|--------|--------|
| **Default Credentials** | `~/.aws/credentials`, environment variables, or EC2 instance profile |
| **AWS Profile** | Named profile from `~/.aws/credentials` |
| **Access Key & Secret** | Explicit key pair entered in the UI |

Click **Test Connection to AWS** to validate. Credentials are not stored by the extension.

### 2. Create Gateways

**From the AWS Gateways tab:**

1. Click **Create Gateway**
2. Enter the target URL (e.g. `https://api.example.com`)
3. Set the stage name (default: `v1`) — see [Stage Name Security](#stage-name-security) below
4. Choose a single region or check **Create in multiple regions** (use **Select All Regions** for all 16)
5. Click **Create** — gateways are provisioned in parallel (~2-3s regardless of count)

Other operations: **Refresh List** (scans all 16 regions in ~500ms), **Use Selected** (auto-adds gateway to domain mappings), **Update Gateway**, **Delete Gateway** (multi-select supported).

**From the context menu (mass setup):**

1. Select requests in Proxy history, Site map, etc.
2. Right-click > **Send to AWS IP Rotator > Create Gateways**
3. Review extracted domains, choose regions and stage name
4. Click **Setup** — a progress dialog tracks each operation with a **Cancel** button

### 3. Configure Domain Mappings

In the **Domain Mappings** tab:

1. **Add Domain** — enter the target domain (e.g. `api.example.com`)
2. In the right panel, **Add Gateway** — paste or enter the gateway URL; region and weight are auto-detected
3. Repeat to add gateways from additional regions
4. Choose a **Rotation Strategy** (Round Robin / Random / Weighted Random)
5. Check **Enable IP Rotation** (master switch) to activate routing

To import domains without creating gateways: right-click requests > **Send to AWS IP Rotator > Add Domain Mappings**. This creates empty domain entries you can wire up to gateways later.

### 4. Verify

Send a request to a configured domain. In the extension output log you'll see:

```
[AWS IP Rotator] Request Rewritten:
  Original: https://api.example.com/v1/users
  Gateway:  https://abc123.execute-api.us-east-1.amazonaws.com/v1/v1/users
  Host Header: api.example.com -> abc123.execute-api.us-east-1.amazonaws.com
  Strategy: Round Robin
```

The extension rewrites the host, path, Host header, and SNI automatically. Original paths and query parameters are preserved.

## Stage Name Security

The extension blocks stage names that may trigger WAFs or security monitoring:

```
proxy, fireprox, api, aws, gateway, prod, production, dev, development,
test, staging, vpn, tunnel, forward, redirect, bypass, rotate, rotation,
security, pentest
```

Use neutral names instead: `v1`, `v2`, `release`, `alpha`, `beta`, `stable`. Stage names must match `[a-zA-Z0-9_-]+`.

## Troubleshooting

**Extension won't load** — Ensure Java 17+ is installed. Check **Extensions > Errors** for details.

**Requests not being rewritten** — Verify the master "Enable IP Rotation" checkbox is on, the domain is listed in mappings, and at least one gateway is assigned. Check the Output tab for logs.

**AWS connection fails** — Confirm IAM permissions (`apigateway:*`), verify credentials, and try explicit Access Key & Secret if default credentials aren't working.

**Stage name rejected** — The name is on the blacklist. Use `v1`, `v2`, `release`, `alpha`, or similar neutral names.

**403 from AWS** — Refresh the gateway list to confirm it still exists. Check AWS API Gateway quotas (600 per region default). Verify the gateway wasn't deleted from the AWS console.

## Notes

- **AWS costs**: API Gateway charges ~$3.50 per million requests after the free tier (first 1M calls/month on new accounts). Monitor your billing dashboard.
- **Limitations**: AWS API Gateway adds ~50-200ms latency per request. WebSocket upgrades are not supported. Rate limit is 10,000 req/s per region by default.
- **Security**: Use this tool only on systems you own or have explicit authorization to test. Misuse may violate the [AWS Acceptable Use Policy](https://aws.amazon.com/aup/) and lead to account termination.

## Credits & License

- Inspired by [fireprox](https://github.com/ustayready/fireprox) by [@ustayready](https://github.com/ustayready)
- Built on the [Burp Montoya API](https://portswigger.net/burp/documentation/desktop/extensions/montoya-api) by PortSwigger

Licensed under the [MIT License](LICENSE). For authorized security testing, penetration testing, bug bounty programs, and educational purposes only.
