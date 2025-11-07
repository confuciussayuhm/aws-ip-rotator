# AWS IP Rotator

A comprehensive Burp Suite extension that integrates AWS API Gateway management for creating and managing FireProx gateways directly from Burp Suite. Automatically route requests through AWS API Gateway for IP address rotation.

This project was inspired by and reimplements the functionality of the [FireProx](https://github.com/ustayready/fireprox) tool by [@ustayready](https://github.com/ustayready), which pioneered the technique of using AWS API Gateway for rotating source IPs.

## Overview

This extension provides **complete AWS API Gateway management** directly within Burp Suite, eliminating the need for the separate Python FireProx tool. Create, manage, and delete FireProx gateways, then automatically rewrite HTTP requests to route through them. FireProx leverages AWS API Gateway to create pass-through proxies that rotate the source IP address with every request.

### Features

#### AWS Gateway Management
- ✅ **Create FireProx gateways** directly from Burp Suite
- ✅ **List all existing gateways** in your AWS account
- ✅ **Update gateway** target URLs on the fly
- ✅ **Delete gateways** when no longer needed
- ✅ **Multiple AWS authentication methods** (default credentials, profiles, explicit keys)
- ✅ **Multi-region support** - Create gateways in any AWS region
- ✅ **No Python dependencies** - Pure Java implementation

#### Multi-Region IP Rotation
- ✅ **Multiple gateways per domain** - Route one domain through multiple AWS regions simultaneously
- ✅ **Rotation strategies**:
  - **Round Robin** - Cycle through gateways sequentially
  - **Random** - Pick a random gateway for each request
  - **Weighted Random** - Prefer gateways based on configurable weights (1-100)
- ✅ **Automatic region detection** - Regions extracted from gateway URLs
- ✅ **Per-domain configuration** - Each domain can have its own rotation strategy
- ✅ **Thread-safe rotation** - Safe for concurrent requests across Burp tools

#### Request Routing
- ✅ **Multiple domain support** - Configure multiple target domains simultaneously
- ✅ **Automatic request rewriting** for specified target domains
- ✅ **SNI modification** to match FireProx gateway
- ✅ **Host header rewriting**
- ✅ **Preservation of original paths and query parameters**
- ✅ **Optional X-Original-Host header** for debugging
- ✅ **Easy configuration** through tabbed Burp UI
- ✅ **Enable/disable routing** on the fly

## Prerequisites

1. **Java 17 or higher**
2. **Maven** (for building from source)
3. **Burp Suite Professional or Community Edition**
4. **AWS Account** with API Gateway permissions
5. **AWS IAM User** with the following permissions:
   - `apigateway:*` (or more restrictive: GET, POST, PUT, DELETE, PATCH on API Gateway resources)
   - `execute-api:Invoke` (optional, for testing gateways)

**Note**: You no longer need the separate Python FireProx tool - this extension provides all functionality directly!

## Building the Extension

```bash
# Clone or download this project
cd aws-ip-rotator

# Build with Maven
mvn clean package

# The compiled JAR will be in: target/aws-ip-rotator-1.0.0.jar
```

## Installation

1. Open Burp Suite
2. Go to **Extensions** → **Installed**
3. Click **Add**
4. Select **Extension type**: Java
5. Select the JAR file: `target/aws-ip-rotator-1.0.0.jar`
6. Click **Next**
7. Check the **Output** tab for confirmation: "AWS IP Rotator loaded successfully!"

## Usage

### Step 1: Configure AWS Credentials

1. In Burp Suite, go to the **AWS IP Rotator** tab
2. Navigate to the **AWS Configuration** tab
3. Select your authentication method:
   - **Default Credentials**: Uses credentials from `~/.aws/credentials` or environment variables
   - **AWS Profile**: Uses a named profile from `~/.aws/credentials`
   - **Access Key & Secret**: Provide explicit AWS credentials
4. Select your AWS region (default: `us-east-1`)
5. Click **Connect to AWS**

### Step 2: Create FireProx Gateways

1. Navigate to the **AWS Gateways** tab
2. Click **Create Gateway**
3. In the gateway creation dialog:
   - Enter the target URL (e.g., `https://api.example.com`)
   - **Single Region**: Select a region from the dropdown (default: us-east-1)
   - **Multiple Regions**: Check "Create in multiple regions" and select all desired regions
4. Click **Create**
5. The extension will:
   - Create AWS API Gateway(s) with proxy configuration in selected region(s)
   - Deploy each to the "proxy" stage
   - Display the new gateway(s) in the table with their proxy URLs

**Region Selection Benefits:**
- Create the same gateway in multiple AWS regions with one click
- No need to manually reconnect to different regions
- Ideal for setting up multi-region rotation instantly

**Other Gateway Management Operations:**
- **Refresh List**: Reload all gateways from AWS
- **Use Selected**: Automatically add the selected gateway to domain mappings
- **Update Gateway**: Change the target URL for an existing gateway
- **Delete Gateway**: Permanently remove a gateway from AWS

### Step 3: Configure Domain Mappings with Multi-Region Rotation

The extension supports routing a single domain through multiple AWS gateways across different regions for enhanced IP diversity.

#### Adding a Domain with Multiple Gateways:

1. Navigate to the **Domain Mappings** tab
2. Click **Add Domain** and enter the target domain (e.g., `api.example.com`)
3. In the right panel, add multiple gateways for this domain:
   - Click **Add Gateway**
   - Enter or paste the gateway URL
   - The region is automatically detected from the URL
   - Set the weight (1-100) for weighted random rotation (default: 50)
   - Repeat to add gateways from different AWS regions
4. Select a **Rotation Strategy**:
   - **Round Robin**: Cycles through gateways sequentially (fair distribution)
   - **Random**: Picks a random gateway for each request
   - **Weighted Random**: Selects gateways based on their weights (higher weight = more requests)
5. Check **Enable automatic IP rotation with multi-region support** to activate

#### Single vs Multi-Region Configuration:

**Single Gateway (Traditional)**:
- One domain → One gateway → One AWS region → Limited IP diversity

**Multi-Region (New)**:
- One domain → Multiple gateways → Multiple AWS regions → Maximum IP diversity
- Example: `api.target.com` can rotate through gateways in us-east-1, eu-west-1, and ap-southeast-1

#### Domain Management:
- **Add Domain**: Create a new domain configuration
- **Edit Domain**: Modify domain or add/remove gateways (or double-click a row)
- **Delete Domain**: Remove a domain and all its gateways
- **Clear All**: Remove all configured domains

#### Gateway Management (per domain):
- **Add Gateway**: Add another region's gateway to the selected domain
- **Edit Gateway**: Modify URL or weight
- **Remove Gateway**: Remove a specific gateway from the domain
- **Change Strategy**: Switch between Round Robin, Random, or Weighted Random

### Step 4: Test

Make a request to your configured target domain through Burp:
- Original request: `https://api.example.com/v1/users`
- Automatically rewritten to: `https://abc123xyz.execute-api.us-east-1.amazonaws.com/proxy/v1/users`

The extension automatically:
- Changes the destination to the FireProx gateway
- Updates the Host header
- Sets the correct SNI
- Preserves the original path and parameters
- Rotates IP address with each request via AWS

## How It Works

When you make a request to any configured target domain:

1. **Request Interception**: The extension intercepts outgoing requests
2. **Domain Matching**: Checks if the request matches any configured target domain (case-insensitive)
3. **Gateway Selection**: Based on the domain's rotation strategy:
   - **Round Robin**: Uses an AtomicInteger to cycle through gateways (thread-safe)
   - **Random**: Uses `java.util.Random` to pick any gateway
   - **Weighted Random**: Uses cumulative probability distribution based on gateway weights
4. **Request Rewriting**:
   - Updates HTTP service to point to the selected FireProx gateway
   - Rewrites Host header to FireProx gateway hostname
   - Prepends FireProx path to the original request path
   - Optionally adds X-Original-Host header
5. **SNI Handling**: The Montoya API automatically sets the correct SNI based on the new HTTP service

Each domain is independently routed through its configured gateways with automatic multi-region rotation, providing maximum IP diversity across AWS regions.

## Example Configuration

### Example 1: Single Domain, Single Region (Basic)

**Scenario**: You want to scan `api.target.com` through one FireProx gateway

**Configuration**:
1. Create one gateway in `us-east-1` for `https://api.target.com`
2. Add domain `api.target.com` with this gateway
3. Enable rotation

**Result**:
- Request to: `https://api.target.com/users/123`
- Routes through: `https://a1b2c3d4.execute-api.us-east-1.amazonaws.com/proxy/users/123`
- IP rotates via AWS API Gateway (single region)

### Example 2: Single Domain, Multi-Region (Maximum IP Diversity)

**Scenario**: You want to scan `api.target.com` with maximum IP rotation across multiple AWS regions

**Configuration**:
1. Go to **AWS Gateways** tab and click **Create Gateway**
2. Enter target URL: `https://api.target.com`
3. Check "Create in multiple regions"
4. Select regions: `us-east-1`, `eu-west-1`, `ap-southeast-1`
5. Click **Create** - all three gateways are created simultaneously
6. Go to **Domain Mappings** tab
7. Add domain `api.target.com`
8. Add all three gateways to this domain:
   - Gateway A (us-east-1) - Weight: 50
   - Gateway B (eu-west-1) - Weight: 50
   - Gateway C (ap-southeast-1) - Weight: 50
9. Select **Round Robin** rotation strategy
10. Enable rotation

**Result Configuration**:
| Domain | Gateway | Region | Weight | Strategy |
|--------|---------|--------|--------|----------|
| `api.target.com` | Gateway A | us-east-1 | 50 | Round Robin |
| | Gateway B | eu-west-1 | 50 | |
| | Gateway C | ap-southeast-1 | 50 | |

**Result**:
- Request 1: Routes through us-east-1 gateway
- Request 2: Routes through eu-west-1 gateway
- Request 3: Routes through ap-southeast-1 gateway
- Request 4: Routes through us-east-1 gateway (cycle repeats)
- Each region provides different source IPs, maximizing IP diversity

### Example 3: Multiple Domains, Multi-Region

**Scenario**: You're testing multiple targets, each through multiple regions

**Configuration**:
1. **Domain 1**: `api.example.com`
   - Gateway in us-east-1, Weight: 70
   - Gateway in eu-west-1, Weight: 30
   - Strategy: Weighted Random (prefer US region)

2. **Domain 2**: `admin.target.com`
   - Gateway in ap-southeast-1, Weight: 50
   - Gateway in us-west-2, Weight: 50
   - Strategy: Random

3. **Domain 3**: `cdn.another.net`
   - Gateway in eu-central-1, Weight: 33
   - Gateway in us-east-1, Weight: 33
   - Gateway in ap-northeast-1, Weight: 34
   - Strategy: Round Robin

**Result**:
- All three domains route simultaneously through their own multi-region gateways
- Each domain uses its own rotation strategy independently
- Maximum IP diversity across multiple AWS regions for each target

## Logging

The extension logs all activity to Burp's extension output. Check the **Extensions** → **Installed** → **Output** tab to see:
- Configuration changes
- Request routing details
- Any errors or warnings

## Troubleshooting

### Extension doesn't load
- Ensure you're using Java 17 or higher
- Check Burp's Extensions → Errors tab for details

### Requests aren't being modified
- Verify "Enable FireProx routing" is checked in the **Domain Mappings** tab
- Confirm you have added the target domain to the mappings table
- Confirm the target domain matches exactly (case-insensitive)
- Check Burp's Extensions → Output tab for log messages

### Cannot connect to AWS
- Verify your AWS credentials are correct
- Ensure your IAM user has `apigateway:*` permissions
- Check your AWS region is correct
- For default credentials, ensure `~/.aws/credentials` exists and is properly formatted
- Try explicit Access Key & Secret authentication method

### Gateway creation fails
- Verify API Gateway service is available in your selected region
- Check IAM permissions include `apigateway:POST`, `apigateway:PUT`
- Ensure you haven't hit AWS API Gateway account limits
- Check Burp's Extensions → Errors tab for detailed error messages

### 403 Forbidden from AWS
- Verify your FireProx gateway is active by refreshing the gateway list in the **AWS Gateways** tab
- Ensure the gateway URL is correct in your domain mappings
- Check AWS API Gateway quotas and limits
- Verify the gateway wasn't manually deleted from AWS console

### SNI issues
- The extension sets the HTTP service which automatically configures SNI
- Ensure TLS pass-through is not interfering with the connection

## AWS Costs

**Important**: AWS API Gateway usage incurs costs. As of 2024:
- First 1 million API calls per month: Free tier (new AWS accounts)
- After free tier: ~$3.50 per million requests
- Data transfer: Standard AWS rates apply

Monitor your AWS billing dashboard when using FireProx gateways extensively.

## Limitations

- Does not automatically handle WebSocket upgrades
- FireProx gateways have AWS API Gateway rate limits (10,000 requests per second per region by default)
- Each domain should have its own dedicated FireProx gateway for best results
- AWS API Gateway may add latency (typically 50-200ms per request)

## Security Considerations

⚠️ **Important**: Use this tool only on systems you own or have explicit permission to test. Improper use may violate the [AWS Acceptable Use Policy](https://aws.amazon.com/aup/) and could lead to account termination.

## Contributing

Issues and pull requests are welcome! Please ensure:
- Code follows existing style
- Changes are tested with Burp Suite
- README is updated for new features

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

**Usage Notice**: This tool is intended for authorized security testing, penetration testing, bug bounty programs, and educational purposes only. See the LICENSE file for full terms and conditions.

## Credits

- **FireProx**: [ustayready/fireprox](https://github.com/ustayready/fireprox)
- **Burp Montoya API**: [PortSwigger](https://portswigger.net/burp/documentation/desktop/extensions/montoya-api)

## Support

For issues related to:
- **This extension**: Open an issue in this repository
- **FireProx**: Visit the [FireProx repository](https://github.com/ustayready/fireprox)
- **Burp Suite**: Check [PortSwigger Support](https://portswigger.net/support)
