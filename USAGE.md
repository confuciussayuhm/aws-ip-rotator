# AWS IP Rotator Usage Guide

## Quick Start

### 1. Configure AWS Credentials

1. Open Burp Suite and go to the **AWS IP Rotator** tab
2. Navigate to **AWS Configuration** tab
3. Select authentication method (Default Credentials, AWS Profile, or Access Key)
4. Choose your AWS region (e.g., `us-east-1`)
5. Click **Connect to AWS**

### 2. Create FireProx Gateway(s)

**Option A - Single Region Gateway:**
1. Go to **AWS Gateways** tab
2. Click **Create Gateway**
3. Enter target URL: `https://api.example.com`
4. Select region from dropdown (e.g., `us-east-1`)
5. Click **Create**
6. Gateway is created and appears in the table

**Option B - Multi-Region Bulk Creation (for maximum IP diversity):**
1. Go to **AWS Gateways** tab
2. Click **Create Gateway**
3. Enter target URL: `https://api.example.com`
4. Check ☑ **"Create in multiple regions"**
5. Select all desired regions (e.g., `us-east-1`, `eu-west-1`, `ap-southeast-1`)
6. Click **Create**
7. All gateways are created simultaneously in all selected regions
8. All appear in the gateways table

### 3. Configure Domain Mappings

1. Go to **Domain Mappings** tab
2. Click **Add Domain**, enter: `api.example.com`
3. In the right panel, add your gateway(s):
   - Click **Add Gateway**
   - Paste the gateway URL from the AWS Gateways tab
   - Set weight (default: 50)
   - Repeat to add more gateways from different regions
4. Select rotation strategy (Round Robin, Random, or Weighted Random)
5. Check ✓ **Enable automatic IP rotation with multi-region support**

### 4. Test the Configuration

Make a request to your target domain through Burp:

```http
GET /v1/users HTTP/1.1
Host: api.example.com
```

The extension will automatically rewrite it to route through your selected gateway:

```http
GET /proxy/v1/users HTTP/1.1
Host: abc123xyz.execute-api.us-east-1.amazonaws.com
X-Original-Host: api.example.com
```

With multi-region rotation, subsequent requests will cycle through your configured gateways across different AWS regions.

## Detailed Examples

### Example 1: Single Region API Testing

**Goal**: Test an API at `https://api.target.com` with rotating IPs from one region

**Steps**:
1. Connect to AWS (us-east-1)
2. Create gateway for `https://api.target.com`
3. Add domain `api.target.com` with this gateway
4. Enable rotation
5. Send requests through Burp

**Result**: All requests to `api.target.com` automatically route through the us-east-1 gateway with IP rotation.

### Example 2: Multi-Region Maximum IP Diversity

**Goal**: Scan `https://api.target.com` with maximum IP diversity across 3 AWS regions

**Steps**:
1. **Create gateways in multiple regions (easy way):**
   - Go to **AWS Gateways** tab → Click **Create Gateway**
   - Enter URL: `https://api.target.com`
   - Check "Create in multiple regions"
   - Select: `us-east-1`, `eu-west-1`, `ap-southeast-1`
   - Click **Create** → All 3 gateways created at once!

2. **Configure domain with all gateways:**
   - Add domain: `api.target.com`
   - Add all 3 gateway URLs to this domain
   - Select **Round Robin** strategy
   - Enable rotation

3. **Test the rotation:**
   - Request 1 → Routes through us-east-1 (IP from Virginia)
   - Request 2 → Routes through eu-west-1 (IP from Ireland)
   - Request 3 → Routes through ap-southeast-1 (IP from Singapore)
   - Request 4 → Routes through us-east-1 (cycle repeats)

**Result**: Maximum IP diversity with source IPs rotating across 3 different geographic regions.

### Example 3: Weighted Multi-Region Strategy

**Goal**: Prefer one region but occasionally use others for diversity

**Steps**:
1. Create gateways:
   - `us-east-1` for `https://api.target.com`
   - `eu-west-1` for `https://api.target.com`

2. Configure domain with weighted strategy:
   - Add domain: `api.target.com`
   - Add us-east-1 gateway, set weight: **80**
   - Add eu-west-1 gateway, set weight: **20**
   - Select **Weighted Random** strategy
   - Enable rotation

**Result**: ~80% of requests use us-east-1 (lower latency), ~20% use eu-west-1 (IP diversity)

## Advanced Configuration

### Preserving Original Host Header

When **Preserve original Host in X-Original-Host header** is enabled, the extension adds an `X-Original-Host` header containing the original target domain. This is useful for:

- Debugging
- Logging which target was accessed
- Applications that need to know the original intended host

### Request Flow Visualization

```
[Burp Browser/Tool]
        ↓
   [FireProx Extension]
   - Intercepts request
   - Rewrites headers
   - Changes destination
        ↓
   [AWS API Gateway]
   - Rotates source IP
   - Forwards to target
        ↓
   [Target Server]
```

## Managing FireProx Gateways

All gateway management is done directly from the Burp Suite extension - no command-line tools required!

### Listing Gateways
1. Go to **AWS Gateways** tab
2. Click **Refresh List**
3. All gateways in the current AWS region are displayed

### Deleting a Gateway
1. Go to **AWS Gateways** tab
2. Select the gateway to delete
3. Click **Delete Gateway**
4. Gateway is permanently removed from AWS

### Updating a Gateway
1. Go to **AWS Gateways** tab
2. Select the gateway to update
3. Click **Update Gateway**
4. Enter new target URL
5. Gateway is updated in AWS

## Best Practices

### 1. Use Appropriate AWS Regions
Choose regions geographically close to your target for better performance.

### 2. Monitor AWS Costs
API Gateway usage incurs costs. Monitor your AWS billing dashboard.

### 3. Respect Rate Limits
Even with IP rotation, respect application rate limits and terms of service.

### 4. Clean Up Unused Gateways
Delete FireProx gateways when no longer needed to avoid unnecessary charges.

**Steps**:
1. Go to **AWS Gateways** tab
2. Click **Refresh List** to see all gateways
3. Select unused gateways
4. Click **Delete Gateway** for each one
5. Confirm deletion

### 5. Test Configuration First
Before running a full scan, test with a single request to verify the configuration works.

## Troubleshooting

### Problem: Requests not being routed

**Check**:
1. Extension is enabled (checkbox checked)
2. Target domain matches exactly
3. FireProx gateway URL is correct (including `/fireprox`)

**Debug**:
- Check Burp Extensions → Output tab for logs
- Look for messages like: "Routing request through FireProx: ..."

### Problem: 403 Forbidden from AWS

**Causes**:
- FireProx gateway was deleted
- AWS credentials expired
- API Gateway quota exceeded

**Solution**:
1. Go to **AWS Gateways** tab
2. Click **Refresh List** to verify gateway still exists
3. If missing, create a new gateway for your target URL
4. Update the Domain Mappings to use the new gateway URL

### Problem: SSL/TLS errors

**Causes**:
- SNI mismatch
- Certificate validation issues

**Solution**:
- Ensure target uses valid SSL certificates
- Check Burp's SSL pass-through settings
- Verify FireProx gateway URL uses `https://`

### Problem: Target application doesn't work

**Causes**:
- Application checks X-Forwarded-For header
- Application uses client IP for session management
- WebSocket connections not supported

**Solution**:
- Some applications may not work through proxies
- Test with simple requests first
- Check application logs if available

## Performance Tips

### 1. Connection Reuse
API Gateway reuses connections to the backend, improving performance for multiple requests to the same target.

### 2. Regional Selection
Choose AWS regions close to your target to minimize latency.

### 3. Request Batching
For bulk operations, consider batching requests when possible to reduce overhead.

## Security Notes

⚠️ **Authorization Required**: Only use this tool on systems you own or have explicit written permission to test.

⚠️ **AWS Policy Compliance**: Ensure your testing complies with the [AWS Acceptable Use Policy](https://aws.amazon.com/aup/).

⚠️ **Responsible Disclosure**: If you discover vulnerabilities, follow responsible disclosure practices.

⚠️ **Rate Limiting**: Respect application rate limits even when rotating IPs.

## Example Workflow: Bug Bounty

**Scenario**: Testing a bug bounty target with multi-region IP rotation

**Steps**:
1. **Set up AWS gateways** (multi-region for maximum diversity):
   - Click **Create Gateway**
   - Enter: `https://api.target.com`
   - Check "Create in multiple regions"
   - Select: `us-east-1`, `eu-west-1`, `ap-southeast-1`
   - Click **Create** (all 3 gateways created instantly)

2. **Configure domain mapping**:
   - Add domain: `api.target.com`
   - Add all 3 gateway URLs
   - Select **Round Robin** strategy
   - Enable rotation

3. **Run reconnaissance**:
   - Use Burp Scanner, Intruder, Repeater, or manual testing
   - All traffic automatically rotates through 3 AWS regions
   - Each request uses a different source IP

4. **Clean up when done**:
   - Go to **AWS Gateways** tab
   - Select and delete all created gateways
   - Confirm they're removed to stop AWS charges

## Integration with Other Tools

### Burp Scanner
The extension works transparently with Burp Scanner. Configure the extension, then run Scanner normally.

### Burp Intruder
Use Intruder for fuzzing and brute-forcing. Each request will use a different source IP.

### Burp Repeater
Test individual requests through FireProx by simply sending to the target domain.

### Manual Testing
Browse the target application normally through Burp's browser. All requests are automatically routed.

## FAQ

**Q: Can I use multiple target domains?**
A: Yes! You can configure multiple domains simultaneously, each with its own set of gateways and rotation strategy.

**Q: Does this work with WebSockets?**
A: WebSocket support depends on AWS API Gateway capabilities and is not explicitly tested.

**Q: Will this bypass WAFs?**
A: IP rotation may help evade IP-based rate limiting, but modern WAFs use multiple detection methods.

**Q: How much does this cost?**
A: AWS API Gateway pricing applies. Check [AWS pricing](https://aws.amazon.com/api-gateway/pricing/) for details.

**Q: Can I see which IP address was used?**
A: The source IP varies per request via AWS infrastructure. Check target logs if available.

**Q: Does this work with HTTP/2?**
A: Yes, the extension supports both HTTP/1 and HTTP/2 connections.

## Additional Resources

- [FireProx GitHub Repository](https://github.com/ustayready/fireprox)
- [AWS API Gateway Documentation](https://docs.aws.amazon.com/apigateway/)
- [Burp Montoya API Documentation](https://portswigger.net/burp/documentation/desktop/extensions/montoya-api)
- [AWS Acceptable Use Policy](https://aws.amazon.com/aup/)
