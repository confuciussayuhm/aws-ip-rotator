package burp;

/**
 * Configuration for a single FireProx gateway
 */
public class GatewayConfig {
    private final String gatewayUrl;
    private final String region;
    private final int weight;

    public GatewayConfig(String gatewayUrl, String region) {
        this(gatewayUrl, region, 100);
    }

    public GatewayConfig(String gatewayUrl, String region, int weight) {
        this.gatewayUrl = gatewayUrl;
        this.region = region;
        this.weight = Math.max(1, Math.min(100, weight)); // Clamp between 1-100
    }

    public String getGatewayUrl() {
        return gatewayUrl;
    }

    public String getRegion() {
        return region;
    }

    public int getWeight() {
        return weight;
    }

    @Override
    public String toString() {
        return String.format("%s (%s, weight: %d%%)", gatewayUrl, region, weight);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        GatewayConfig that = (GatewayConfig) o;
        return gatewayUrl.equals(that.gatewayUrl);
    }

    @Override
    public int hashCode() {
        return gatewayUrl.hashCode();
    }
}
