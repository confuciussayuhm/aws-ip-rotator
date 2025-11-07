package burp;

import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Configuration for a domain with multiple FireProx gateways and rotation strategy
 */
public class DomainConfig {
    public enum RotationStrategy {
        ROUND_ROBIN("Round Robin - Cycle through gateways sequentially"),
        RANDOM("Random - Pick a random gateway each time"),
        WEIGHTED("Weighted Random - Prefer gateways based on weight");

        private final String description;

        RotationStrategy(String description) {
            this.description = description;
        }

        public String getDescription() {
            return description;
        }

        @Override
        public String toString() {
            return name().replace('_', ' ');
        }
    }

    private final String domain;
    private final List<GatewayConfig> gateways;
    private RotationStrategy strategy;
    private final AtomicInteger roundRobinIndex;
    private final Random random;

    public DomainConfig(String domain) {
        this.domain = domain;
        this.gateways = new ArrayList<>();
        this.strategy = RotationStrategy.ROUND_ROBIN;
        this.roundRobinIndex = new AtomicInteger(0);
        this.random = new Random();
    }

    public String getDomain() {
        return domain;
    }

    public List<GatewayConfig> getGateways() {
        return new ArrayList<>(gateways);
    }

    public void addGateway(GatewayConfig gateway) {
        if (!gateways.contains(gateway)) {
            gateways.add(gateway);
        }
    }

    public void removeGateway(GatewayConfig gateway) {
        gateways.remove(gateway);
    }

    public void clearGateways() {
        gateways.clear();
    }

    public int getGatewayCount() {
        return gateways.size();
    }

    public RotationStrategy getStrategy() {
        return strategy;
    }

    public void setStrategy(RotationStrategy strategy) {
        this.strategy = strategy;
    }

    /**
     * Get the next gateway URL based on the rotation strategy
     */
    public String getNextGatewayUrl() {
        if (gateways.isEmpty()) {
            return null;
        }

        if (gateways.size() == 1) {
            return gateways.get(0).getGatewayUrl();
        }

        switch (strategy) {
            case ROUND_ROBIN:
                return getRoundRobinGateway();
            case RANDOM:
                return getRandomGateway();
            case WEIGHTED:
                return getWeightedRandomGateway();
            default:
                return gateways.get(0).getGatewayUrl();
        }
    }

    private String getRoundRobinGateway() {
        int index = roundRobinIndex.getAndUpdate(i -> (i + 1) % gateways.size());
        return gateways.get(index).getGatewayUrl();
    }

    private String getRandomGateway() {
        int index = random.nextInt(gateways.size());
        return gateways.get(index).getGatewayUrl();
    }

    private String getWeightedRandomGateway() {
        // Calculate total weight
        int totalWeight = gateways.stream()
                .mapToInt(GatewayConfig::getWeight)
                .sum();

        // Pick a random number between 0 and totalWeight
        int randomValue = random.nextInt(totalWeight);

        // Find which gateway this falls into
        int cumulativeWeight = 0;
        for (GatewayConfig gateway : gateways) {
            cumulativeWeight += gateway.getWeight();
            if (randomValue < cumulativeWeight) {
                return gateway.getGatewayUrl();
            }
        }

        // Fallback (shouldn't reach here)
        return gateways.get(0).getGatewayUrl();
    }

    /**
     * Get summary of this domain configuration
     */
    public String getSummary() {
        return String.format("%s (%d gateway%s, %s)",
                domain,
                gateways.size(),
                gateways.size() == 1 ? "" : "s",
                strategy.toString());
    }
}
