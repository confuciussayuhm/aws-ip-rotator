package burp;

import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.AwsCredentials;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.auth.credentials.ProfileCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.apigateway.ApiGatewayClient;
import software.amazon.awssdk.services.apigateway.model.*;

import java.net.URI;
import java.net.URL;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * FireProx Manager - Handles AWS API Gateway operations for creating rotating IP proxies
 */
public class FireProxManager {
    private ApiGatewayClient client;
    private Region region;
    private String lastError;

    /**
     * Initialize with default credentials provider (uses AWS credentials from environment/config)
     */
    public boolean initializeWithDefaultCredentials(String regionName) {
        try {
            this.region = Region.of(regionName != null ? regionName : "us-east-1");
            this.client = ApiGatewayClient.builder()
                    .region(this.region)
                    .credentialsProvider(DefaultCredentialsProvider.create())
                    .build();

            // Test credentials by calling get_account
            client.getAccount();
            return true;
        } catch (Exception e) {
            lastError = "Failed to initialize with default credentials: " + e.getMessage();
            return false;
        }
    }

    /**
     * Initialize with AWS profile
     */
    public boolean initializeWithProfile(String profileName, String regionName) {
        try {
            this.region = Region.of(regionName != null ? regionName : "us-east-1");
            this.client = ApiGatewayClient.builder()
                    .region(this.region)
                    .credentialsProvider(ProfileCredentialsProvider.create(profileName))
                    .build();

            // Test credentials
            client.getAccount();
            return true;
        } catch (Exception e) {
            lastError = "Failed to initialize with profile: " + e.getMessage();
            return false;
        }
    }

    /**
     * Initialize with explicit AWS credentials
     */
    public boolean initializeWithCredentials(String accessKey, String secretKey, String regionName) {
        try {
            this.region = Region.of(regionName != null ? regionName : "us-east-1");
            AwsCredentials credentials = AwsBasicCredentials.create(accessKey, secretKey);
            this.client = ApiGatewayClient.builder()
                    .region(this.region)
                    .credentialsProvider(StaticCredentialsProvider.create(credentials))
                    .build();

            // Test credentials
            client.getAccount();
            return true;
        } catch (Exception e) {
            lastError = "Failed to initialize with credentials: " + e.getMessage();
            return false;
        }
    }

    /**
     * Get the Swagger/OpenAPI template for FireProx
     */
    private String getSwaggerTemplate(String targetUrl) {
        // Remove trailing slash
        if (targetUrl.endsWith("/")) {
            targetUrl = targetUrl.substring(0, targetUrl.length() - 1);
        }

        // Extract domain for title
        String domain = "";
        try {
            URL url = new URL(targetUrl);
            domain = url.getHost().replaceAll("\\.", "_");
        } catch (Exception e) {
            domain = "proxy";
        }

        String title = "aws_ip_rotator_" + domain;
        String versionDate = DateTimeFormatter.ISO_INSTANT.format(Instant.now());

        return String.format("""
        {
          "swagger": "2.0",
          "info": {
            "version": "%s",
            "title": "%s"
          },
          "basePath": "/",
          "schemes": [
            "https"
          ],
          "paths": {
            "/": {
              "get": {
                "parameters": [
                  {
                    "name": "proxy",
                    "in": "path",
                    "required": true,
                    "type": "string"
                  },
                  {
                    "name": "X-My-X-Forwarded-For",
                    "in": "header",
                    "required": false,
                    "type": "string"
                  }
                ],
                "responses": {},
                "x-amazon-apigateway-integration": {
                  "uri": "%s/",
                  "responses": {
                    "default": {
                      "statusCode": "200"
                    }
                  },
                  "requestParameters": {
                    "integration.request.path.proxy": "method.request.path.proxy",
                    "integration.request.header.X-Forwarded-For": "method.request.header.X-My-X-Forwarded-For"
                  },
                  "passthroughBehavior": "when_no_match",
                  "httpMethod": "ANY",
                  "cacheNamespace": "irx7tm",
                  "cacheKeyParameters": [
                    "method.request.path.proxy"
                  ],
                  "type": "http_proxy"
                }
              }
            },
            "/{proxy+}": {
              "x-amazon-apigateway-any-method": {
                "produces": [
                  "application/json"
                ],
                "parameters": [
                  {
                    "name": "proxy",
                    "in": "path",
                    "required": true,
                    "type": "string"
                  },
                  {
                    "name": "X-My-X-Forwarded-For",
                    "in": "header",
                    "required": false,
                    "type": "string"
                  }
                ],
                "responses": {},
                "x-amazon-apigateway-integration": {
                  "uri": "%s/{proxy}",
                  "responses": {
                    "default": {
                      "statusCode": "200"
                    }
                  },
                  "requestParameters": {
                    "integration.request.path.proxy": "method.request.path.proxy",
                    "integration.request.header.X-Forwarded-For": "method.request.header.X-My-X-Forwarded-For"
                  },
                  "passthroughBehavior": "when_no_match",
                  "httpMethod": "ANY",
                  "cacheNamespace": "irx7tm",
                  "cacheKeyParameters": [
                    "method.request.path.proxy"
                  ],
                  "type": "http_proxy"
                }
              }
            }
          }
        }
        """, versionDate, title, targetUrl, targetUrl);
    }

    /**
     * Create a new FireProx gateway in the current region
     */
    public FireProxGateway createGateway(String targetUrl) {
        return createGatewayInRegion(targetUrl, region.id());
    }

    /**
     * Create a new FireProx gateway in a specific region
     * This creates a temporary client for the specified region to create the gateway
     */
    public FireProxGateway createGatewayInRegion(String targetUrl, String regionName) {
        ApiGatewayClient tempClient = null;
        try {
            Region targetRegion = Region.of(regionName);

            // Create a temporary client for the target region using the same credentials provider
            // as the main client
            if (client != null) {
                tempClient = ApiGatewayClient.builder()
                        .region(targetRegion)
                        .credentialsProvider(client.serviceClientConfiguration().credentialsProvider())
                        .build();
            } else {
                lastError = "Client not initialized";
                return null;
            }

            String template = getSwaggerTemplate(targetUrl);

            Map<String, String> parameters = new HashMap<>();
            parameters.put("endpointConfigurationTypes", "REGIONAL");

            ImportRestApiRequest request = ImportRestApiRequest.builder()
                    .parameters(parameters)
                    .body(software.amazon.awssdk.core.SdkBytes.fromUtf8String(template))
                    .build();

            ImportRestApiResponse response = tempClient.importRestApi(request);
            String apiId = response.id();

            // Create deployment
            CreateDeploymentRequest deployRequest = CreateDeploymentRequest.builder()
                    .restApiId(apiId)
                    .stageName("proxy")
                    .stageDescription("AWS IP Rotator")
                    .description("AWS IP Rotator Production Deployment")
                    .build();

            tempClient.createDeployment(deployRequest);

            // Build the proxy URL
            String proxyUrl = String.format("https://%s.execute-api.%s.amazonaws.com/proxy/",
                    apiId, targetRegion.id());

            return new FireProxGateway(
                    apiId,
                    response.name(),
                    response.createdDate(),
                    targetUrl,
                    proxyUrl,
                    targetRegion.id()
            );
        } catch (Exception e) {
            lastError = "Failed to create gateway in region " + regionName + ": " + e.getMessage();
            return null;
        } finally {
            if (tempClient != null) {
                tempClient.close();
            }
        }
    }

    /**
     * List all FireProx gateways in the current region
     */
    public List<FireProxGateway> listGateways() {
        List<FireProxGateway> gateways = new ArrayList<>();
        try {
            GetRestApisRequest request = GetRestApisRequest.builder().build();
            GetRestApisResponse response = client.getRestApis(request);

            for (RestApi api : response.items()) {
                try {
                    String apiId = api.id();
                    String targetUrl = getIntegrationUri(apiId);
                    if (targetUrl != null) {
                        String proxyUrl = String.format("https://%s.execute-api.%s.amazonaws.com/proxy/",
                                apiId, region.id());

                        gateways.add(new FireProxGateway(
                                apiId,
                                api.name(),
                                api.createdDate(),
                                targetUrl,
                                proxyUrl,
                                region.id()
                        ));
                    }
                } catch (Exception e) {
                    // Skip APIs that don't have the expected structure
                }
            }
        } catch (Exception e) {
            lastError = "Failed to list gateways: " + e.getMessage();
        }
        return gateways;
    }

    /**
     * List all FireProx gateways across all common AWS regions
     */
    public List<FireProxGateway> listGatewaysAllRegions() {
        List<FireProxGateway> allGateways = new ArrayList<>();

        // Common AWS regions to check
        String[] regions = {
            "us-east-1", "us-east-2", "us-west-1", "us-west-2",
            "eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1", "eu-north-1",
            "ap-south-1", "ap-northeast-1", "ap-northeast-2", "ap-southeast-1", "ap-southeast-2",
            "ca-central-1", "sa-east-1"
        };

        for (String regionName : regions) {
            ApiGatewayClient tempClient = null;
            try {
                Region targetRegion = Region.of(regionName);

                // Create temporary client for this region
                if (client != null) {
                    tempClient = ApiGatewayClient.builder()
                            .region(targetRegion)
                            .credentialsProvider(client.serviceClientConfiguration().credentialsProvider())
                            .build();
                } else {
                    continue;
                }

                // List gateways in this region
                GetRestApisRequest request = GetRestApisRequest.builder().build();
                GetRestApisResponse response = tempClient.getRestApis(request);

                for (RestApi api : response.items()) {
                    try {
                        String apiId = api.id();
                        String targetUrl = getIntegrationUriForClient(tempClient, apiId);
                        if (targetUrl != null) {
                            String proxyUrl = String.format("https://%s.execute-api.%s.amazonaws.com/proxy/",
                                    apiId, targetRegion.id());

                            allGateways.add(new FireProxGateway(
                                    apiId,
                                    api.name(),
                                    api.createdDate(),
                                    targetUrl,
                                    proxyUrl,
                                    targetRegion.id()
                            ));
                        }
                    } catch (Exception e) {
                        // Skip APIs that don't have the expected structure
                    }
                }
            } catch (Exception e) {
                // Skip regions where we can't connect or don't have access
            } finally {
                if (tempClient != null) {
                    tempClient.close();
                }
            }
        }

        return allGateways;
    }

    /**
     * Delete a FireProx gateway in the current region
     */
    public boolean deleteGateway(String apiId) {
        return deleteGatewayInRegion(apiId, region.id());
    }

    /**
     * Delete a FireProx gateway in a specific region
     */
    public boolean deleteGatewayInRegion(String apiId, String regionName) {
        ApiGatewayClient tempClient = null;
        try {
            Region targetRegion = Region.of(regionName);

            // Create temporary client for the target region
            if (client != null) {
                tempClient = ApiGatewayClient.builder()
                        .region(targetRegion)
                        .credentialsProvider(client.serviceClientConfiguration().credentialsProvider())
                        .build();
            } else {
                lastError = "Client not initialized";
                return false;
            }

            DeleteRestApiRequest request = DeleteRestApiRequest.builder()
                    .restApiId(apiId)
                    .build();
            tempClient.deleteRestApi(request);
            return true;
        } catch (Exception e) {
            lastError = "Failed to delete gateway in region " + regionName + ": " + e.getMessage();
            return false;
        } finally {
            if (tempClient != null) {
                tempClient.close();
            }
        }
    }

    /**
     * Update a FireProx gateway to point to a new URL
     */
    public boolean updateGateway(String apiId, String newTargetUrl) {
        try {
            // Remove trailing slash
            if (newTargetUrl.endsWith("/")) {
                newTargetUrl = newTargetUrl.substring(0, newTargetUrl.length() - 1);
            }

            String resourceId = getProxyResourceId(apiId);
            if (resourceId == null) {
                lastError = "Unable to find proxy resource for API";
                return false;
            }

            UpdateIntegrationRequest request = UpdateIntegrationRequest.builder()
                    .restApiId(apiId)
                    .resourceId(resourceId)
                    .httpMethod("ANY")
                    .patchOperations(
                            PatchOperation.builder()
                                    .op(Op.REPLACE)
                                    .path("/uri")
                                    .value(newTargetUrl + "/{proxy}")
                                    .build()
                    )
                    .build();

            client.updateIntegration(request);
            return true;
        } catch (Exception e) {
            lastError = "Failed to update gateway: " + e.getMessage();
            return false;
        }
    }

    /**
     * Get the resource ID for the /{proxy+} path
     */
    private String getProxyResourceId(String apiId) {
        try {
            GetResourcesRequest request = GetResourcesRequest.builder()
                    .restApiId(apiId)
                    .build();
            GetResourcesResponse response = client.getResources(request);

            for (Resource resource : response.items()) {
                if ("/{proxy+}".equals(resource.path())) {
                    return resource.id();
                }
            }
        } catch (Exception e) {
            lastError = "Failed to get resource: " + e.getMessage();
        }
        return null;
    }

    /**
     * Get the integration URI for an API (using instance client)
     */
    private String getIntegrationUri(String apiId) {
        return getIntegrationUriForClient(client, apiId);
    }

    /**
     * Get the integration URI for an API (using specified client)
     */
    private String getIntegrationUriForClient(ApiGatewayClient apiClient, String apiId) {
        try {
            String resourceId = getProxyResourceIdForClient(apiClient, apiId);
            if (resourceId == null) {
                return null;
            }

            GetIntegrationRequest request = GetIntegrationRequest.builder()
                    .restApiId(apiId)
                    .resourceId(resourceId)
                    .httpMethod("ANY")
                    .build();

            GetIntegrationResponse response = apiClient.getIntegration(request);
            String uri = response.uri();

            // Remove the /{proxy} suffix
            if (uri != null && uri.endsWith("/{proxy}")) {
                uri = uri.substring(0, uri.length() - "/{proxy}".length());
            }

            return uri;
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Get the proxy resource ID for an API (using specified client)
     */
    private String getProxyResourceIdForClient(ApiGatewayClient apiClient, String apiId) {
        try {
            GetResourcesRequest request = GetResourcesRequest.builder()
                    .restApiId(apiId)
                    .build();
            GetResourcesResponse response = apiClient.getResources(request);

            for (Resource resource : response.items()) {
                if ("/{proxy+}".equals(resource.path())) {
                    return resource.id();
                }
            }
        } catch (Exception e) {
            // Silently skip
        }
        return null;
    }

    /**
     * Get the last error message
     */
    public String getLastError() {
        return lastError;
    }

    /**
     * Close the API Gateway client
     */
    public void close() {
        if (client != null) {
            client.close();
        }
    }

    /**
     * Data class representing a FireProx gateway
     */
    public static class FireProxGateway {
        public final String apiId;
        public final String name;
        public final Instant createdDate;
        public final String targetUrl;
        public final String proxyUrl;
        public final String region;

        public FireProxGateway(String apiId, String name, Instant createdDate,
                               String targetUrl, String proxyUrl, String region) {
            this.apiId = apiId;
            this.name = name;
            this.createdDate = createdDate;
            this.targetUrl = targetUrl;
            this.proxyUrl = proxyUrl;
            this.region = region;
        }

        @Override
        public String toString() {
            return String.format("[%s] (%s) %s: %s => %s",
                    createdDate, apiId, name, proxyUrl, targetUrl);
        }
    }
}
