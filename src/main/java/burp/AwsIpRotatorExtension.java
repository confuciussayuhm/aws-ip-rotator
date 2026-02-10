package burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.core.Registration;
import burp.api.montoya.ui.UserInterface;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.persistence.PersistedObject;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * AWS IP Rotator Burp Extension
 *
 * This extension automatically rewrites requests to route through AWS IP Rotator gateways.
 * It modifies the SNI, Host header, and prepends the gateway path to all matching requests.
 */
public class AwsIpRotatorExtension implements BurpExtension {
    // Blacklist of banned stage names (common AWS/security terms that may be flagged)
    private static final String[] BANNED_STAGE_NAMES = {
        "proxy", "fireprox", "api", "aws", "gateway", "prod", "production",
        "dev", "development", "test", "staging", "vpn", "tunnel", "forward",
        "redirect", "bypass", "rotate", "rotation", "security", "pentest"
    };

    private MontoyaApi api;
    private Logging logging;
    private AwsIpRotatorConfig config;
    private AwsIpRotatorManager awsManager;
    private JPanel mainPanel;
    private DefaultTableModel gatewaysTableModel;
    private DefaultTableModel mappingsTableModel;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        this.logging = api.logging();
        this.config = new AwsIpRotatorConfig();

        // Set extension name
        api.extension().setName("AWS IP Rotator");

        // Load persisted domain mappings from Burp project
        loadDomainMappings();

        // Register HTTP handler
        api.http().registerHttpHandler(new AwsIpRotatorHttpHandler());

        // Create and register UI
        createUI();
        api.userInterface().registerSuiteTab("AWS IP Rotator", mainPanel);

        // Register context menu provider for right-click "Send to AWS IP Rotator"
        api.userInterface().registerContextMenuItemsProvider(new AwsIpRotatorContextMenuProvider());

        logging.logToOutput("AWS IP Rotator loaded successfully!");
        logging.logToOutput("Configure multi-region rotation in the 'AWS IP Rotator' tab");
    }

    /**
     * Check if a stage name is in the blacklist
     */
    private static boolean isStagNameBanned(String stageName) {
        if (stageName == null || stageName.trim().isEmpty()) {
            return false;
        }
        String lowerStageName = stageName.trim().toLowerCase();
        for (String banned : BANNED_STAGE_NAMES) {
            if (lowerStageName.equals(banned.toLowerCase())) {
                return true;
            }
        }
        return false;
    }

    /**
     * Save domain mappings to Burp project file
     */
    private void saveDomainMappings() {
        try {
            PersistedObject persistedData = api.persistence().extensionData();

            // Clear existing data
            for (String key : persistedData.childObjectKeys()) {
                persistedData.deleteChildObject(key);
            }

            // Save enabled state
            persistedData.setBoolean("enabled", config.enabled);
            persistedData.setBoolean("preserveOriginalHost", config.preserveOriginalHost);

            // Save each domain configuration
            int domainIndex = 0;
            for (Map.Entry<String, DomainConfig> entry : config.domainConfigs.entrySet()) {
                String domain = entry.getKey();
                DomainConfig domainConfig = entry.getValue();

                PersistedObject domainObj = PersistedObject.persistedObject();
                domainObj.setString("domain", domain);
                domainObj.setString("strategy", domainConfig.getStrategy().name());

                // Save gateways for this domain
                List<GatewayConfig> gateways = domainConfig.getGateways();
                for (int i = 0; i < gateways.size(); i++) {
                    GatewayConfig gateway = gateways.get(i);
                    PersistedObject gatewayObj = PersistedObject.persistedObject();
                    gatewayObj.setString("url", gateway.getGatewayUrl());
                    gatewayObj.setString("region", gateway.getRegion());
                    gatewayObj.setInteger("weight", gateway.getWeight());
                    domainObj.setChildObject("gateway_" + i, gatewayObj);
                }

                persistedData.setChildObject("domain_" + domainIndex, domainObj);
                domainIndex++;
            }

            logging.logToOutput("Domain mappings saved to project file");
        } catch (Exception e) {
            logging.logToError("Failed to save domain mappings: " + e.getMessage());
        }
    }

    /**
     * Load domain mappings from Burp project file
     */
    private void loadDomainMappings() {
        try {
            PersistedObject persistedData = api.persistence().extensionData();

            // Load enabled state
            Boolean enabled = persistedData.getBoolean("enabled");
            if (enabled != null) {
                config.enabled = enabled;
            }

            Boolean preserveOriginalHost = persistedData.getBoolean("preserveOriginalHost");
            if (preserveOriginalHost != null) {
                config.preserveOriginalHost = preserveOriginalHost;
            }

            // Load domain configurations
            config.domainConfigs.clear();
            for (String domainKey : persistedData.childObjectKeys()) {
                if (!domainKey.startsWith("domain_")) {
                    continue;
                }

                PersistedObject domainObj = persistedData.getChildObject(domainKey);
                String domain = domainObj.getString("domain");
                String strategyName = domainObj.getString("strategy");

                if (domain == null) {
                    continue;
                }

                DomainConfig domainConfig = new DomainConfig(domain);

                // Set rotation strategy
                if (strategyName != null) {
                    try {
                        domainConfig.setStrategy(DomainConfig.RotationStrategy.valueOf(strategyName));
                    } catch (IllegalArgumentException e) {
                        // Use default strategy if invalid
                    }
                }

                // Load gateways for this domain
                for (String gatewayKey : domainObj.childObjectKeys()) {
                    if (!gatewayKey.startsWith("gateway_")) {
                        continue;
                    }

                    PersistedObject gatewayObj = domainObj.getChildObject(gatewayKey);
                    String url = gatewayObj.getString("url");
                    String region = gatewayObj.getString("region");
                    Integer weight = gatewayObj.getInteger("weight");

                    if (url != null && region != null) {
                        GatewayConfig gateway = new GatewayConfig(url, region, weight != null ? weight : 100);
                        domainConfig.addGateway(gateway);
                    }
                }

                config.domainConfigs.put(domain, domainConfig);
            }

            if (!config.domainConfigs.isEmpty()) {
                logging.logToOutput("Loaded " + config.domainConfigs.size() + " domain mapping(s) from project file");
            }
        } catch (Exception e) {
            logging.logToError("Failed to load domain mappings: " + e.getMessage());
        }
    }

    /**
     * Creates the configuration UI with AWS management
     */
    private void createUI() {
        mainPanel = new JPanel(new BorderLayout(10, 10));
        mainPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // Title
        JLabel titleLabel = new JLabel("AWS IP Rotator - Multi-Region Configuration");
        titleLabel.setFont(new Font("Arial", Font.BOLD, 16));
        mainPanel.add(titleLabel, BorderLayout.NORTH);

        // Create tabbed pane
        JTabbedPane tabbedPane = new JTabbedPane();

        // Tab 1: Domain Mappings
        JPanel mappingsPanel = createMappingsPanel();
        tabbedPane.addTab("Domain Mappings", mappingsPanel);

        // Tab 2: AWS Gateway Management
        JPanel awsPanel = createAWSManagementPanel();
        tabbedPane.addTab("AWS Gateways", awsPanel);

        // Tab 3: AWS Configuration
        JPanel awsConfigPanel = createAWSConfigPanel();
        tabbedPane.addTab("AWS Configuration", awsConfigPanel);

        mainPanel.add(tabbedPane, BorderLayout.CENTER);
    }

    /**
     * Create the Domain Mappings panel with multi-region support
     */
    private JPanel createMappingsPanel() {
        JPanel panel = new JPanel(new BorderLayout(10, 10));

        // Top panel with enable checkbox and preserve host option
        JPanel topPanel = new JPanel(new GridLayout(2, 1, 5, 5));
        JCheckBox enabledCheckbox = new JCheckBox("✓ ENABLE IP ROTATION (Master On/Off Switch)", config.enabled);
        enabledCheckbox.setFont(enabledCheckbox.getFont().deriveFont(Font.BOLD));
        enabledCheckbox.setToolTipText("Check this box to activate IP rotation through AWS gateways. Uncheck to disable all request rewriting.");
        enabledCheckbox.addActionListener(e -> {
            config.enabled = enabledCheckbox.isSelected();
            logging.logToOutput("IP rotation " + (config.enabled ? "enabled" : "disabled"));
            saveDomainMappings();
        });
        topPanel.add(enabledCheckbox);

        JCheckBox preserveHostCheckbox = new JCheckBox("Preserve original Host in X-Original-Host header", config.preserveOriginalHost);
        preserveHostCheckbox.addActionListener(e -> {
            config.preserveOriginalHost = preserveHostCheckbox.isSelected();
            saveDomainMappings();
        });
        topPanel.add(preserveHostCheckbox);

        panel.add(topPanel, BorderLayout.NORTH);

        // Split pane: domains list on left, gateway details on right
        JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        splitPane.setDividerLocation(350);

        // Left: Domains table
        JPanel domainsPanel = new JPanel(new BorderLayout(5, 5));
        domainsPanel.setBorder(BorderFactory.createTitledBorder("Configured Domains"));

        String[] domainColumns = {"Domain", "Gateways", "Strategy"};
        mappingsTableModel = new DefaultTableModel(domainColumns, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };

        // Load existing domain configs
        for (DomainConfig dc : config.domainConfigs.values()) {
            mappingsTableModel.addRow(new Object[]{
                dc.getDomain(),
                dc.getGatewayCount(),
                dc.getStrategy().toString()
            });
        }

        JTable domainsTable = new JTable(mappingsTableModel);
        domainsTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        domainsTable.setRowHeight(25);

        // Enable sorting on all columns
        domainsTable.setAutoCreateRowSorter(true);

        JScrollPane domainsScrollPane = new JScrollPane(domainsTable);
        domainsPanel.add(domainsScrollPane, BorderLayout.CENTER);

        // Domain management buttons
        JPanel domainButtonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton addDomainButton = new JButton("Add Domain");
        JButton removeDomainButton = new JButton("Remove Domain");
        JButton clearAllButton = new JButton("Clear All");
        domainButtonPanel.add(addDomainButton);
        domainButtonPanel.add(removeDomainButton);
        domainButtonPanel.add(clearAllButton);
        domainsPanel.add(domainButtonPanel, BorderLayout.SOUTH);

        splitPane.setLeftComponent(domainsPanel);

        // Right: Gateway details panel
        JPanel detailsPanel = new JPanel(new BorderLayout(5, 5));
        detailsPanel.setBorder(BorderFactory.createTitledBorder("Gateway Details"));

        // Gateway list
        DefaultListModel<String> gatewayListModel = new DefaultListModel<>();
        JList<String> gatewayList = new JList<>(gatewayListModel);
        gatewayList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        JScrollPane gatewayScrollPane = new JScrollPane(gatewayList);
        detailsPanel.add(gatewayScrollPane, BorderLayout.CENTER);

        // Details control panel
        JPanel controlPanel = new JPanel(new BorderLayout(5, 5));

        // Rotation strategy selector
        JPanel strategyPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        strategyPanel.add(new JLabel("Rotation Strategy:"));
        JComboBox<DomainConfig.RotationStrategy> strategyCombo = new JComboBox<>(DomainConfig.RotationStrategy.values());
        strategyPanel.add(strategyCombo);
        controlPanel.add(strategyPanel, BorderLayout.NORTH);

        // Gateway management buttons
        JPanel gatewayButtonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton addGatewayButton = new JButton("Add Gateway");
        JButton removeGatewayButton = new JButton("Remove Gateway");
        JButton editWeightButton = new JButton("Edit Weight");
        gatewayButtonPanel.add(addGatewayButton);
        gatewayButtonPanel.add(removeGatewayButton);
        gatewayButtonPanel.add(editWeightButton);
        controlPanel.add(gatewayButtonPanel, BorderLayout.SOUTH);

        detailsPanel.add(controlPanel, BorderLayout.SOUTH);

        splitPane.setRightComponent(detailsPanel);
        panel.add(splitPane, BorderLayout.CENTER);

        // Domain selection handler
        domainsTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int row = domainsTable.getSelectedRow();
                if (row >= 0) {
                    String domain = (String) mappingsTableModel.getValueAt(row, 0);
                    DomainConfig dc = config.domainConfigs.get(domain);
                    if (dc != null) {
                        updateGatewayDetails(dc, gatewayListModel, strategyCombo);
                    }
                }
            }
        });

        // Strategy change handler
        strategyCombo.addActionListener(e -> {
            int row = domainsTable.getSelectedRow();
            if (row >= 0) {
                String domain = (String) mappingsTableModel.getValueAt(row, 0);
                DomainConfig dc = config.domainConfigs.get(domain);
                if (dc != null) {
                    DomainConfig.RotationStrategy newStrategy = (DomainConfig.RotationStrategy) strategyCombo.getSelectedItem();
                    dc.setStrategy(newStrategy);
                    mappingsTableModel.setValueAt(newStrategy.toString(), row, 2);
                    logging.logToOutput("Changed rotation strategy for " + domain + " to " + newStrategy);
                    saveDomainMappings();
                }
            }
        });

        // Add domain button
        addDomainButton.addActionListener(e -> {
            String domain = JOptionPane.showInputDialog(mainPanel,
                "Enter domain name (e.g., api.example.com):",
                "Add Domain",
                JOptionPane.PLAIN_MESSAGE);

            if (domain != null && !domain.trim().isEmpty()) {
                domain = domain.trim();
                if (config.domainConfigs.containsKey(domain)) {
                    JOptionPane.showMessageDialog(mainPanel,
                        "Domain already exists!",
                        "Duplicate Domain",
                        JOptionPane.WARNING_MESSAGE);
                } else {
                    DomainConfig dc = new DomainConfig(domain);
                    config.domainConfigs.put(domain, dc);
                    mappingsTableModel.addRow(new Object[]{domain, 0, dc.getStrategy().toString()});
                    logging.logToOutput("Added domain: " + domain);
                    saveDomainMappings();
                }
            }
        });

        // Remove domain button
        removeDomainButton.addActionListener(e -> {
            int row = domainsTable.getSelectedRow();
            if (row >= 0) {
                String domain = (String) mappingsTableModel.getValueAt(row, 0);
                int confirm = JOptionPane.showConfirmDialog(mainPanel,
                    "Remove domain " + domain + " and all its gateways?",
                    "Confirm Remove",
                    JOptionPane.YES_NO_OPTION);

                if (confirm == JOptionPane.YES_OPTION) {
                    config.domainConfigs.remove(domain);
                    mappingsTableModel.removeRow(row);
                    gatewayListModel.clear();
                    logging.logToOutput("Removed domain: " + domain);
                    saveDomainMappings();
                }
            } else {
                JOptionPane.showMessageDialog(mainPanel,
                    "Please select a domain to remove",
                    "No Selection",
                    JOptionPane.WARNING_MESSAGE);
            }
        });

        // Clear all button
        clearAllButton.addActionListener(e -> {
            if (!config.domainConfigs.isEmpty()) {
                int confirm = JOptionPane.showConfirmDialog(mainPanel,
                    "Remove all domains and gateways?",
                    "Confirm Clear",
                    JOptionPane.YES_NO_OPTION);

                if (confirm == JOptionPane.YES_OPTION) {
                    config.domainConfigs.clear();
                    mappingsTableModel.setRowCount(0);
                    gatewayListModel.clear();
                    logging.logToOutput("Cleared all domain configurations");
                    saveDomainMappings();
                }
            }
        });

        // Add gateway button
        addGatewayButton.addActionListener(e -> {
            int row = domainsTable.getSelectedRow();
            if (row >= 0) {
                String domain = (String) mappingsTableModel.getValueAt(row, 0);
                DomainConfig dc = config.domainConfigs.get(domain);
                addGatewayToDomain(dc, domainsTable, row, gatewayListModel);
            } else {
                JOptionPane.showMessageDialog(mainPanel,
                    "Please select a domain first",
                    "No Domain Selected",
                    JOptionPane.WARNING_MESSAGE);
            }
        });

        // Remove gateway button
        removeGatewayButton.addActionListener(e -> {
            int row = domainsTable.getSelectedRow();
            int gatewayIndex = gatewayList.getSelectedIndex();
            if (row >= 0 && gatewayIndex >= 0) {
                String domain = (String) mappingsTableModel.getValueAt(row, 0);
                DomainConfig dc = config.domainConfigs.get(domain);
                if (dc != null) {
                    List<GatewayConfig> gateways = dc.getGateways();
                    if (gatewayIndex < gateways.size()) {
                        GatewayConfig gateway = gateways.get(gatewayIndex);
                        dc.removeGateway(gateway);
                        gatewayListModel.remove(gatewayIndex);
                        mappingsTableModel.setValueAt(dc.getGatewayCount(), row, 1);
                        logging.logToOutput("Removed gateway from " + domain + ": " + gateway.getGatewayUrl());
                        saveDomainMappings();
                    }
                }
            } else {
                JOptionPane.showMessageDialog(mainPanel,
                    "Please select a domain and gateway to remove",
                    "No Selection",
                    JOptionPane.WARNING_MESSAGE);
            }
        });

        // Edit weight button
        editWeightButton.addActionListener(e -> {
            int row = domainsTable.getSelectedRow();
            int gatewayIndex = gatewayList.getSelectedIndex();
            if (row >= 0 && gatewayIndex >= 0) {
                String domain = (String) mappingsTableModel.getValueAt(row, 0);
                DomainConfig dc = config.domainConfigs.get(domain);
                if (dc != null) {
                    List<GatewayConfig> gateways = dc.getGateways();
                    if (gatewayIndex < gateways.size()) {
                        editGatewayWeight(dc, gatewayIndex, gatewayListModel);
                    }
                }
            } else {
                JOptionPane.showMessageDialog(mainPanel,
                    "Please select a gateway to edit weight",
                    "No Selection",
                    JOptionPane.WARNING_MESSAGE);
            }
        });

        // Populate table with loaded domain mappings
        for (Map.Entry<String, DomainConfig> entry : config.domainConfigs.entrySet()) {
            DomainConfig dc = entry.getValue();
            mappingsTableModel.addRow(new Object[]{
                dc.getDomain(),
                dc.getGatewayCount(),
                dc.getStrategy().toString()
            });
        }

        return panel;
    }

    /**
     * Update gateway details panel for selected domain
     */
    private void updateGatewayDetails(DomainConfig dc, DefaultListModel<String> gatewayListModel,
                                      JComboBox<DomainConfig.RotationStrategy> strategyCombo) {
        gatewayListModel.clear();
        for (GatewayConfig gateway : dc.getGateways()) {
            gatewayListModel.addElement(String.format("%s (%s) [weight: %d%%]",
                gateway.getGatewayUrl(), gateway.getRegion(), gateway.getWeight()));
        }
        strategyCombo.setSelectedItem(dc.getStrategy());
    }

    /**
     * Add a gateway to a domain
     */
    private void addGatewayToDomain(DomainConfig dc, JTable domainsTable, int row,
                                    DefaultListModel<String> gatewayListModel) {
        String gatewayUrl = JOptionPane.showInputDialog(mainPanel,
            "Enter AWS IP Rotator Gateway URL:",
            "Add Gateway",
            JOptionPane.PLAIN_MESSAGE);

        if (gatewayUrl != null && !gatewayUrl.trim().isEmpty()) {
            gatewayUrl = gatewayUrl.trim();

            // Extract region from URL (e.g., us-east-1 from execute-api.us-east-1.amazonaws.com)
            String region = extractRegionFromUrl(gatewayUrl);

            try {
                new URL(gatewayUrl);
                GatewayConfig gateway = new GatewayConfig(gatewayUrl, region);
                dc.addGateway(gateway);
                mappingsTableModel.setValueAt(dc.getGatewayCount(), row, 1);
                gatewayListModel.addElement(String.format("%s (%s) [weight: %d%%]",
                    gateway.getGatewayUrl(), gateway.getRegion(), gateway.getWeight()));
                logging.logToOutput("Added gateway to " + dc.getDomain() + ": " + gatewayUrl + " (region: " + region + ")");
                saveDomainMappings();
            } catch (MalformedURLException ex) {
                JOptionPane.showMessageDialog(mainPanel,
                    "Invalid URL format!",
                    "Error",
                    JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    /**
     * Edit gateway weight
     */
    private void editGatewayWeight(DomainConfig dc, int gatewayIndex, DefaultListModel<String> gatewayListModel) {
        List<GatewayConfig> gateways = dc.getGateways();
        GatewayConfig oldGateway = gateways.get(gatewayIndex);

        String weightStr = JOptionPane.showInputDialog(mainPanel,
            "Enter weight (1-100):",
            "Edit Gateway Weight",
            JOptionPane.PLAIN_MESSAGE);

        if (weightStr != null && !weightStr.trim().isEmpty()) {
            try {
                int weight = Integer.parseInt(weightStr.trim());
                if (weight < 1 || weight > 100) {
                    throw new NumberFormatException();
                }

                // Remove old and add new with updated weight
                dc.removeGateway(oldGateway);
                GatewayConfig newGateway = new GatewayConfig(oldGateway.getGatewayUrl(),
                    oldGateway.getRegion(), weight);
                dc.addGateway(newGateway);

                // Update display
                gatewayListModel.set(gatewayIndex, String.format("%s (%s) [weight: %d%%]",
                    newGateway.getGatewayUrl(), newGateway.getRegion(), newGateway.getWeight()));

                logging.logToOutput("Updated gateway weight for " + dc.getDomain() + ": " + oldGateway.getGatewayUrl() + " to " + weight + "%");
                saveDomainMappings();
            } catch (NumberFormatException ex) {
                JOptionPane.showMessageDialog(mainPanel,
                    "Please enter a valid number between 1 and 100",
                    "Invalid Weight",
                    JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    /**
     * Extract AWS region from gateway URL
     */
    private String extractRegionFromUrl(String url) {
        try {
            URL urlObj = new URL(url);
            String host = urlObj.getHost();
            // Format: xxx.execute-api.REGION.amazonaws.com
            String[] parts = host.split("\\.");
            if (parts.length >= 4 && parts[1].equals("execute-api")) {
                return parts[2];
            }
        } catch (Exception e) {
            // Ignore
        }
        return "unknown";
    }

    /**
     * Create the AWS Gateway Management panel
     */
    private JPanel createAWSManagementPanel() {
        JPanel panel = new JPanel(new BorderLayout(10, 10));

        // Gateway list table
        String[] columnNames = {"API ID", "Name", "Target URL", "Proxy URL", "Region", "Created"};
        gatewaysTableModel = new DefaultTableModel(columnNames, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };

        JTable gatewaysTable = new JTable(gatewaysTableModel);
        gatewaysTable.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        gatewaysTable.setRowHeight(25);
        gatewaysTable.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
        gatewaysTable.getColumnModel().getColumn(0).setPreferredWidth(150);
        gatewaysTable.getColumnModel().getColumn(1).setPreferredWidth(150);
        gatewaysTable.getColumnModel().getColumn(2).setPreferredWidth(200);
        gatewaysTable.getColumnModel().getColumn(3).setPreferredWidth(300);
        gatewaysTable.getColumnModel().getColumn(4).setPreferredWidth(100);
        gatewaysTable.getColumnModel().getColumn(5).setPreferredWidth(150);

        // Enable sorting on all columns
        gatewaysTable.setAutoCreateRowSorter(true);

        JScrollPane tableScrollPane = new JScrollPane(gatewaysTable);
        tableScrollPane.setBorder(BorderFactory.createTitledBorder("AWS API Gateways"));
        panel.add(tableScrollPane, BorderLayout.CENTER);

        // Button panel
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));

        JButton refreshButton = new JButton("Refresh List");
        refreshButton.addActionListener(e -> refreshGatewayList());
        buttonPanel.add(refreshButton);

        JButton createButton = new JButton("Create Gateway");
        createButton.addActionListener(e -> createGateway());
        buttonPanel.add(createButton);

        JButton useButton = new JButton("Use Selected");
        useButton.setToolTipText("Add selected gateway(s) to domain mappings");
        useButton.addActionListener(e -> {
            int[] selectedRows = gatewaysTable.getSelectedRows();
            if (selectedRows.length > 0) {
                int addedCount = 0;
                for (int viewRow : selectedRows) {
                    // Convert view row to model row (important when table is sorted)
                    int modelRow = gatewaysTable.convertRowIndexToModel(viewRow);
                    String targetUrl = (String) gatewaysTableModel.getValueAt(modelRow, 2);
                    String proxyUrl = (String) gatewaysTableModel.getValueAt(modelRow, 3);
                    useGatewayForMapping(targetUrl, proxyUrl);
                    addedCount++;
                }

                // Show single success message for all added gateways
                String message = addedCount == 1
                    ? "Added 1 gateway to domain mappings"
                    : String.format("Added %d gateways to domain mappings", addedCount);
                JOptionPane.showMessageDialog(mainPanel,
                    message,
                    "Success",
                    JOptionPane.INFORMATION_MESSAGE);
            } else {
                JOptionPane.showMessageDialog(mainPanel,
                    "Please select at least one gateway to use",
                    "No Selection",
                    JOptionPane.WARNING_MESSAGE);
            }
        });
        buttonPanel.add(useButton);

        JButton updateButton = new JButton("Update Gateway");
        updateButton.addActionListener(e -> {
            int viewRow = gatewaysTable.getSelectedRow();
            if (viewRow >= 0) {
                // Convert view row to model row (important when table is sorted)
                int modelRow = gatewaysTable.convertRowIndexToModel(viewRow);
                String apiId = (String) gatewaysTableModel.getValueAt(modelRow, 0);
                updateGateway(apiId);
            } else {
                JOptionPane.showMessageDialog(mainPanel,
                    "Please select a gateway to update",
                    "No Selection",
                    JOptionPane.WARNING_MESSAGE);
            }
        });
        buttonPanel.add(updateButton);

        JButton deleteButton = new JButton("Delete Gateway");
        deleteButton.addActionListener(e -> {
            int[] selectedRows = gatewaysTable.getSelectedRows();
            if (selectedRows.length > 0) {
                // Confirm deletion
                String message = selectedRows.length == 1
                    ? "Delete the selected gateway?\n\nThis will permanently delete the API Gateway from AWS."
                    : String.format("Delete %d selected gateways?\n\nThis will permanently delete all API Gateways from AWS.", selectedRows.length);

                int confirm = JOptionPane.showConfirmDialog(mainPanel,
                    message,
                    "Confirm Delete",
                    JOptionPane.YES_NO_OPTION,
                    JOptionPane.WARNING_MESSAGE);

                if (confirm == JOptionPane.YES_OPTION) {
                    logging.logToOutput("Deleting " + selectedRows.length + " gateway(s) (parallel execution)...");

                    // Collect gateway info before deletion
                    List<Map<String, String>> gatewaysToDelete = new ArrayList<>();
                    for (int i = 0; i < selectedRows.length; i++) {
                        int viewRow = selectedRows[i];
                        int modelRow = gatewaysTable.convertRowIndexToModel(viewRow);

                        Map<String, String> gatewayInfo = new HashMap<>();
                        gatewayInfo.put("apiId", (String) gatewaysTableModel.getValueAt(modelRow, 0));
                        gatewayInfo.put("name", (String) gatewaysTableModel.getValueAt(modelRow, 1));
                        gatewayInfo.put("region", (String) gatewaysTableModel.getValueAt(modelRow, 4));
                        gatewayInfo.put("modelRow", String.valueOf(modelRow));
                        gatewaysToDelete.add(gatewayInfo);
                    }

                    // Use SwingWorker to delete gateways in background
                    SwingWorker<Map<String, Object>, Void> worker = new SwingWorker<>() {
                        @Override
                        protected Map<String, Object> doInBackground() {
                            Map<String, Object> result = new HashMap<>();
                            List<String> successDeletes = Collections.synchronizedList(new ArrayList<>());
                            List<String> failures = Collections.synchronizedList(new ArrayList<>());

                            // Create executor service for parallel execution
                            ExecutorService executor = Executors.newFixedThreadPool(Math.min(gatewaysToDelete.size(), 10));
                            List<CompletableFuture<Void>> futures = new ArrayList<>();

                            for (Map<String, String> gateway : gatewaysToDelete) {
                                CompletableFuture<Void> future = CompletableFuture.runAsync(() -> {
                                    String apiId = gateway.get("apiId");
                                    String name = gateway.get("name");
                                    String region = gateway.get("region");

                                    try {
                                        if (awsManager != null && awsManager.deleteGatewayInRegion(apiId, region)) {
                                            successDeletes.add(apiId);
                                            logging.logToOutput("Deleted gateway: " + apiId + " in region " + region);
                                        } else {
                                            failures.add(name + " (" + apiId + ") - " + region);
                                            logging.logToError("Failed to delete gateway: " + apiId + " in region " + region);
                                        }
                                    } catch (Exception e) {
                                        failures.add(name + " (" + apiId + ") - " + region + ": " + e.getMessage());
                                        logging.logToError("Exception deleting gateway " + apiId + ": " + e.getMessage());
                                    }
                                }, executor);

                                futures.add(future);
                            }

                            // Wait for all to complete
                            try {
                                CompletableFuture.allOf(futures.toArray(new CompletableFuture[0])).join();
                            } catch (Exception e) {
                                logging.logToError("Error during parallel gateway deletion: " + e.getMessage());
                            } finally {
                                executor.shutdown();
                            }

                            result.put("success", successDeletes);
                            result.put("failures", failures);
                            return result;
                        }

                        @Override
                        protected void done() {
                            try {
                                Map<String, Object> result = get();
                                @SuppressWarnings("unchecked")
                                List<String> successDeletes = (List<String>) result.get("success");
                                @SuppressWarnings("unchecked")
                                List<String> failures = (List<String>) result.get("failures");

                                // Remove successfully deleted gateways from table (in reverse order)
                                for (int i = gatewaysToDelete.size() - 1; i >= 0; i--) {
                                    Map<String, String> gateway = gatewaysToDelete.get(i);
                                    String apiId = gateway.get("apiId");
                                    if (successDeletes.contains(apiId)) {
                                        int modelRow = Integer.parseInt(gateway.get("modelRow"));
                                        // Find current row index (may have changed)
                                        for (int row = 0; row < gatewaysTableModel.getRowCount(); row++) {
                                            if (gatewaysTableModel.getValueAt(row, 0).equals(apiId)) {
                                                gatewaysTableModel.removeRow(row);
                                                break;
                                            }
                                        }
                                    }
                                }

                                int successCount = successDeletes.size();
                                int failureCount = failures.size();

                                // Show summary
                                if (gatewaysToDelete.size() > 1 || failureCount > 0) {
                                    String title = (failureCount == 0) ? "Success" : "Partial Success";
                                    int messageType = (failureCount == 0) ? JOptionPane.INFORMATION_MESSAGE : JOptionPane.WARNING_MESSAGE;
                                    StringBuilder summary = new StringBuilder(String.format("Deletion complete:\n\nSuccess: %d | Failed: %d", successCount, failureCount));
                                    if (failureCount > 0) {
                                        summary.append("\n\nFailed deletions:\n");
                                        for (String failure : failures) {
                                            summary.append("✗ ").append(failure).append("\n");
                                        }
                                    }
                                    JOptionPane.showMessageDialog(mainPanel, summary.toString(), title, messageType);
                                }

                                logging.logToOutput("Gateway deletion complete: " + successCount + " succeeded, " + failureCount + " failed");

                            } catch (Exception ex) {
                                logging.logToError("Failed to process gateway deletion results: " + ex.getMessage());
                                JOptionPane.showMessageDialog(mainPanel,
                                    "Failed to delete gateways: " + ex.getMessage(),
                                    "Error",
                                    JOptionPane.ERROR_MESSAGE);
                            }
                        }
                    };

                    worker.execute();
                }
            } else {
                JOptionPane.showMessageDialog(mainPanel,
                    "Please select at least one gateway to delete",
                    "No Selection",
                    JOptionPane.WARNING_MESSAGE);
            }
        });
        buttonPanel.add(deleteButton);

        panel.add(buttonPanel, BorderLayout.SOUTH);

        return panel;
    }

    /**
     * Create the AWS Configuration panel
     */
    private JPanel createAWSConfigPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(5, 5, 5, 5);

        // Auth method selection
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.gridwidth = 2;
        panel.add(new JLabel("AWS Authentication Method:"), gbc);

        gbc.gridy = 1;
        JComboBox<String> authMethodCombo = new JComboBox<>(new String[]{
            "Default Credentials (Environment/Config)",
            "AWS Profile",
            "Access Key & Secret"
        });
        panel.add(authMethodCombo, gbc);

        // Profile name
        gbc.gridy = 2;
        gbc.gridwidth = 1;
        gbc.weightx = 0.3;
        JLabel profileLabel = new JLabel("Profile Name:");
        panel.add(profileLabel, gbc);

        gbc.gridx = 1;
        gbc.weightx = 0.7;
        JTextField profileField = new JTextField();
        panel.add(profileField, gbc);

        // Access Key
        gbc.gridx = 0;
        gbc.gridy = 3;
        gbc.weightx = 0.3;
        JLabel accessKeyLabel = new JLabel("Access Key:");
        panel.add(accessKeyLabel, gbc);

        gbc.gridx = 1;
        gbc.weightx = 0.7;
        JTextField accessKeyField = new JTextField();
        panel.add(accessKeyField, gbc);

        // Secret Key
        gbc.gridx = 0;
        gbc.gridy = 4;
        gbc.weightx = 0.3;
        JLabel secretKeyLabel = new JLabel("Secret Key:");
        panel.add(secretKeyLabel, gbc);

        gbc.gridx = 1;
        gbc.weightx = 0.7;
        JPasswordField secretKeyField = new JPasswordField();
        panel.add(secretKeyField, gbc);

        // Region
        gbc.gridx = 0;
        gbc.gridy = 5;
        gbc.weightx = 0.3;
        panel.add(new JLabel("AWS Region:"), gbc);

        gbc.gridx = 1;
        gbc.weightx = 0.7;
        JComboBox<String> regionCombo = new JComboBox<>(new String[]{
            "us-east-1", "us-east-2", "us-west-1", "us-west-2",
            "eu-west-1", "eu-west-2", "eu-central-1",
            "ap-southeast-1", "ap-southeast-2", "ap-northeast-1"
        });
        panel.add(regionCombo, gbc);

        // Initial field states
        profileLabel.setEnabled(false);
        profileField.setEnabled(false);
        accessKeyLabel.setEnabled(false);
        accessKeyField.setEnabled(false);
        secretKeyLabel.setEnabled(false);
        secretKeyField.setEnabled(false);

        // Auth method change handler
        authMethodCombo.addActionListener(e -> {
            int selected = authMethodCombo.getSelectedIndex();
            profileLabel.setEnabled(selected == 1);
            profileField.setEnabled(selected == 1);
            accessKeyLabel.setEnabled(selected == 2);
            accessKeyField.setEnabled(selected == 2);
            secretKeyLabel.setEnabled(selected == 2);
            secretKeyField.setEnabled(selected == 2);
        });

        // Test connection button
        gbc.gridx = 0;
        gbc.gridy = 6;
        gbc.gridwidth = 2;
        gbc.anchor = GridBagConstraints.CENTER;
        JButton connectButton = new JButton("Test Connection to AWS");
        connectButton.addActionListener(e -> {
            awsManager = new AwsIpRotatorManager();
            boolean success = false;
            int authMethod = authMethodCombo.getSelectedIndex();
            String region = (String) regionCombo.getSelectedItem();

            switch (authMethod) {
                case 0: // Default
                    success = awsManager.initializeWithDefaultCredentials(region);
                    break;
                case 1: // Profile
                    String profile = profileField.getText().trim();
                    if (profile.isEmpty()) {
                        JOptionPane.showMessageDialog(mainPanel,
                            "Please enter a profile name",
                            "Error",
                            JOptionPane.ERROR_MESSAGE);
                        return;
                    }
                    success = awsManager.initializeWithProfile(profile, region);
                    break;
                case 2: // Keys
                    String accessKey = accessKeyField.getText().trim();
                    String secretKey = new String(secretKeyField.getPassword()).trim();
                    if (accessKey.isEmpty() || secretKey.isEmpty()) {
                        JOptionPane.showMessageDialog(mainPanel,
                            "Please enter both access key and secret key",
                            "Error",
                            JOptionPane.ERROR_MESSAGE);
                        return;
                    }
                    success = awsManager.initializeWithCredentials(accessKey, secretKey, region);
                    break;
            }

            if (success) {
                logging.logToOutput("Successfully connected to AWS in region: " + region);
                JOptionPane.showMessageDialog(mainPanel,
                    "Successfully connected to AWS!",
                    "Success",
                    JOptionPane.INFORMATION_MESSAGE);
            } else {
                logging.logToError("Failed to connect to AWS: " + awsManager.getLastError());
                JOptionPane.showMessageDialog(mainPanel,
                    "Failed to connect: " + awsManager.getLastError(),
                    "Error",
                    JOptionPane.ERROR_MESSAGE);
            }
        });
        panel.add(connectButton, gbc);

        // Instructions
        gbc.gridy = 7;
        gbc.gridwidth = 2;
        gbc.fill = GridBagConstraints.BOTH;
        gbc.weighty = 1.0;

        JTextArea instructions = new JTextArea();
        instructions.setEditable(false);
        instructions.setWrapStyleWord(true);
        instructions.setLineWrap(true);
        instructions.setBackground(panel.getBackground());
        instructions.setText(
            "\nAWS Configuration Instructions:\n\n" +
            "1. Select your authentication method:\n" +
            "   - Default: Uses credentials from ~/.aws/credentials or environment\n" +
            "   - AWS Profile: Uses a named profile from ~/.aws/credentials\n" +
            "   - Access Key: Provide explicit AWS credentials\n\n" +
            "2. Select your AWS region (used for connection testing only)\n" +
            "   Note: The extension queries ALL regions when listing/managing gateways\n\n" +
            "3. Click 'Test Connection to AWS' to verify your credentials\n" +
            "   Note: Credentials are not stored, only tested\n\n" +
            "4. Go to the 'AWS Gateways' tab to manage AWS IP Rotator gateways\n" +
            "   - 'Refresh List' shows gateways from ALL AWS regions\n" +
            "   - 'Create Gateway' lets you create in single or multiple regions\n\n" +
            "Note: Ensure your AWS IAM user has API Gateway permissions:\n" +
            "- apigateway:*\n" +
            "- execute-api:Invoke"
        );

        JScrollPane scrollPane = new JScrollPane(instructions);
        scrollPane.setBorder(BorderFactory.createTitledBorder("Instructions"));
        panel.add(scrollPane, gbc);

        return panel;
    }

    /**
     * Refresh the AWS gateway list in background thread to avoid freezing UI
     */
    private void refreshGatewayList() {
        if (awsManager == null) {
            JOptionPane.showMessageDialog(mainPanel,
                "Please configure AWS credentials first in the 'AWS Configuration' tab",
                "Not Connected",
                JOptionPane.WARNING_MESSAGE);
            return;
        }

        // Show progress message
        logging.logToOutput("Refreshing gateway list across all AWS regions (this may take a few seconds)...");

        // Clear table immediately
        gatewaysTableModel.setRowCount(0);

        // Use SwingWorker to query in background thread
        SwingWorker<List<AwsIpRotatorManager.AwsIpRotatorGateway>, Void> worker = new SwingWorker<>() {
            @Override
            protected List<AwsIpRotatorManager.AwsIpRotatorGateway> doInBackground() {
                // This runs in background thread - won't freeze UI
                return awsManager.listGatewaysAllRegions();
            }

            @Override
            protected void done() {
                try {
                    // This runs on UI thread after background work completes
                    List<AwsIpRotatorManager.AwsIpRotatorGateway> gateways = get();

                    for (AwsIpRotatorManager.AwsIpRotatorGateway gateway : gateways) {
                        gatewaysTableModel.addRow(new Object[]{
                            gateway.apiId,
                            gateway.name,
                            gateway.targetUrl,
                            gateway.proxyUrl,
                            gateway.region,
                            gateway.createdDate.toString()
                        });
                    }

                    logging.logToOutput("Refreshed gateway list: " + gateways.size() + " gateways found across all regions");
                } catch (Exception ex) {
                    logging.logToError("Failed to refresh gateway list: " + ex.getMessage());
                    JOptionPane.showMessageDialog(mainPanel,
                        "Failed to refresh gateway list: " + ex.getMessage(),
                        "Error",
                        JOptionPane.ERROR_MESSAGE);
                }
            }
        };

        worker.execute();
    }

    /**
     * Create a new gateway
     */
    private void createGateway() {
        if (awsManager == null) {
            JOptionPane.showMessageDialog(mainPanel,
                "Please configure AWS credentials first in the 'AWS Configuration' tab",
                "Not Connected",
                JOptionPane.WARNING_MESSAGE);
            return;
        }

        // Show custom dialog for gateway creation
        GatewayCreationDialog dialog = new GatewayCreationDialog(mainPanel);
        dialog.setVisible(true);

        if (dialog.isConfirmed()) {
            String targetUrl = dialog.getTargetUrl().trim();
            String stageName = dialog.getStageName();
            List<String> selectedRegions = dialog.getSelectedRegions();

            if (selectedRegions.isEmpty()) {
                JOptionPane.showMessageDialog(mainPanel,
                    "Please select at least one region",
                    "No Region Selected",
                    JOptionPane.WARNING_MESSAGE);
                return;
            }

            try {
                new URL(targetUrl);

                logging.logToOutput("Creating gateways in " + selectedRegions.size() + " region(s) (parallel execution)...");

                // Use SwingWorker to create gateways in background
                SwingWorker<Map<String, Object>, Void> worker = new SwingWorker<>() {
                    @Override
                    protected Map<String, Object> doInBackground() {
                        Map<String, Object> result = new HashMap<>();
                        List<AwsIpRotatorManager.AwsIpRotatorGateway> successGateways = Collections.synchronizedList(new ArrayList<>());
                        List<String> failures = Collections.synchronizedList(new ArrayList<>());

                        // Create executor service for parallel execution
                        ExecutorService executor = Executors.newFixedThreadPool(Math.min(selectedRegions.size(), 10));
                        List<CompletableFuture<Void>> futures = new ArrayList<>();

                        for (String region : selectedRegions) {
                            CompletableFuture<Void> future = CompletableFuture.runAsync(() -> {
                                try {
                                    logging.logToOutput("Creating AWS IP Rotator gateway for: " + targetUrl + " in region: " + region + " with stage: " + stageName);

                                    AwsIpRotatorManager.AwsIpRotatorGateway gateway = awsManager.createGatewayInRegion(targetUrl, region, stageName);

                                    if (gateway != null) {
                                        successGateways.add(gateway);
                                        logging.logToOutput("Created gateway: " + gateway.apiId + " in " + region);
                                    } else {
                                        failures.add(region + ": " + awsManager.getLastError());
                                        logging.logToError("Failed to create gateway in " + region + ": " + awsManager.getLastError());
                                    }
                                } catch (Exception e) {
                                    failures.add(region + ": " + e.getMessage());
                                    logging.logToError("Exception creating gateway in " + region + ": " + e.getMessage());
                                }
                            }, executor);

                            futures.add(future);
                        }

                        // Wait for all to complete
                        try {
                            CompletableFuture.allOf(futures.toArray(new CompletableFuture[0])).join();
                        } catch (Exception e) {
                            logging.logToError("Error during parallel gateway creation: " + e.getMessage());
                        } finally {
                            executor.shutdown();
                        }

                        result.put("success", successGateways);
                        result.put("failures", failures);
                        return result;
                    }

                    @Override
                    protected void done() {
                        try {
                            Map<String, Object> result = get();
                            @SuppressWarnings("unchecked")
                            List<AwsIpRotatorManager.AwsIpRotatorGateway> successGateways = (List<AwsIpRotatorManager.AwsIpRotatorGateway>) result.get("success");
                            @SuppressWarnings("unchecked")
                            List<String> failures = (List<String>) result.get("failures");

                            // Add successful gateways to table
                            for (AwsIpRotatorManager.AwsIpRotatorGateway gateway : successGateways) {
                                gatewaysTableModel.addRow(new Object[]{
                                    gateway.apiId,
                                    gateway.name,
                                    gateway.targetUrl,
                                    gateway.proxyUrl,
                                    gateway.region,
                                    gateway.createdDate.toString()
                                });
                            }

                            // Build summary message
                            StringBuilder resultMessage = new StringBuilder();
                            for (AwsIpRotatorManager.AwsIpRotatorGateway gateway : successGateways) {
                                resultMessage.append("✓ ").append(gateway.region).append(": ").append(gateway.apiId).append("\n");
                            }
                            for (String failure : failures) {
                                resultMessage.append("✗ ").append(failure).append("\n");
                            }

                            int successCount = successGateways.size();
                            int failureCount = failures.size();

                            String title = (failureCount == 0) ? "Success" : "Partial Success";
                            int messageType = (failureCount == 0) ? JOptionPane.INFORMATION_MESSAGE : JOptionPane.WARNING_MESSAGE;

                            JOptionPane.showMessageDialog(mainPanel,
                                String.format("Gateway creation complete:\n\n%s\nSuccess: %d | Failed: %d",
                                    resultMessage.toString(), successCount, failureCount),
                                title,
                                messageType);

                            logging.logToOutput("Gateway creation complete: " + successCount + " succeeded, " + failureCount + " failed");

                        } catch (Exception ex) {
                            logging.logToError("Failed to process gateway creation results: " + ex.getMessage());
                            JOptionPane.showMessageDialog(mainPanel,
                                "Failed to create gateways: " + ex.getMessage(),
                                "Error",
                                JOptionPane.ERROR_MESSAGE);
                        }
                    }
                };

                worker.execute();

            } catch (MalformedURLException ex) {
                JOptionPane.showMessageDialog(mainPanel,
                    "Invalid URL format!",
                    "Error",
                    JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    /**
     * Custom dialog for gateway creation with region selection
     */
    private static class GatewayCreationDialog extends JDialog {
        private JTextField urlField;
        private JTextField stageNameField;
        private JCheckBox multiRegionCheckbox;
        private JComboBox<String> singleRegionCombo;
        private JPanel regionSelectionPanel;
        private Map<String, JCheckBox> regionCheckboxes;
        private boolean confirmed = false;

        // Common AWS regions
        private static final String[] COMMON_REGIONS = {
            "us-east-1", "us-east-2", "us-west-1", "us-west-2",
            "eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1", "eu-north-1",
            "ap-south-1", "ap-northeast-1", "ap-northeast-2", "ap-southeast-1", "ap-southeast-2",
            "ca-central-1", "sa-east-1"
        };

        public GatewayCreationDialog(JPanel parent) {
            super(SwingUtilities.getWindowAncestor(parent), "Create AWS IP Rotator Gateway", Dialog.ModalityType.APPLICATION_MODAL);

            regionCheckboxes = new HashMap<>();
            initComponents();
            pack();
            setLocationRelativeTo(parent);
        }

        private void initComponents() {
            setLayout(new BorderLayout(10, 10));

            JPanel contentPanel = new JPanel(new GridBagLayout());
            contentPanel.setBorder(BorderFactory.createEmptyBorder(15, 15, 15, 15));
            GridBagConstraints gbc = new GridBagConstraints();
            gbc.fill = GridBagConstraints.HORIZONTAL;
            gbc.insets = new Insets(5, 5, 5, 5);

            // Target URL
            gbc.gridx = 0; gbc.gridy = 0; gbc.gridwidth = 1;
            contentPanel.add(new JLabel("Target URL:"), gbc);

            urlField = new JTextField(40);
            gbc.gridx = 1; gbc.gridy = 0; gbc.gridwidth = 2;
            contentPanel.add(urlField, gbc);

            // Stage Name
            gbc.gridx = 0; gbc.gridy = 1; gbc.gridwidth = 1;
            contentPanel.add(new JLabel("Stage Name:"), gbc);

            stageNameField = new JTextField("v1", 20);
            stageNameField.setToolTipText("AWS API Gateway stage name (e.g., v1, v2, release, alpha)");
            gbc.gridx = 1; gbc.gridy = 1; gbc.gridwidth = 2;
            contentPanel.add(stageNameField, gbc);

            // Multi-region checkbox
            multiRegionCheckbox = new JCheckBox("Create in multiple regions");
            gbc.gridx = 0; gbc.gridy = 2; gbc.gridwidth = 3;
            contentPanel.add(multiRegionCheckbox, gbc);

            // Single region selection (shown by default)
            gbc.gridx = 0; gbc.gridy = 3; gbc.gridwidth = 1;
            contentPanel.add(new JLabel("Region:"), gbc);

            singleRegionCombo = new JComboBox<>(COMMON_REGIONS);
            singleRegionCombo.setSelectedItem("us-east-1");
            gbc.gridx = 1; gbc.gridy = 3; gbc.gridwidth = 2;
            contentPanel.add(singleRegionCombo, gbc);

            // Multi-region selection panel (hidden by default)
            regionSelectionPanel = new JPanel(new GridLayout(0, 3, 5, 5));
            regionSelectionPanel.setBorder(BorderFactory.createTitledBorder("Select Regions"));

            for (String region : COMMON_REGIONS) {
                JCheckBox cb = new JCheckBox(region);
                regionCheckboxes.put(region, cb);
                regionSelectionPanel.add(cb);
            }

            // "Select All" checkbox for multi-region
            JCheckBox selectAllCheckbox = new JCheckBox("Select All Regions");
            selectAllCheckbox.setVisible(false);
            selectAllCheckbox.addActionListener(e -> {
                boolean selected = selectAllCheckbox.isSelected();
                for (JCheckBox cb : regionCheckboxes.values()) {
                    cb.setSelected(selected);
                }
            });

            gbc.gridx = 0; gbc.gridy = 4; gbc.gridwidth = 3;
            gbc.fill = GridBagConstraints.HORIZONTAL;
            gbc.weightx = 1.0; gbc.weighty = 0;
            contentPanel.add(selectAllCheckbox, gbc);

            JScrollPane scrollPane = new JScrollPane(regionSelectionPanel);
            scrollPane.setPreferredSize(new Dimension(500, 150));
            scrollPane.setVisible(false);

            gbc.gridx = 0; gbc.gridy = 5; gbc.gridwidth = 3;
            gbc.fill = GridBagConstraints.BOTH;
            gbc.weightx = 1.0; gbc.weighty = 1.0;
            contentPanel.add(scrollPane, gbc);

            // Toggle visibility based on checkbox
            multiRegionCheckbox.addActionListener(e -> {
                boolean multiRegion = multiRegionCheckbox.isSelected();
                singleRegionCombo.setVisible(!multiRegion);
                selectAllCheckbox.setVisible(multiRegion);
                scrollPane.setVisible(multiRegion);
                pack();
            });

            add(contentPanel, BorderLayout.CENTER);

            // Buttons
            JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
            JButton createBtn = new JButton("Create");
            JButton cancelBtn = new JButton("Cancel");

            createBtn.addActionListener(e -> {
                if (urlField.getText().trim().isEmpty()) {
                    JOptionPane.showMessageDialog(this, "Please enter a target URL", "Error", JOptionPane.ERROR_MESSAGE);
                    return;
                }
                if (stageNameField.getText().trim().isEmpty()) {
                    JOptionPane.showMessageDialog(this, "Please enter a stage name", "Error", JOptionPane.ERROR_MESSAGE);
                    return;
                }
                // Validate stage name (alphanumeric, hyphens, underscores only)
                String stageName = stageNameField.getText().trim();
                if (!stageName.matches("[a-zA-Z0-9_-]+")) {
                    JOptionPane.showMessageDialog(this, "Stage name can only contain letters, numbers, hyphens, and underscores", "Error", JOptionPane.ERROR_MESSAGE);
                    return;
                }
                // Check if stage name is blacklisted
                if (isStagNameBanned(stageName)) {
                    JOptionPane.showMessageDialog(this,
                        "Stage name '" + stageName + "' is not allowed.\n\n" +
                        "This stage name may be flagged by security systems.\n" +
                        "Please use a neutral name like: v1, v2, v3, release, alpha, beta, etc.",
                        "Banned Stage Name",
                        JOptionPane.ERROR_MESSAGE);
                    return;
                }
                confirmed = true;
                dispose();
            });

            cancelBtn.addActionListener(e -> {
                confirmed = false;
                dispose();
            });

            buttonPanel.add(createBtn);
            buttonPanel.add(cancelBtn);
            add(buttonPanel, BorderLayout.SOUTH);
        }

        public boolean isConfirmed() {
            return confirmed;
        }

        public String getTargetUrl() {
            return urlField.getText();
        }

        public String getStageName() {
            return stageNameField.getText().trim();
        }

        public List<String> getSelectedRegions() {
            List<String> regions = new ArrayList<>();
            if (multiRegionCheckbox.isSelected()) {
                // Get all checked regions
                for (Map.Entry<String, JCheckBox> entry : regionCheckboxes.entrySet()) {
                    if (entry.getValue().isSelected()) {
                        regions.add(entry.getKey());
                    }
                }
            } else {
                // Get single selected region
                regions.add((String) singleRegionCombo.getSelectedItem());
            }
            return regions;
        }
    }

    /**
     * Modal dialog for mass gateway setup from context menu
     */
    private static class MassGatewaySetupDialog extends JDialog {
        private boolean confirmed = false;
        private JTextField stageNameField;
        private JCheckBox multiRegionCheckbox;
        private JComboBox<String> singleRegionCombo;
        private JPanel regionSelectionPanel;
        private Map<String, JCheckBox> regionCheckboxes;
        private DefaultTableModel hostTableModel;
        private List<HostInfo> allHosts;
        private Set<String> existingDomains;

        private static final String[] COMMON_REGIONS = {
            "us-east-1", "us-east-2", "us-west-1", "us-west-2",
            "eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1", "eu-north-1",
            "ap-south-1", "ap-northeast-1", "ap-northeast-2", "ap-southeast-1", "ap-southeast-2",
            "ca-central-1", "sa-east-1"
        };

        public MassGatewaySetupDialog(JPanel parent, List<HostInfo> hosts, Set<String> existingDomains) {
            super(SwingUtilities.getWindowAncestor(parent), "Mass Gateway Setup", Dialog.ModalityType.APPLICATION_MODAL);
            this.allHosts = hosts;
            this.existingDomains = existingDomains;
            this.regionCheckboxes = new HashMap<>();
            initComponents();
            pack();
            setLocationRelativeTo(parent);
        }

        private void initComponents() {
            setLayout(new BorderLayout(10, 10));

            JPanel contentPanel = new JPanel(new BorderLayout(10, 10));
            contentPanel.setBorder(BorderFactory.createEmptyBorder(15, 15, 15, 15));

            // === Domain table ===
            String[] columns = {"Selected", "Domain", "Status"};
            hostTableModel = new DefaultTableModel(columns, 0) {
                @Override
                public Class<?> getColumnClass(int column) {
                    if (column == 0) return Boolean.class;
                    return String.class;
                }

                @Override
                public boolean isCellEditable(int row, int column) {
                    if (column != 0) return false;
                    // Disable checkbox for already-configured domains
                    String status = (String) getValueAt(row, 2);
                    return "New".equals(status);
                }
            };

            for (HostInfo host : allHosts) {
                boolean alreadyConfigured = existingDomains.contains(host.domain.toLowerCase());
                hostTableModel.addRow(new Object[]{
                    !alreadyConfigured,  // pre-checked for new, unchecked for existing
                    host.domain,
                    alreadyConfigured ? "Already configured" : "New"
                });
            }

            JTable hostTable = new JTable(hostTableModel);
            hostTable.setRowHeight(25);
            hostTable.getColumnModel().getColumn(0).setMaxWidth(70);
            hostTable.getColumnModel().getColumn(0).setMinWidth(70);
            hostTable.getColumnModel().getColumn(2).setMaxWidth(130);
            hostTable.getColumnModel().getColumn(2).setMinWidth(130);

            JScrollPane tableScrollPane = new JScrollPane(hostTable);
            tableScrollPane.setPreferredSize(new Dimension(550, Math.min(200, 30 + allHosts.size() * 25)));
            tableScrollPane.setBorder(BorderFactory.createTitledBorder("Domains (" + allHosts.size() + ")"));

            // Select All / Deselect All buttons
            JPanel selectButtonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
            JButton selectAllBtn = new JButton("Select All New");
            JButton deselectAllBtn = new JButton("Deselect All");
            selectAllBtn.addActionListener(e -> {
                for (int i = 0; i < hostTableModel.getRowCount(); i++) {
                    if ("New".equals(hostTableModel.getValueAt(i, 2))) {
                        hostTableModel.setValueAt(true, i, 0);
                    }
                }
            });
            deselectAllBtn.addActionListener(e -> {
                for (int i = 0; i < hostTableModel.getRowCount(); i++) {
                    if ("New".equals(hostTableModel.getValueAt(i, 2))) {
                        hostTableModel.setValueAt(false, i, 0);
                    }
                }
            });
            selectButtonPanel.add(selectAllBtn);
            selectButtonPanel.add(deselectAllBtn);

            JPanel topPanel = new JPanel(new BorderLayout());
            topPanel.add(tableScrollPane, BorderLayout.CENTER);
            topPanel.add(selectButtonPanel, BorderLayout.SOUTH);

            contentPanel.add(topPanel, BorderLayout.NORTH);

            // === Settings panel (stage name + regions) ===
            JPanel settingsPanel = new JPanel(new GridBagLayout());
            GridBagConstraints gbc = new GridBagConstraints();
            gbc.fill = GridBagConstraints.HORIZONTAL;
            gbc.insets = new Insets(5, 5, 5, 5);

            // Stage Name
            gbc.gridx = 0; gbc.gridy = 0; gbc.gridwidth = 1;
            settingsPanel.add(new JLabel("Stage Name:"), gbc);

            stageNameField = new JTextField("v1", 20);
            stageNameField.setToolTipText("AWS API Gateway stage name (e.g., v1, v2, release, alpha)");
            gbc.gridx = 1; gbc.gridy = 0; gbc.gridwidth = 2;
            settingsPanel.add(stageNameField, gbc);

            // Multi-region checkbox
            multiRegionCheckbox = new JCheckBox("Create in multiple regions");
            gbc.gridx = 0; gbc.gridy = 1; gbc.gridwidth = 3;
            settingsPanel.add(multiRegionCheckbox, gbc);

            // Single region combo
            gbc.gridx = 0; gbc.gridy = 2; gbc.gridwidth = 1;
            settingsPanel.add(new JLabel("Region:"), gbc);

            singleRegionCombo = new JComboBox<>(COMMON_REGIONS);
            singleRegionCombo.setSelectedItem("us-east-1");
            gbc.gridx = 1; gbc.gridy = 2; gbc.gridwidth = 2;
            settingsPanel.add(singleRegionCombo, gbc);

            // Multi-region panel
            regionSelectionPanel = new JPanel(new GridLayout(0, 3, 5, 5));
            regionSelectionPanel.setBorder(BorderFactory.createTitledBorder("Select Regions"));

            for (String region : COMMON_REGIONS) {
                JCheckBox cb = new JCheckBox(region);
                regionCheckboxes.put(region, cb);
                regionSelectionPanel.add(cb);
            }

            JCheckBox selectAllRegions = new JCheckBox("Select All Regions");
            selectAllRegions.setVisible(false);
            selectAllRegions.addActionListener(e -> {
                boolean selected = selectAllRegions.isSelected();
                for (JCheckBox cb : regionCheckboxes.values()) {
                    cb.setSelected(selected);
                }
            });

            gbc.gridx = 0; gbc.gridy = 3; gbc.gridwidth = 3;
            settingsPanel.add(selectAllRegions, gbc);

            JScrollPane regionScrollPane = new JScrollPane(regionSelectionPanel);
            regionScrollPane.setPreferredSize(new Dimension(500, 150));
            regionScrollPane.setVisible(false);

            gbc.gridx = 0; gbc.gridy = 4; gbc.gridwidth = 3;
            gbc.fill = GridBagConstraints.BOTH;
            gbc.weightx = 1.0; gbc.weighty = 1.0;
            settingsPanel.add(regionScrollPane, gbc);

            multiRegionCheckbox.addActionListener(e -> {
                boolean multi = multiRegionCheckbox.isSelected();
                singleRegionCombo.setVisible(!multi);
                selectAllRegions.setVisible(multi);
                regionScrollPane.setVisible(multi);
                pack();
            });

            contentPanel.add(settingsPanel, BorderLayout.CENTER);
            add(contentPanel, BorderLayout.CENTER);

            // === Buttons ===
            JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
            JButton setupBtn = new JButton("Setup");
            JButton cancelBtn = new JButton("Cancel");

            setupBtn.addActionListener(e -> {
                // Validate stage name
                String stageName = stageNameField.getText().trim();
                if (stageName.isEmpty()) {
                    JOptionPane.showMessageDialog(this, "Please enter a stage name", "Error", JOptionPane.ERROR_MESSAGE);
                    return;
                }
                if (!stageName.matches("[a-zA-Z0-9_-]+")) {
                    JOptionPane.showMessageDialog(this, "Stage name can only contain letters, numbers, hyphens, and underscores", "Error", JOptionPane.ERROR_MESSAGE);
                    return;
                }
                if (isStagNameBanned(stageName)) {
                    JOptionPane.showMessageDialog(this,
                        "Stage name '" + stageName + "' is not allowed.\n\n" +
                        "This stage name may be flagged by security systems.\n" +
                        "Please use a neutral name like: v1, v2, v3, release, alpha, beta, etc.",
                        "Banned Stage Name", JOptionPane.ERROR_MESSAGE);
                    return;
                }
                // Validate at least one host selected
                if (getSelectedHosts().isEmpty()) {
                    JOptionPane.showMessageDialog(this, "Please select at least one domain", "Error", JOptionPane.ERROR_MESSAGE);
                    return;
                }
                // Validate at least one region
                if (getSelectedRegions().isEmpty()) {
                    JOptionPane.showMessageDialog(this, "Please select at least one region", "Error", JOptionPane.ERROR_MESSAGE);
                    return;
                }
                confirmed = true;
                dispose();
            });

            cancelBtn.addActionListener(e -> {
                confirmed = false;
                dispose();
            });

            buttonPanel.add(setupBtn);
            buttonPanel.add(cancelBtn);
            add(buttonPanel, BorderLayout.SOUTH);
        }

        public boolean isConfirmed() {
            return confirmed;
        }

        public String getStageName() {
            return stageNameField.getText().trim();
        }

        public List<HostInfo> getSelectedHosts() {
            List<HostInfo> selected = new ArrayList<>();
            for (int i = 0; i < hostTableModel.getRowCount(); i++) {
                Boolean checked = (Boolean) hostTableModel.getValueAt(i, 0);
                if (checked != null && checked) {
                    selected.add(allHosts.get(i));
                }
            }
            return selected;
        }

        public List<String> getSelectedRegions() {
            List<String> regions = new ArrayList<>();
            if (multiRegionCheckbox.isSelected()) {
                for (Map.Entry<String, JCheckBox> entry : regionCheckboxes.entrySet()) {
                    if (entry.getValue().isSelected()) {
                        regions.add(entry.getKey());
                    }
                }
            } else {
                regions.add((String) singleRegionCombo.getSelectedItem());
            }
            return regions;
        }
    }

    /**
     * Use selected gateway for domain mapping
     */
    private void useGatewayForMapping(String targetUrl, String proxyUrl) {
        try {
            URL url = new URL(targetUrl);
            String domain = url.getHost();

            // Remove trailing slash from proxyUrl if present
            if (proxyUrl.endsWith("/")) {
                proxyUrl = proxyUrl.substring(0, proxyUrl.length() - 1);
            }

            // Extract region from proxy URL
            String region = extractRegionFromUrl(proxyUrl);

            // Check if domain already exists
            DomainConfig dc = config.domainConfigs.get(domain);
            boolean isNewDomain = (dc == null);

            if (dc == null) {
                dc = new DomainConfig(domain);
                config.domainConfigs.put(domain, dc);
            }

            // Add gateway to domain
            GatewayConfig gateway = new GatewayConfig(proxyUrl, region);
            dc.addGateway(gateway);

            // Update or add to table
            if (isNewDomain) {
                mappingsTableModel.addRow(new Object[]{
                    domain,
                    dc.getGatewayCount(),
                    dc.getStrategy().toString()
                });
                logging.logToOutput("Created domain " + domain + " and added gateway: " + proxyUrl + " (" + region + ")");
            } else {
                // Find and update existing row
                for (int i = 0; i < mappingsTableModel.getRowCount(); i++) {
                    if (domain.equals(mappingsTableModel.getValueAt(i, 0))) {
                        mappingsTableModel.setValueAt(dc.getGatewayCount(), i, 1);
                        break;
                    }
                }
                logging.logToOutput("Added gateway to existing domain " + domain + ": " + proxyUrl + " (" + region + ")");
            }

            // Success - no dialog shown here, let caller handle messaging
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(mainPanel,
                "Failed to add gateway: " + ex.getMessage(),
                "Error",
                JOptionPane.ERROR_MESSAGE);
        }
    }

    /**
     * Add domains from a list of HttpRequestResponse items (used by context menu).
     * Extracts unique hosts, detects protocol/port, and launches mass gateway setup.
     */
    private void addDomainsFromRequestResponses(List<HttpRequestResponse> items) {
        // Extract unique hosts with protocol and port info
        // Key: lowercase host, Value: HostInfo with best target URL
        Map<String, HostInfo> hostMap = new LinkedHashMap<>();

        for (HttpRequestResponse item : items) {
            try {
                if (item == null || item.request() == null || item.request().httpService() == null) {
                    continue;
                }
                HttpService service = item.request().httpService();
                String host = service.host().toLowerCase();
                if (host.isEmpty()) continue;

                boolean isSecure = service.secure();
                int port = service.port();

                // Build target URL: prefer HTTPS if seen in any request
                HostInfo existing = hostMap.get(host);
                if (existing == null || isSecure) {
                    String scheme = isSecure ? "https" : "http";
                    boolean nonStandardPort = (isSecure && port != 443) || (!isSecure && port != 80);
                    String targetUrl = scheme + "://" + host + (nonStandardPort ? ":" + port : "");
                    hostMap.put(host, new HostInfo(host, targetUrl));
                }
            } catch (Exception e) {
                logging.logToError("Failed to extract host from request: " + e.getMessage());
            }
        }

        if (hostMap.isEmpty()) {
            JOptionPane.showMessageDialog(mainPanel,
                "No domains found in the selected items.",
                "Send to AWS IP Rotator",
                JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        // Check if AWS manager is initialized
        if (awsManager == null) {
            JOptionPane.showMessageDialog(mainPanel,
                "AWS credentials are not configured.\n\n" +
                "Please go to the 'AWS Configuration' tab and connect to AWS first.",
                "AWS Not Connected",
                JOptionPane.ERROR_MESSAGE);
            return;
        }

        // Build set of already-configured domains (lowercase)
        Set<String> existingDomains = new LinkedHashSet<>();
        for (String domain : config.domainConfigs.keySet()) {
            existingDomains.add(domain.toLowerCase());
        }

        List<HostInfo> allHosts = new ArrayList<>(hostMap.values());

        // Show mass gateway setup dialog
        MassGatewaySetupDialog dialog = new MassGatewaySetupDialog(mainPanel, allHosts, existingDomains);
        dialog.setVisible(true);

        if (dialog.isConfirmed()) {
            List<HostInfo> selectedHosts = dialog.getSelectedHosts();
            String stageName = dialog.getStageName();
            List<String> selectedRegions = dialog.getSelectedRegions();
            executeMassGatewaySetup(selectedHosts, stageName, selectedRegions);
        }
    }

    /**
     * Execute mass gateway setup: create gateways for multiple hosts across multiple regions
     */
    private void executeMassGatewaySetup(List<HostInfo> selectedHosts, String stageName, List<String> selectedRegions) {
        int totalOps = selectedHosts.size() * selectedRegions.size();
        logging.logToOutput("Starting mass gateway setup: " + selectedHosts.size() + " host(s) x " +
            selectedRegions.size() + " region(s) = " + totalOps + " gateway(s)...");

        SwingWorker<Map<String, Object>, Void> worker = new SwingWorker<>() {
            @Override
            protected Map<String, Object> doInBackground() {
                Map<String, Object> result = new HashMap<>();
                // Per-host results: domain -> list of successful gateways
                Map<String, List<AwsIpRotatorManager.AwsIpRotatorGateway>> successByHost = Collections.synchronizedMap(new LinkedHashMap<>());
                // Per-host failures: domain -> list of "region: error"
                Map<String, List<String>> failuresByHost = Collections.synchronizedMap(new LinkedHashMap<>());

                // Initialize maps
                for (HostInfo host : selectedHosts) {
                    successByHost.put(host.domain, Collections.synchronizedList(new ArrayList<>()));
                    failuresByHost.put(host.domain, Collections.synchronizedList(new ArrayList<>()));
                }

                ExecutorService executor = Executors.newFixedThreadPool(Math.min(totalOps, 10));
                List<CompletableFuture<Void>> futures = new ArrayList<>();

                for (HostInfo host : selectedHosts) {
                    for (String region : selectedRegions) {
                        CompletableFuture<Void> future = CompletableFuture.runAsync(() -> {
                            try {
                                logging.logToOutput("Creating gateway for " + host.domain + " in " + region + "...");
                                AwsIpRotatorManager.AwsIpRotatorGateway gateway =
                                    awsManager.createGatewayInRegion(host.targetUrl, region, stageName);

                                if (gateway != null) {
                                    successByHost.get(host.domain).add(gateway);
                                    logging.logToOutput("Created gateway for " + host.domain + " in " + region + ": " + gateway.apiId);
                                } else {
                                    failuresByHost.get(host.domain).add(region + ": " + awsManager.getLastError());
                                    logging.logToError("Failed to create gateway for " + host.domain + " in " + region);
                                }
                            } catch (Exception e) {
                                failuresByHost.get(host.domain).add(region + ": " + e.getMessage());
                                logging.logToError("Exception creating gateway for " + host.domain + " in " + region + ": " + e.getMessage());
                            }
                        }, executor);
                        futures.add(future);
                    }
                }

                try {
                    CompletableFuture.allOf(futures.toArray(new CompletableFuture[0])).join();
                } catch (Exception e) {
                    logging.logToError("Error during mass gateway creation: " + e.getMessage());
                } finally {
                    executor.shutdown();
                }

                result.put("successByHost", successByHost);
                result.put("failuresByHost", failuresByHost);
                return result;
            }

            @Override
            @SuppressWarnings("unchecked")
            protected void done() {
                try {
                    Map<String, Object> result = get();
                    Map<String, List<AwsIpRotatorManager.AwsIpRotatorGateway>> successByHost =
                        (Map<String, List<AwsIpRotatorManager.AwsIpRotatorGateway>>) result.get("successByHost");
                    Map<String, List<String>> failuresByHost =
                        (Map<String, List<String>>) result.get("failuresByHost");

                    int totalCreated = 0;
                    int totalFailed = 0;
                    int domainsWithGateways = 0;

                    // Process results: create/update domain configs and UI tables
                    for (HostInfo host : selectedHosts) {
                        List<AwsIpRotatorManager.AwsIpRotatorGateway> gateways = successByHost.get(host.domain);
                        if (gateways == null || gateways.isEmpty()) {
                            totalFailed += failuresByHost.getOrDefault(host.domain, Collections.emptyList()).size();
                            continue;
                        }

                        domainsWithGateways++;
                        totalCreated += gateways.size();
                        totalFailed += failuresByHost.getOrDefault(host.domain, Collections.emptyList()).size();

                        // Get or create DomainConfig
                        DomainConfig dc = config.domainConfigs.get(host.domain);
                        boolean isNewDomain = (dc == null);
                        if (dc == null) {
                            dc = new DomainConfig(host.domain);
                            config.domainConfigs.put(host.domain, dc);
                        }

                        // Add each gateway to domain config
                        for (AwsIpRotatorManager.AwsIpRotatorGateway gw : gateways) {
                            String proxyUrl = gw.proxyUrl;
                            if (proxyUrl.endsWith("/")) {
                                proxyUrl = proxyUrl.substring(0, proxyUrl.length() - 1);
                            }
                            String region = extractRegionFromUrl(proxyUrl);
                            GatewayConfig gc = new GatewayConfig(proxyUrl, region);
                            dc.addGateway(gc);

                            // Add to AWS Gateways table
                            gatewaysTableModel.addRow(new Object[]{
                                gw.apiId, gw.name, gw.targetUrl, gw.proxyUrl, gw.region,
                                gw.createdDate.toString()
                            });
                        }

                        // Update or add to Domain Mappings table
                        if (isNewDomain) {
                            mappingsTableModel.addRow(new Object[]{
                                host.domain, dc.getGatewayCount(), dc.getStrategy().toString()
                            });
                        } else {
                            for (int i = 0; i < mappingsTableModel.getRowCount(); i++) {
                                if (host.domain.equals(mappingsTableModel.getValueAt(i, 0))) {
                                    mappingsTableModel.setValueAt(dc.getGatewayCount(), i, 1);
                                    break;
                                }
                            }
                        }
                    }

                    saveDomainMappings();

                    // Build summary
                    StringBuilder summary = new StringBuilder("Mass Setup Complete:\n\n");
                    for (HostInfo host : selectedHosts) {
                        List<AwsIpRotatorManager.AwsIpRotatorGateway> gateways = successByHost.get(host.domain);
                        List<String> failures = failuresByHost.getOrDefault(host.domain, Collections.emptyList());

                        if (gateways != null && !gateways.isEmpty()) {
                            StringBuilder regions = new StringBuilder();
                            for (int i = 0; i < gateways.size(); i++) {
                                if (i > 0) regions.append(", ");
                                regions.append(gateways.get(i).region);
                            }
                            summary.append("+ ").append(host.domain).append(": ")
                                .append(gateways.size()).append(" gateway(s) (").append(regions).append(")\n");
                        }
                        for (String failure : failures) {
                            summary.append("x ").append(host.domain).append(": Failed in ").append(failure).append("\n");
                        }
                    }

                    summary.append("\nTotal: ").append(totalCreated).append(" gateway(s) created across ")
                        .append(domainsWithGateways).append(" domain(s)");
                    if (totalFailed > 0) {
                        summary.append(", ").append(totalFailed).append(" failed");
                    }

                    String title = (totalFailed == 0) ? "Mass Setup Complete" : "Mass Setup Complete (with errors)";
                    int messageType = (totalFailed == 0) ? JOptionPane.INFORMATION_MESSAGE : JOptionPane.WARNING_MESSAGE;
                    JOptionPane.showMessageDialog(mainPanel, summary.toString(), title, messageType);

                    logging.logToOutput("Mass gateway setup complete: " + totalCreated + " created, " + totalFailed + " failed");

                } catch (Exception ex) {
                    logging.logToError("Failed to process mass gateway setup results: " + ex.getMessage());
                    JOptionPane.showMessageDialog(mainPanel,
                        "Failed during mass gateway setup: " + ex.getMessage(),
                        "Error", JOptionPane.ERROR_MESSAGE);
                }
            }
        };

        worker.execute();
    }

    /**
     * Update a gateway (non-blocking)
     */
    private void updateGateway(String apiId) {
        if (awsManager == null) {
            return;
        }

        String newTargetUrl = JOptionPane.showInputDialog(mainPanel,
            "Enter new target URL:",
            "Update Gateway",
            JOptionPane.PLAIN_MESSAGE);

        if (newTargetUrl != null && !newTargetUrl.trim().isEmpty()) {
            final String targetUrl = newTargetUrl.trim();

            try {
                new URL(targetUrl);

                logging.logToOutput("Updating gateway " + apiId + " (background operation)...");

                // Use SwingWorker to update gateway in background
                SwingWorker<Boolean, Void> worker = new SwingWorker<>() {
                    @Override
                    protected Boolean doInBackground() {
                        // This runs in background thread - won't freeze UI
                        return awsManager.updateGateway(apiId, targetUrl);
                    }

                    @Override
                    protected void done() {
                        try {
                            boolean success = get();

                            if (success) {
                                logging.logToOutput("Updated gateway " + apiId + " to point to " + targetUrl);
                                JOptionPane.showMessageDialog(mainPanel,
                                    "Gateway updated successfully!",
                                    "Success",
                                    JOptionPane.INFORMATION_MESSAGE);
                                refreshGatewayList();
                            } else {
                                JOptionPane.showMessageDialog(mainPanel,
                                    "Failed to update gateway: " + awsManager.getLastError(),
                                    "Error",
                                    JOptionPane.ERROR_MESSAGE);
                            }
                        } catch (Exception ex) {
                            logging.logToError("Failed to update gateway: " + ex.getMessage());
                            JOptionPane.showMessageDialog(mainPanel,
                                "Failed to update gateway: " + ex.getMessage(),
                                "Error",
                                JOptionPane.ERROR_MESSAGE);
                        }
                    }
                };

                worker.execute();

            } catch (MalformedURLException ex) {
                JOptionPane.showMessageDialog(mainPanel,
                    "Invalid URL format!",
                    "Error",
                    JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    /**
     * Delete a gateway
     */
    private void deleteGateway(String apiId, String name) {
        if (awsManager == null) {
            return;
        }

        int confirm = JOptionPane.showConfirmDialog(mainPanel,
            "Delete gateway " + name + " (" + apiId + ")?\n\n" +
            "This will permanently delete the API Gateway from AWS.",
            "Confirm Delete",
            JOptionPane.YES_NO_OPTION,
            JOptionPane.WARNING_MESSAGE);

        if (confirm == JOptionPane.YES_OPTION) {
            boolean success = awsManager.deleteGateway(apiId);

            if (success) {
                logging.logToOutput("Deleted gateway: " + apiId);
                JOptionPane.showMessageDialog(mainPanel,
                    "Gateway deleted successfully!",
                    "Success",
                    JOptionPane.INFORMATION_MESSAGE);
                refreshGatewayList();
            } else {
                JOptionPane.showMessageDialog(mainPanel,
                    "Failed to delete gateway: " + awsManager.getLastError(),
                    "Error",
                    JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    /**
     * Simple holder for a domain and its target URL (used by mass gateway setup)
     */
    private static class HostInfo {
        final String domain;     // e.g. "api.example.com"
        final String targetUrl;  // e.g. "https://api.example.com" or "http://api.example.com:8080"

        HostInfo(String domain, String targetUrl) {
            this.domain = domain;
            this.targetUrl = targetUrl;
        }
    }

    /**
     * Configuration storage class
     */
    private static class AwsIpRotatorConfig {
        boolean enabled = false;
        Map<String, DomainConfig> domainConfigs = new HashMap<>(); // domain -> DomainConfig
        boolean preserveOriginalHost = false;
    }

    /**
     * Context menu provider that adds "Send to AWS IP Rotator" to right-click menus
     */
    private class AwsIpRotatorContextMenuProvider implements ContextMenuItemsProvider {
        @Override
        public List<Component> provideMenuItems(ContextMenuEvent event) {
            List<HttpRequestResponse> items = new ArrayList<>();

            // Collect from list views (proxy history, site map, search results, etc.)
            if (event.selectedRequestResponses() != null) {
                items.addAll(event.selectedRequestResponses());
            }

            // Collect from message editor (single item view)
            if (event.messageEditorRequestResponse().isPresent()) {
                items.add(event.messageEditorRequestResponse().get().requestResponse());
            }

            if (items.isEmpty()) {
                return Collections.emptyList();
            }

            JMenuItem menuItem = new JMenuItem("Send to AWS IP Rotator");
            final List<HttpRequestResponse> finalItems = items;
            menuItem.addActionListener(e -> addDomainsFromRequestResponses(finalItems));

            return Collections.singletonList(menuItem);
        }
    }

    /**
     * HTTP Handler that rewrites requests to use AWS IP Rotator with multi-region rotation
     */
    private class AwsIpRotatorHttpHandler implements HttpHandler {
        @Override
        public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
            // Only process if enabled and configured
            if (!config.enabled || config.domainConfigs.isEmpty()) {
                return RequestToBeSentAction.continueWith(requestToBeSent);
            }

            // Check if this request is for any of our configured domains
            String requestHost = requestToBeSent.httpService().host();
            DomainConfig domainConfig = null;

            // Find matching domain config (case-insensitive)
            for (Map.Entry<String, DomainConfig> entry : config.domainConfigs.entrySet()) {
                if (requestHost.equalsIgnoreCase(entry.getKey())) {
                    domainConfig = entry.getValue();
                    break;
                }
            }

            // No matching domain found or no gateways configured
            if (domainConfig == null || domainConfig.getGatewayCount() == 0) {
                return RequestToBeSentAction.continueWith(requestToBeSent);
            }

            // Get the next gateway URL based on rotation strategy
            String awsIpRotatorGatewayUrl = domainConfig.getNextGatewayUrl();

            // Safety check
            if (awsIpRotatorGatewayUrl == null) {
                return RequestToBeSentAction.continueWith(requestToBeSent);
            }

            try {
                // Parse AWS IP Rotator gateway URL
                URL gatewayUrl = new URL(awsIpRotatorGatewayUrl);
                String gatewayHost = gatewayUrl.getHost();
                int gatewayPort = gatewayUrl.getPort() != -1 ? gatewayUrl.getPort() :
                                  (gatewayUrl.getProtocol().equals("https") ? 443 : 80);
                boolean isHttps = gatewayUrl.getProtocol().equals("https");
                String gatewayPath = gatewayUrl.getPath();

                // Ensure gateway path ends with /
                if (!gatewayPath.endsWith("/")) {
                    gatewayPath += "/";
                }

                // Remove leading / from request path if present
                String requestPath = requestToBeSent.path();
                if (requestPath.startsWith("/")) {
                    requestPath = requestPath.substring(1);
                }

                // Build new path
                String newPath = gatewayPath + requestPath;

                // Build modified request with new path
                HttpRequest modifiedRequest = requestToBeSent.withPath(newPath);

                // Update Host header
                modifiedRequest = modifiedRequest.withUpdatedHeader("Host", gatewayHost);

                // Optionally preserve original host
                if (config.preserveOriginalHost) {
                    modifiedRequest = modifiedRequest.withAddedHeader("X-Original-Host", requestHost);
                }

                // Create new HTTP service for the gateway
                modifiedRequest = modifiedRequest.withService(
                    HttpService.httpService(gatewayHost, gatewayPort, isHttps)
                );

                // Log detailed rewriting information
                logging.logToOutput(String.format(
                    "[AWS IP Rotator] Request Rewritten:\n" +
                    "  Original: %s://%s%s\n" +
                    "  Gateway:  %s://%s%s\n" +
                    "  Host Header: %s -> %s\n" +
                    "  SNI: %s (auto-set by Montoya API)\n" +
                    "  Strategy: %s",
                    requestToBeSent.httpService().secure() ? "https" : "http",
                    requestHost,
                    requestToBeSent.path(),
                    isHttps ? "https" : "http",
                    gatewayHost,
                    newPath,
                    requestHost,
                    gatewayHost,
                    gatewayHost,
                    domainConfig.getStrategy()
                ));

                return RequestToBeSentAction.continueWith(modifiedRequest);

            } catch (MalformedURLException e) {
                logging.logToError("Invalid AWS IP Rotator gateway URL: " + e.getMessage());
                return RequestToBeSentAction.continueWith(requestToBeSent);
            }
        }

        @Override
        public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
            return ResponseReceivedAction.continueWith(responseReceived);
        }
    }
}
