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

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * FireProx Burp Extension
 *
 * This extension automatically rewrites requests to route through AWS FireProx gateways.
 * It modifies the SNI, Host header, and prepends the FireProx path to all matching requests.
 */
public class FireProxExtension implements BurpExtension {
    private MontoyaApi api;
    private Logging logging;
    private FireProxConfig config;
    private FireProxManager awsManager;
    private JPanel mainPanel;
    private DefaultTableModel gatewaysTableModel;
    private DefaultTableModel mappingsTableModel;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        this.logging = api.logging();
        this.config = new FireProxConfig();

        // Set extension name
        api.extension().setName("AWS IP Rotator");

        // Register HTTP handler
        api.http().registerHttpHandler(new FireProxHttpHandler());

        // Create and register UI
        createUI();
        api.userInterface().registerSuiteTab("AWS IP Rotator", mainPanel);

        logging.logToOutput("AWS IP Rotator loaded successfully!");
        logging.logToOutput("Configure multi-region rotation in the 'AWS IP Rotator' tab");
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
        });
        topPanel.add(enabledCheckbox);

        JCheckBox preserveHostCheckbox = new JCheckBox("Preserve original Host in X-Original-Host header", config.preserveOriginalHost);
        preserveHostCheckbox.addActionListener(e -> {
            config.preserveOriginalHost = preserveHostCheckbox.isSelected();
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
            "Enter FireProx Gateway URL:",
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
                    int successCount = 0;
                    int failureCount = 0;
                    StringBuilder results = new StringBuilder();

                    // Delete in reverse order to avoid index shifting issues
                    for (int i = selectedRows.length - 1; i >= 0; i--) {
                        int viewRow = selectedRows[i];
                        // Convert view row to model row (important when table is sorted)
                        int modelRow = gatewaysTable.convertRowIndexToModel(viewRow);

                        String apiId = (String) gatewaysTableModel.getValueAt(modelRow, 0);
                        String name = (String) gatewaysTableModel.getValueAt(modelRow, 1);
                        String region = (String) gatewaysTableModel.getValueAt(modelRow, 4); // Get region from column 4

                        if (awsManager != null && awsManager.deleteGatewayInRegion(apiId, region)) {
                            logging.logToOutput("Deleted gateway: " + apiId + " in region " + region);
                            gatewaysTableModel.removeRow(modelRow);
                            successCount++;
                        } else {
                            logging.logToError("Failed to delete gateway: " + apiId + " in region " + region);
                            results.append("✗ ").append(name).append(" (").append(apiId).append(") - ").append(region).append("\n");
                            failureCount++;
                        }
                    }

                    // Show summary
                    if (selectedRows.length > 1) {
                        String title = (failureCount == 0) ? "Success" : "Partial Success";
                        int messageType = (failureCount == 0) ? JOptionPane.INFORMATION_MESSAGE : JOptionPane.WARNING_MESSAGE;
                        String summary = String.format("Deletion complete:\n\nSuccess: %d | Failed: %d", successCount, failureCount);
                        if (failureCount > 0) {
                            summary += "\n\nFailed deletions:\n" + results.toString();
                        }
                        JOptionPane.showMessageDialog(mainPanel, summary, title, messageType);
                    } else if (failureCount > 0) {
                        JOptionPane.showMessageDialog(mainPanel,
                            "Failed to delete gateway: " + awsManager.getLastError(),
                            "Error",
                            JOptionPane.ERROR_MESSAGE);
                    }
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

        // Connect button
        gbc.gridx = 0;
        gbc.gridy = 6;
        gbc.gridwidth = 2;
        gbc.anchor = GridBagConstraints.CENTER;
        JButton connectButton = new JButton("Connect to AWS");
        connectButton.addActionListener(e -> {
            awsManager = new FireProxManager();
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
            "2. Select your AWS region (default: us-east-1)\n\n" +
            "3. Click 'Connect to AWS' to initialize the connection\n\n" +
            "4. Go to the 'AWS Gateways' tab to manage FireProx gateways\n\n" +
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
     * Refresh the AWS gateway list
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
        logging.logToOutput("Refreshing gateway list across all AWS regions...");

        gatewaysTableModel.setRowCount(0);

        // List gateways from ALL regions
        List<FireProxManager.FireProxGateway> gateways = awsManager.listGatewaysAllRegions();

        for (FireProxManager.FireProxGateway gateway : gateways) {
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

                // Create progress dialog for multi-region creation
                StringBuilder resultMessage = new StringBuilder();
                int successCount = 0;
                int failureCount = 0;

                for (String region : selectedRegions) {
                    logging.logToOutput("Creating FireProx gateway for: " + targetUrl + " in region: " + region);

                    FireProxManager.FireProxGateway gateway = awsManager.createGatewayInRegion(targetUrl, region);

                    if (gateway != null) {
                        gatewaysTableModel.addRow(new Object[]{
                            gateway.apiId,
                            gateway.name,
                            gateway.targetUrl,
                            gateway.proxyUrl,
                            gateway.region,
                            gateway.createdDate.toString()
                        });

                        logging.logToOutput("Created gateway: " + gateway.apiId + " in " + region);
                        resultMessage.append("✓ ").append(region).append(": ").append(gateway.apiId).append("\n");
                        successCount++;
                    } else {
                        logging.logToError("Failed to create gateway in " + region + ": " + awsManager.getLastError());
                        resultMessage.append("✗ ").append(region).append(": Failed - ").append(awsManager.getLastError()).append("\n");
                        failureCount++;
                    }
                }

                // Show summary
                String title = (failureCount == 0) ? "Success" : "Partial Success";
                int messageType = (failureCount == 0) ? JOptionPane.INFORMATION_MESSAGE : JOptionPane.WARNING_MESSAGE;

                JOptionPane.showMessageDialog(mainPanel,
                    String.format("Gateway creation complete:\n\n%s\nSuccess: %d | Failed: %d",
                        resultMessage.toString(), successCount, failureCount),
                    title,
                    messageType);

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
            super(SwingUtilities.getWindowAncestor(parent), "Create FireProx Gateway", Dialog.ModalityType.APPLICATION_MODAL);

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

            // Multi-region checkbox
            multiRegionCheckbox = new JCheckBox("Create in multiple regions");
            gbc.gridx = 0; gbc.gridy = 1; gbc.gridwidth = 3;
            contentPanel.add(multiRegionCheckbox, gbc);

            // Single region selection (shown by default)
            gbc.gridx = 0; gbc.gridy = 2; gbc.gridwidth = 1;
            contentPanel.add(new JLabel("Region:"), gbc);

            singleRegionCombo = new JComboBox<>(COMMON_REGIONS);
            singleRegionCombo.setSelectedItem("us-east-1");
            gbc.gridx = 1; gbc.gridy = 2; gbc.gridwidth = 2;
            contentPanel.add(singleRegionCombo, gbc);

            // Multi-region selection panel (hidden by default)
            regionSelectionPanel = new JPanel(new GridLayout(0, 3, 5, 5));
            regionSelectionPanel.setBorder(BorderFactory.createTitledBorder("Select Regions"));

            for (String region : COMMON_REGIONS) {
                JCheckBox cb = new JCheckBox(region);
                regionCheckboxes.put(region, cb);
                regionSelectionPanel.add(cb);
            }

            JScrollPane scrollPane = new JScrollPane(regionSelectionPanel);
            scrollPane.setPreferredSize(new Dimension(500, 150));
            scrollPane.setVisible(false);

            gbc.gridx = 0; gbc.gridy = 3; gbc.gridwidth = 3;
            gbc.fill = GridBagConstraints.BOTH;
            gbc.weightx = 1.0; gbc.weighty = 1.0;
            contentPanel.add(scrollPane, gbc);

            // Toggle visibility based on checkbox
            multiRegionCheckbox.addActionListener(e -> {
                boolean multiRegion = multiRegionCheckbox.isSelected();
                singleRegionCombo.setVisible(!multiRegion);
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
     * Update a gateway
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
            newTargetUrl = newTargetUrl.trim();

            try {
                new URL(newTargetUrl);
                boolean success = awsManager.updateGateway(apiId, newTargetUrl);

                if (success) {
                    logging.logToOutput("Updated gateway " + apiId + " to point to " + newTargetUrl);
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
     * Configuration storage class
     */
    private static class FireProxConfig {
        boolean enabled = false;
        Map<String, DomainConfig> domainConfigs = new HashMap<>(); // domain -> DomainConfig
        boolean preserveOriginalHost = false;
    }

    /**
     * HTTP Handler that rewrites requests to use FireProx with multi-region rotation
     */
    private class FireProxHttpHandler implements HttpHandler {
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
            String fireProxGatewayUrl = domainConfig.getNextGatewayUrl();

            // Safety check
            if (fireProxGatewayUrl == null) {
                return RequestToBeSentAction.continueWith(requestToBeSent);
            }

            try {
                // Parse FireProx gateway URL
                URL gatewayUrl = new URL(fireProxGatewayUrl);
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
                logging.logToError("Invalid FireProx gateway URL: " + e.getMessage());
                return RequestToBeSentAction.continueWith(requestToBeSent);
            }
        }

        @Override
        public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
            return ResponseReceivedAction.continueWith(responseReceived);
        }
    }
}
