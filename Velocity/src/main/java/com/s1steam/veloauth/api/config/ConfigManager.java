package com.s1steam.veloauth.api.config;

import com.s1steam.veloauth.api.VeloAuthAPI;
import org.yaml.snakeyaml.Yaml;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;

public class ConfigManager {
    
    private final VeloAuthAPI plugin;
    private final Path configPath;
    private Map<String, Object> config;
    
    public ConfigManager(VeloAuthAPI plugin) {
        this.plugin = plugin;
        this.configPath = plugin.getDataDirectory().resolve("config.yml");
        this.config = new HashMap<>();
    }
    
    public void loadConfig() {
        try {
            // Create data directory if it doesn't exist
            if (!Files.exists(plugin.getDataDirectory())) {
                Files.createDirectories(plugin.getDataDirectory());
            }
            
            // Create default config if it doesn't exist
            if (!Files.exists(configPath)) {
                saveDefaultConfig();
            }
            
            // Load config
            Yaml yaml = new Yaml();
            try (InputStream inputStream = Files.newInputStream(configPath)) {
                config = yaml.load(inputStream);
                if (config == null) {
                    config = new HashMap<>();
                }
            }
            
            // Validate config
            validateConfig();
            
        } catch (IOException e) {
            plugin.getLogger().error("Failed to load configuration", e);
            config = new HashMap<>();
        }
    }
    
    public void saveDefaultConfig() {
        try (InputStream inputStream = getClass().getResourceAsStream("/config.yml")) {
            if (inputStream == null) {
                // Create default config manually
                createDefaultConfig();
                return;
            }
            
            Files.copy(inputStream, configPath);
            plugin.getLogger().info("Default configuration created");
            
        } catch (IOException e) {
            plugin.getLogger().error("Failed to save default configuration", e);
            createDefaultConfig();
        }
    }
    
    private void createDefaultConfig() {
        try (BufferedWriter writer = Files.newBufferedWriter(configPath)) {
            writer.write(getDefaultConfigContent());
            plugin.getLogger().info("Default configuration created manually");
        } catch (IOException e) {
            plugin.getLogger().error("Failed to create default configuration", e);
        }
    }
    
    private String getDefaultConfigContent() {
        return "# VeloAuth API Configuration\n" +
               "# Автор: S1sTeam\n" +
               "# Версия: 1.0.0\n" +
               "\n" +
               "# ============================================\n" +
               "# ОСНОВНЫЕ НАСТРОЙКИ\n" +
               "# ============================================\n" +
               "plugin:\n" +
               "  version: \"1.0.0\"\n" +
               "  author: \"S1sTeam\"\n" +
               "\n" +
               "# ============================================\n" +
               "# НАСТРОЙКИ BACKEND СЕРВЕРА\n" +
               "# ============================================\n" +
               "backend:\n" +
               "  server-name: \"lobby\"\n" +
               "\n" +
               "# ============================================\n" +
               "# НАСТРОЙКИ СИНХРОНИЗАЦИИ\n" +
               "# ============================================\n" +
               "sync:\n" +
               "  debug: false\n" +
               "  channel: \"veloauth:sync\"\n" +
               "\n" +
               "# ============================================\n" +
               "# СООБЩЕНИЯ\n" +
               "# ============================================\n" +
               "messages:\n" +
               "  prefix: \"§6[VeloAuth API]§r\"\n" +
               "  reload: \"§aКонфигурация успешно перезагружена!\"\n" +
               "  info: |\n" +
               "    §6§l=== VeloAuth API ===\n" +
               "    §eВерсия: §f{version}\n" +
               "    §eАвтор: §f{author}\n" +
               "    §eАвторизованных игроков: §f{authenticated}\n" +
               "  no-permission: \"§cУ вас нет прав на выполнение этой команды!\"\n" +
               "  backend-unavailable: \"§cBackend сервер недоступен! Обратитесь к администратору.\"\n";
    }
    
    private void validateConfig() {
        // Validate backend server name
        String backendServer = getBackendServer();
        if (backendServer == null || backendServer.isEmpty()) {
            plugin.getLogger().warn("Backend server name is not configured, using default: lobby");
            setDefault("backend.server-name", "lobby");
        }
        
        // Validate sync channel
        String channel = getSyncChannel();
        if (channel == null || channel.isEmpty()) {
            plugin.getLogger().warn("Sync channel is not configured, using default: veloauth:sync");
            setDefault("sync.channel", "veloauth:sync");
        }
    }
    
    @SuppressWarnings("unchecked")
    private <T> T get(String path, T defaultValue) {
        String[] keys = path.split("\\.");
        Map<String, Object> current = config;
        
        for (int i = 0; i < keys.length - 1; i++) {
            Object next = current.get(keys[i]);
            if (!(next instanceof Map)) {
                return defaultValue;
            }
            current = (Map<String, Object>) next;
        }
        
        Object value = current.get(keys[keys.length - 1]);
        if (value == null) {
            return defaultValue;
        }
        
        try {
            return (T) value;
        } catch (ClassCastException e) {
            return defaultValue;
        }
    }
    
    @SuppressWarnings("unchecked")
    private void setDefault(String path, Object value) {
        String[] keys = path.split("\\.");
        Map<String, Object> current = config;
        
        for (int i = 0; i < keys.length - 1; i++) {
            Object next = current.get(keys[i]);
            if (!(next instanceof Map)) {
                Map<String, Object> newMap = new HashMap<>();
                current.put(keys[i], newMap);
                current = newMap;
            } else {
                current = (Map<String, Object>) next;
            }
        }
        
        current.put(keys[keys.length - 1], value);
    }
    
    public String getBackendServer() {
        return get("backend.server-name", "lobby");
    }
    
    public boolean isDebugMode() {
        return get("sync.debug", false);
    }
    
    public String getSyncChannel() {
        return get("sync.channel", "veloauth:sync");
    }
    
    public String getMessage(String key) {
        return get("messages." + key, "§cMessage not found: " + key);
    }
    
    public String getMessage(String key, Map<String, String> placeholders) {
        String message = getMessage(key);
        
        for (Map.Entry<String, String> entry : placeholders.entrySet()) {
            message = message.replace("{" + entry.getKey() + "}", entry.getValue());
        }
        
        return message;
    }
    
    // DDoS Protection settings
    public boolean isDDoSProtectionEnabled() {
        return get("ddos-protection.enabled", true);
    }
    
    public int getMaxConnectionsPerSecond() {
        return get("ddos-protection.max-connections-per-second", 5);
    }
    
    public int getMaxConnectionsPerMinute() {
        return get("ddos-protection.max-connections-per-minute", 20);
    }
    
    public int getMaxAuthAttemptsPerMinute() {
        return get("ddos-protection.max-auth-attempts-per-minute", 5);
    }
    
    public int getMaxCommandsPerSecond() {
        return get("ddos-protection.max-commands-per-second", 10);
    }
    
    public int getMinReputationForConnection() {
        return get("ddos-protection.min-reputation-for-connection", 20);
    }
    
    public long getBaseBlockDuration() {
        Object value = get("ddos-protection.base-block-duration", 60000);
        if (value instanceof Integer) {
            return ((Integer) value).longValue();
        }
        return (Long) value;
    }
    
    public double getBackoffMultiplier() {
        Object value = get("ddos-protection.backoff-multiplier", 2.0);
        if (value instanceof Integer) {
            return ((Integer) value).doubleValue();
        }
        return (Double) value;
    }
}
