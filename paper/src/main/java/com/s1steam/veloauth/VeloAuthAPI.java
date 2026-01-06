package com.s1steam.veloauth.api;

import com.google.inject.Inject;
import com.s1steam.veloauth.api.commands.VaCommand;
import com.s1steam.veloauth.api.config.ConfigManager;
import com.s1steam.veloauth.api.registry.AuthRegistry;
import com.s1steam.veloauth.api.messaging.PluginMessageHandler;
import com.s1steam.veloauth.api.security.ddos.DDoSProtection;
import com.s1steam.veloauth.api.security.ddos.DDoSProtectionManager;
import com.velocitypowered.api.event.Subscribe;
import com.velocitypowered.api.event.proxy.ProxyInitializeEvent;
import com.velocitypowered.api.event.proxy.ProxyShutdownEvent;
import com.velocitypowered.api.plugin.Plugin;
import com.velocitypowered.api.plugin.annotation.DataDirectory;
import com.velocitypowered.api.proxy.ProxyServer;
import com.velocitypowered.api.scheduler.ScheduledTask;
import org.slf4j.Logger;

import java.nio.file.Path;
import java.util.concurrent.TimeUnit;

@Plugin(
    id = "veloauth-api",
    name = "VeloAuth API",
    version = "1.0.0",
    description = "Velocity plugin for VeloAuth authentication system",
    authors = {"S1sTeam"}
)
public class VeloAuthAPI {
    
    private final ProxyServer server;
    private final Logger logger;
    private final Path dataDirectory;
    
    private ConfigManager configManager;
    private AuthRegistry authRegistry;
    private PluginMessageHandler messageHandler;
    private DDoSProtection ddosProtection;
    private ScheduledTask cleanupTask;
    
    @Inject
    public VeloAuthAPI(ProxyServer server, Logger logger, @DataDirectory Path dataDirectory) {
        this.server = server;
        this.logger = logger;
        this.dataDirectory = dataDirectory;
    }
    
    @Subscribe
    public void onProxyInitialization(ProxyInitializeEvent event) {
        logger.info("VeloAuth API v1.0.0 by S1sTeam is initializing...");
        
        try {
            // Initialize ConfigManager
            configManager = new ConfigManager(this);
            configManager.loadConfig();
            logger.info("Configuration loaded successfully");
            
            // Initialize AuthRegistry
            authRegistry = new AuthRegistry();
            logger.info("AuthRegistry initialized");
            
            // Initialize DDoS Protection
            ddosProtection = new DDoSProtectionManager(this, authRegistry);
            logger.info("DDoS Protection initialized");
            
            // Schedule cleanup task (every hour)
            cleanupTask = server.getScheduler()
                    .buildTask(this, () -> ddosProtection.cleanup())
                    .repeat(1, TimeUnit.HOURS)
                    .schedule();
            logger.info("DDoS Protection cleanup task scheduled");
            
            // Initialize PluginMessageHandler
            messageHandler = new PluginMessageHandler(this, authRegistry);
            messageHandler.registerChannel();
            logger.info("Plugin messaging channel registered");
            
            // Register commands
            server.getCommandManager().register("va", new VaCommand(this));
            logger.info("Commands registered");
            
            logger.info("VeloAuth API successfully initialized!");
            
        } catch (Exception e) {
            logger.error("Failed to initialize VeloAuth API", e);
        }
    }
    
    @Subscribe
    public void onProxyShutdown(ProxyShutdownEvent event) {
        logger.info("VeloAuth API is shutting down...");
        
        // Cancel cleanup task
        if (cleanupTask != null) {
            cleanupTask.cancel();
        }
        
        // Clear auth registry
        if (authRegistry != null) {
            authRegistry.clear();
        }
        
        logger.info("VeloAuth API shutdown complete");
    }
    
    public ProxyServer getServer() {
        return server;
    }
    
    public Logger getLogger() {
        return logger;
    }
    
    public Path getDataDirectory() {
        return dataDirectory;
    }
    
    public ConfigManager getConfigManager() {
        return configManager;
    }
    
    public AuthRegistry getAuthRegistry() {
        return authRegistry;
    }
    
    public PluginMessageHandler getMessageHandler() {
        return messageHandler;
    }
    
    public DDoSProtection getDDoSProtection() {
        return ddosProtection;
    }
}
