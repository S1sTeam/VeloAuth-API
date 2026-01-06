package com.s1steam.veloauth.api.messaging;

import com.google.common.io.ByteArrayDataInput;
import com.google.common.io.ByteStreams;
import com.s1steam.veloauth.api.VeloAuthAPI;
import com.s1steam.veloauth.api.registry.AuthRegistry;
import com.velocitypowered.api.event.Subscribe;
import com.velocitypowered.api.event.connection.PluginMessageEvent;
import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.api.proxy.ServerConnection;
import com.velocitypowered.api.proxy.messages.MinecraftChannelIdentifier;

import java.util.UUID;

/**
 * Handles plugin messaging between Velocity and backend servers
 */
public class PluginMessageHandler {
    
    private final VeloAuthAPI plugin;
    private final AuthRegistry authRegistry;
    private final MinecraftChannelIdentifier channel;
    
    public PluginMessageHandler(VeloAuthAPI plugin, AuthRegistry authRegistry) {
        this.plugin = plugin;
        this.authRegistry = authRegistry;
        
        String channelName = plugin.getConfigManager().getSyncChannel();
        this.channel = MinecraftChannelIdentifier.from(channelName);
    }
    
    /**
     * Register the plugin messaging channel
     */
    public void registerChannel() {
        plugin.getServer().getChannelRegistrar().register(channel);
        plugin.getServer().getEventManager().register(plugin, this);
        
        if (plugin.getConfigManager().isDebugMode()) {
            plugin.getLogger().info("Registered plugin messaging channel: " + channel.getId());
        }
    }
    
    /**
     * Handle incoming plugin messages
     */
    @Subscribe
    public void onPluginMessage(PluginMessageEvent event) {
        // Only handle messages from backend servers
        if (!(event.getSource() instanceof ServerConnection)) {
            return;
        }
        
        // Check if it's our channel
        if (!event.getIdentifier().equals(channel)) {
            return;
        }
        
        try {
            ByteArrayDataInput in = ByteStreams.newDataInput(event.getData());
            
            // Read message type
            String messageType = in.readUTF();
            
            if ("AUTH_STATUS".equals(messageType)) {
                handleAuthStatus(in);
            } else if (plugin.getConfigManager().isDebugMode()) {
                plugin.getLogger().warn("Unknown message type: " + messageType);
            }
            
        } catch (Exception e) {
            plugin.getLogger().error("Error handling plugin message", e);
        }
    }
    
    /**
     * Handle authentication status update from backend server
     */
    private void handleAuthStatus(ByteArrayDataInput in) {
        try {
            // Read player UUID
            String uuidString = in.readUTF();
            UUID playerId = UUID.fromString(uuidString);
            
            // Read authentication status
            boolean authenticated = in.readBoolean();
            
            // Get player IP for DDoS tracking
            plugin.getServer().getPlayer(playerId).ifPresent(player -> {
                String ip = player.getRemoteAddress().getAddress().getHostAddress();
                
                // Register auth attempt in DDoS protection
                plugin.getDDoSProtection().registerAuthAttempt(ip, authenticated);
                
                if (plugin.getConfigManager().isDebugMode()) {
                    plugin.getLogger().info("Registered auth attempt for IP " + ip + ": " + 
                        (authenticated ? "success" : "failure"));
                }
            });
            
            // Update registry
            if (authenticated) {
                authRegistry.addAuthenticatedPlayer(playerId);
                
                if (plugin.getConfigManager().isDebugMode()) {
                    plugin.getLogger().info("Player " + playerId + " authenticated");
                }
            } else {
                authRegistry.removeAuthenticatedPlayer(playerId);
                
                if (plugin.getConfigManager().isDebugMode()) {
                    plugin.getLogger().info("Player " + playerId + " logged out");
                }
            }
            
        } catch (Exception e) {
            plugin.getLogger().error("Error handling auth status message", e);
        }
    }
    
    /**
     * Get the channel identifier
     */
    public MinecraftChannelIdentifier getChannel() {
        return channel;
    }
}
