package com.s1steam.veloauth.api.registry;

import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Thread-safe registry for tracking authenticated players
 */
public class AuthRegistry {
    
    private final Set<UUID> authenticatedPlayers;
    
    public AuthRegistry() {
        this.authenticatedPlayers = ConcurrentHashMap.newKeySet();
    }
    
    /**
     * Add a player to the authenticated registry
     * @param playerId UUID of the player
     */
    public void addAuthenticatedPlayer(UUID playerId) {
        authenticatedPlayers.add(playerId);
    }
    
    /**
     * Remove a player from the authenticated registry
     * @param playerId UUID of the player
     */
    public void removeAuthenticatedPlayer(UUID playerId) {
        authenticatedPlayers.remove(playerId);
    }
    
    /**
     * Check if a player is authenticated
     * @param playerId UUID of the player
     * @return true if player is authenticated, false otherwise
     */
    public boolean isAuthenticated(UUID playerId) {
        return authenticatedPlayers.contains(playerId);
    }
    
    /**
     * Get the count of authenticated players
     * @return number of authenticated players
     */
    public int getAuthenticatedCount() {
        return authenticatedPlayers.size();
    }
    
    /**
     * Clear all authenticated players
     * Used during plugin shutdown
     */
    public void clear() {
        authenticatedPlayers.clear();
    }
    
    /**
     * Get all authenticated player UUIDs
     * @return set of authenticated player UUIDs
     */
    public Set<UUID> getAuthenticatedPlayers() {
        return Set.copyOf(authenticatedPlayers);
    }
}
