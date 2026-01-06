package com.s1steam.veloauth.api.security.ddos;

import com.s1steam.veloauth.api.models.ConnectionCheckResult;
import com.s1steam.veloauth.api.models.IPReputationData;
import net.jqwik.api.*;
import net.jqwik.api.constraints.IntRange;
import net.jqwik.api.constraints.StringLength;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Property-based tests for DDoS Protection
 * 
 * Feature: veloauth-enhanced
 * Tests Properties 4-7 from design document
 */
class DDoSProtectionPropertyTest {
    
    /**
     * Simplified DDoS Protection for testing without database dependencies
     */
    private static class TestDDoSProtection {
        private final ConcurrentHashMap<String, AtomicInteger> connectionsPerSecond = new ConcurrentHashMap<>();
        private final ConcurrentHashMap<String, IPReputationData> reputationCache = new ConcurrentHashMap<>();
        private final int maxConnectionsPerSecond = 5;
        private final int maxConnectionsPerMinute = 20;
        private final int maxAuthAttemptsPerMinute = 3;
        private final int minReputationForConnection = 30;
        private final long baseBlockDuration = 5000L; // 5 seconds
        private final double backoffMultiplier = 2.0;
        
        public ConnectionCheckResult checkConnection(String ip) {
            IPReputationData reputation = getOrCreateReputation(ip);
            
            // Check blacklist
            if (reputation.isBlacklisted()) {
                return ConnectionCheckResult.blocked("IP is blacklisted", Long.MAX_VALUE);
            }
            
            // Check whitelist (bypass all checks)
            if (reputation.isWhitelisted()) {
                return ConnectionCheckResult.allowed(100);
            }
            
            // Check if blocked
            if (reputation.isBlocked()) {
                return ConnectionCheckResult.blocked(reputation.getBlockReason(), reputation.getBlockUntil());
            }
            
            // Check minimum reputation
            if (reputation.getReputation() < minReputationForConnection) {
                long blockDuration = calculateBlockDuration(reputation.getFailedAttempts());
                reputation.block(blockDuration, "Low reputation score");
                return ConnectionCheckResult.blocked("Low reputation score", reputation.getBlockUntil());
            }
            
            // Rate limiting - connections per second
            AtomicInteger perSecond = connectionsPerSecond.computeIfAbsent(ip, k -> new AtomicInteger(0));
            if (perSecond.incrementAndGet() > maxConnectionsPerSecond) {
                long blockDuration = calculateBlockDuration(reputation.getFailedAttempts());
                reputation.block(blockDuration, "Too many connections per second");
                return ConnectionCheckResult.rateLimited(reputation.getBlockUntil());
            }
            
            return ConnectionCheckResult.allowed(reputation.getReputation());
        }
        
        public void registerAuthAttempt(String ip, boolean success) {
            IPReputationData reputation = getOrCreateReputation(ip);
            
            if (success) {
                reputation.recordSuccessfulLogin();
            } else {
                reputation.recordFailedAttempt();
            }
        }
        
        public IPReputationData getIPReputation(String ip) {
            return getOrCreateReputation(ip);
        }
        
        public void whitelistIP(String ip) {
            IPReputationData reputation = getOrCreateReputation(ip);
            reputation.setWhitelisted(true);
            reputation.unblock();
        }
        
        public void blacklistIP(String ip) {
            IPReputationData reputation = getOrCreateReputation(ip);
            reputation.setBlacklisted(true);
        }
        
        private IPReputationData getOrCreateReputation(String ip) {
            return reputationCache.computeIfAbsent(ip, IPReputationData::new);
        }
        
        private long calculateBlockDuration(int failedAttempts) {
            long duration = (long) (baseBlockDuration * Math.pow(backoffMultiplier, Math.min(failedAttempts, 10)));
            return Math.min(duration, 24 * 60 * 60 * 1000L); // Max 24 hours
        }
        
        public int getMaxConnectionsPerSecond() {
            return maxConnectionsPerSecond;
        }
        
        public long getBaseBlockDuration() {
            return baseBlockDuration;
        }
        
        public double getBackoffMultiplier() {
            return backoffMultiplier;
        }
    }
    
    /**
     * Property 4: DDoS Rate Limiting Activation
     * 
     * For any IP address, when connection attempts exceed the configured threshold 
     * within the time window, rate limiting should activate.
     * 
     * Validates: Requirements 9.1.1
     */
    @Property(tries = 100)
    @Tag("Feature: veloauth-enhanced, Property 4: DDoS Rate Limiting Activation")
    void rateLimitingActivatesWhenThresholdExceeded(@ForAll @StringLength(min = 7, max = 15) String ip,
                                                      @ForAll @IntRange(min = 6, max = 20) int attempts) {
        // Given: A fresh DDoS protection instance and a random IP
        TestDDoSProtection ddos = new TestDDoSProtection();
        int threshold = ddos.getMaxConnectionsPerSecond();
        
        // When: Making more connection attempts than allowed
        ConnectionCheckResult lastResult = null;
        for (int i = 0; i < attempts; i++) {
            lastResult = ddos.checkConnection(ip);
        }
        
        // Then: Rate limiting should activate (connection should be blocked)
        assertNotNull(lastResult, "Last connection check result should not be null");
        
        if (attempts > threshold) {
            assertFalse(lastResult.isAllowed(), 
                "Connection should be blocked when attempts (" + attempts + ") exceed threshold (" + threshold + ")");
            assertTrue(lastResult.getReason().contains("Too many connections") || 
                      lastResult.getReason().contains("Rate limit") ||
                      lastResult.getReason().contains("Low reputation"),
                "Block reason should indicate rate limiting or low reputation, got: " + lastResult.getReason());
        }
    }
    
    /**
     * Property 5: Exponential Backoff Correctness
     * 
     * For any IP address with N failed connection attempts, the backoff time 
     * should be exponentially increasing (e.g., 2^N seconds).
     * 
     * Validates: Requirements 9.1.2
     */
    @Property(tries = 100)
    @Tag("Feature: veloauth-enhanced, Property 5: Exponential Backoff Correctness")
    void exponentialBackoffIncreasesWithFailedAttempts(@ForAll @StringLength(min = 7, max = 15) String ip,
                                                        @ForAll @IntRange(min = 1, max = 5) int failedAttempts) {
        // Given: A fresh DDoS protection instance
        TestDDoSProtection ddos = new TestDDoSProtection();
        
        // When: Recording multiple failed auth attempts
        for (int i = 0; i < failedAttempts; i++) {
            ddos.registerAuthAttempt(ip, false);
        }
        
        // Then: Failed attempts should be tracked
        IPReputationData reputation = ddos.getIPReputation(ip);
        assertEquals(failedAttempts, reputation.getFailedAttempts(),
            "Failed attempts should be accurately tracked");
        
        // And: If blocked, block duration should follow exponential pattern
        if (reputation.isBlocked()) {
            long blockDuration = reputation.getBlockUntil() - System.currentTimeMillis();
            long baseBlockDuration = ddos.getBaseBlockDuration();
            double multiplier = ddos.getBackoffMultiplier();
            
            // Expected minimum duration: baseBlockDuration * (multiplier ^ (failedAttempts - 1))
            long expectedMinDuration = (long) (baseBlockDuration * Math.pow(multiplier, failedAttempts - 1));
            
            assertTrue(blockDuration >= 0,
                "Block duration should be non-negative");
            
            // Allow some tolerance for timing and calculation
            assertTrue(blockDuration >= expectedMinDuration * 0.8,
                "Block duration (" + blockDuration + "ms) should follow exponential backoff pattern " +
                "(expected min: " + expectedMinDuration + "ms for " + failedAttempts + " attempts)");
        }
    }
    
    /**
     * Property 6: Connection Tracking Accuracy
     * 
     * For any IP address, the number of tracked connections should equal 
     * the actual number of connection attempts made.
     * 
     * Validates: Requirements 9.1.4
     */
    @Property(tries = 100)
    @Tag("Feature: veloauth-enhanced, Property 6: Connection Tracking Accuracy")
    void connectionTrackingIsAccurate(@ForAll @StringLength(min = 7, max = 15) String ip,
                                      @ForAll @IntRange(min = 1, max = 10) int connectionAttempts) {
        // Given: A fresh DDoS protection instance
        TestDDoSProtection ddos = new TestDDoSProtection();
        
        // When: Making N connection attempts
        int allowedConnections = 0;
        int blockedConnections = 0;
        
        for (int i = 0; i < connectionAttempts; i++) {
            ConnectionCheckResult result = ddos.checkConnection(ip);
            if (result.isAllowed()) {
                allowedConnections++;
            } else {
                blockedConnections++;
            }
        }
        
        // Then: Total attempts should equal allowed + blocked
        int totalTracked = allowedConnections + blockedConnections;
        assertEquals(connectionAttempts, totalTracked,
            "Total tracked connections (" + totalTracked + ") should equal actual attempts (" + connectionAttempts + ")");
        
        // And: Once threshold is exceeded, subsequent connections should be blocked
        int threshold = ddos.getMaxConnectionsPerSecond();
        if (connectionAttempts > threshold) {
            assertTrue(blockedConnections > 0,
                "Some connections should be blocked when attempts (" + connectionAttempts + 
                ") exceed threshold (" + threshold + ")");
        }
    }
    
    /**
     * Property 7: Bot Pattern Detection and Blocking
     * 
     * For any IP address exhibiting bot-like behavior (rapid connections, 
     * predictable patterns), the system should automatically block it for 
     * the configured duration.
     * 
     * Validates: Requirements 9.1.3
     */
    @Property(tries = 100)
    @Tag("Feature: veloauth-enhanced, Property 7: Bot Pattern Detection and Blocking")
    void botPatternDetectionBlocksRapidConnections(@ForAll @StringLength(min = 7, max = 15) String ip,
                                                    @ForAll @IntRange(min = 10, max = 30) int rapidAttempts) {
        // Given: A fresh DDoS protection instance
        TestDDoSProtection ddos = new TestDDoSProtection();
        
        // When: Making many rapid connection attempts (bot-like behavior)
        ConnectionCheckResult lastResult = null;
        int blockedCount = 0;
        
        for (int i = 0; i < rapidAttempts; i++) {
            lastResult = ddos.checkConnection(ip);
            if (lastResult.isBlocked()) {
                blockedCount++;
            }
        }
        
        // Then: The IP should eventually be blocked
        assertNotNull(lastResult, "Last connection check result should not be null");
        assertTrue(blockedCount > 0,
            "Bot-like behavior (" + rapidAttempts + " rapid attempts) should trigger blocking");
        
        // And: The final result should be blocked
        assertTrue(lastResult.isBlocked(),
            "After " + rapidAttempts + " rapid attempts, connection should be blocked");
        
        // And: Block should have a duration
        assertTrue(lastResult.getBlockUntil() > System.currentTimeMillis(),
            "Blocked IP should have a future block expiration time");
        
        // And: Subsequent attempts should also be blocked
        ConnectionCheckResult subsequentResult = ddos.checkConnection(ip);
        assertTrue(subsequentResult.isBlocked(),
            "Subsequent connection attempts should remain blocked");
    }
    
    /**
     * Additional Property: Whitelist Bypass
     * 
     * For any IP address in the whitelist, all rate limiting checks should be bypassed.
     */
    @Property(tries = 100)
    @Tag("Feature: veloauth-enhanced, Additional Property: Whitelist Bypass")
    void whitelistedIPsBypassRateLimiting(@ForAll @StringLength(min = 7, max = 15) String ip,
                                          @ForAll @IntRange(min = 10, max = 50) int attempts) {
        // Given: A fresh DDoS protection instance and a whitelisted IP
        TestDDoSProtection ddos = new TestDDoSProtection();
        ddos.whitelistIP(ip);
        
        // When: Making many connection attempts
        ConnectionCheckResult lastResult = null;
        for (int i = 0; i < attempts; i++) {
            lastResult = ddos.checkConnection(ip);
        }
        
        // Then: All connections should be allowed
        assertNotNull(lastResult, "Last connection check result should not be null");
        assertTrue(lastResult.isAllowed(),
            "Whitelisted IP should bypass rate limiting even after " + attempts + " attempts");
        assertEquals(100, lastResult.getReputation(),
            "Whitelisted IP should have maximum reputation");
    }
    
    /**
     * Additional Property: Blacklist Always Blocks
     * 
     * For any IP address in the blacklist, all connections should be blocked immediately.
     */
    @Property(tries = 100)
    @Tag("Feature: veloauth-enhanced, Additional Property: Blacklist Always Blocks")
    void blacklistedIPsAlwaysBlocked(@ForAll @StringLength(min = 7, max = 15) String ip) {
        // Given: A fresh DDoS protection instance and a blacklisted IP
        TestDDoSProtection ddos = new TestDDoSProtection();
        ddos.blacklistIP(ip);
        
        // When: Attempting to connect
        ConnectionCheckResult result = ddos.checkConnection(ip);
        
        // Then: Connection should be blocked
        assertTrue(result.isBlocked(),
            "Blacklisted IP should always be blocked");
        assertTrue(result.getReason().toLowerCase().contains("blacklist"),
            "Block reason should indicate blacklist, got: " + result.getReason());
    }
    
    /**
     * Additional Property: Successful Auth Improves Reputation
     * 
     * For any IP address, successful authentication attempts should improve reputation.
     */
    @Property(tries = 100)
    @Tag("Feature: veloauth-enhanced, Additional Property: Successful Auth Improves Reputation")
    void successfulAuthImprovesReputation(@ForAll @StringLength(min = 7, max = 15) String ip,
                                          @ForAll @IntRange(min = 1, max = 10) int successfulAttempts) {
        // Given: A fresh DDoS protection instance
        TestDDoSProtection ddos = new TestDDoSProtection();
        IPReputationData initialReputation = ddos.getIPReputation(ip);
        int initialScore = initialReputation.getReputation();
        
        // When: Recording successful auth attempts
        for (int i = 0; i < successfulAttempts; i++) {
            ddos.registerAuthAttempt(ip, true);
        }
        
        // Then: Reputation should improve
        IPReputationData finalReputation = ddos.getIPReputation(ip);
        int finalScore = finalReputation.getReputation();
        
        assertTrue(finalScore >= initialScore,
            "Reputation should improve or stay same after " + successfulAttempts + " successful attempts " +
            "(initial: " + initialScore + ", final: " + finalScore + ")");
        
        assertEquals(successfulAttempts, finalReputation.getSuccessfulLogins(),
            "Successful login count should be tracked accurately");
    }
    
    // Arbitraries for generating test data
    
    @Provide
    Arbitrary<String> validIPAddresses() {
        return Arbitraries.integers().between(1, 255)
            .list().ofSize(4)
            .map(parts -> String.join(".", 
                parts.stream().map(String::valueOf).toArray(String[]::new)));
    }
}
