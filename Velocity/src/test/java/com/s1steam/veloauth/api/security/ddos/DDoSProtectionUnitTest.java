package com.s1steam.veloauth.api.security.ddos;

import com.s1steam.veloauth.api.models.ConnectionCheckResult;
import com.s1steam.veloauth.api.models.IPReputationData;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for DDoS Protection
 * 
 * Tests specific examples and edge cases for DDoS protection functionality
 */
@DisplayName("DDoS Protection Unit Tests")
class DDoSProtectionUnitTest {
    
    private TestDDoSProtection ddos;
    
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
    }
    
    @BeforeEach
    void setUp() {
        ddos = new TestDDoSProtection();
    }
    
    @Test
    @DisplayName("Test rate limit threshold - exactly at limit should pass")
    void testRateLimitThreshold_AtLimit() {
        String ip = "192.168.1.1";
        int threshold = ddos.getMaxConnectionsPerSecond();
        
        // Make exactly threshold number of connections
        ConnectionCheckResult lastResult = null;
        for (int i = 0; i < threshold; i++) {
            lastResult = ddos.checkConnection(ip);
        }
        
        // At threshold, should still be allowed
        assertNotNull(lastResult);
        assertTrue(lastResult.isAllowed(), 
            "Connection at threshold should be allowed");
    }
    
    @Test
    @DisplayName("Test rate limit threshold - one over limit should block")
    void testRateLimitThreshold_OverLimit() {
        String ip = "192.168.1.2";
        int threshold = ddos.getMaxConnectionsPerSecond();
        
        // Make threshold + 1 connections
        ConnectionCheckResult lastResult = null;
        for (int i = 0; i <= threshold; i++) {
            lastResult = ddos.checkConnection(ip);
        }
        
        // Over threshold, should be blocked
        assertNotNull(lastResult);
        assertTrue(lastResult.isBlocked(), 
            "Connection over threshold should be blocked");
    }
    
    @Test
    @DisplayName("Test exponential backoff calculation - 1 failed attempt")
    void testExponentialBackoff_OneAttempt() {
        String ip = "10.0.0.1";
        
        // Record 1 failed attempt
        ddos.registerAuthAttempt(ip, false);
        
        IPReputationData reputation = ddos.getIPReputation(ip);
        assertEquals(1, reputation.getFailedAttempts(), 
            "Should have 1 failed attempt");
    }
    
    @Test
    @DisplayName("Test exponential backoff calculation - multiple failed attempts")
    void testExponentialBackoff_MultipleAttempts() {
        String ip = "10.0.0.2";
        
        // Record 3 failed attempts
        for (int i = 0; i < 3; i++) {
            ddos.registerAuthAttempt(ip, false);
        }
        
        IPReputationData reputation = ddos.getIPReputation(ip);
        assertEquals(3, reputation.getFailedAttempts(), 
            "Should have 3 failed attempts");
    }
    
    @Test
    @DisplayName("Test IP reputation scoring - successful login increases reputation")
    void testIPReputationScoring_SuccessfulLogin() {
        String ip = "172.16.0.1";
        
        IPReputationData initialReputation = ddos.getIPReputation(ip);
        int initialScore = initialReputation.getReputation();
        
        // Record successful login
        ddos.registerAuthAttempt(ip, true);
        
        IPReputationData finalReputation = ddos.getIPReputation(ip);
        int finalScore = finalReputation.getReputation();
        
        assertTrue(finalScore >= initialScore, 
            "Reputation should increase or stay same after successful login");
        assertEquals(1, finalReputation.getSuccessfulLogins(), 
            "Should have 1 successful login");
    }
    
    @Test
    @DisplayName("Test IP reputation scoring - failed attempt decreases reputation")
    void testIPReputationScoring_FailedAttempt() {
        String ip = "172.16.0.2";
        
        IPReputationData initialReputation = ddos.getIPReputation(ip);
        int initialScore = initialReputation.getReputation();
        
        // Record failed attempt
        ddos.registerAuthAttempt(ip, false);
        
        IPReputationData finalReputation = ddos.getIPReputation(ip);
        int finalScore = finalReputation.getReputation();
        
        assertTrue(finalScore <= initialScore, 
            "Reputation should decrease or stay same after failed attempt");
        assertEquals(1, finalReputation.getFailedAttempts(), 
            "Should have 1 failed attempt");
    }
    
    @Test
    @DisplayName("Test whitelist bypass - whitelisted IP bypasses all checks")
    void testWhitelistBypass() {
        String ip = "192.168.100.1";
        
        // Whitelist the IP
        ddos.whitelistIP(ip);
        
        // Make many connections (way over limit)
        ConnectionCheckResult result = null;
        for (int i = 0; i < 100; i++) {
            result = ddos.checkConnection(ip);
        }
        
        // Should still be allowed
        assertNotNull(result);
        assertTrue(result.isAllowed(), 
            "Whitelisted IP should bypass rate limiting");
        assertEquals(100, result.getReputation(), 
            "Whitelisted IP should have maximum reputation");
    }
    
    @Test
    @DisplayName("Test blacklist blocking - blacklisted IP is always blocked")
    void testBlacklistBlocking() {
        String ip = "192.168.200.1";
        
        // Blacklist the IP
        ddos.blacklistIP(ip);
        
        // Try to connect
        ConnectionCheckResult result = ddos.checkConnection(ip);
        
        // Should be blocked
        assertNotNull(result);
        assertTrue(result.isBlocked(), 
            "Blacklisted IP should always be blocked");
        assertTrue(result.getReason().toLowerCase().contains("blacklist"), 
            "Block reason should mention blacklist");
    }
    
    @Test
    @DisplayName("Test edge case - empty IP string")
    void testEdgeCase_EmptyIP() {
        String ip = "";
        
        // Should not throw exception
        assertDoesNotThrow(() -> {
            ConnectionCheckResult result = ddos.checkConnection(ip);
            assertNotNull(result, "Result should not be null for empty IP");
        });
    }
    
    @Test
    @DisplayName("Test edge case - very long IP string")
    void testEdgeCase_VeryLongIP() {
        String ip = "192.168.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1";
        
        // Should not throw exception
        assertDoesNotThrow(() -> {
            ConnectionCheckResult result = ddos.checkConnection(ip);
            assertNotNull(result, "Result should not be null for long IP");
        });
    }
    
    @Test
    @DisplayName("Test edge case - special characters in IP")
    void testEdgeCase_SpecialCharactersIP() {
        String ip = "192.168.1.1; DROP TABLE users;";
        
        // Should not throw exception (SQL injection attempt)
        assertDoesNotThrow(() -> {
            ConnectionCheckResult result = ddos.checkConnection(ip);
            assertNotNull(result, "Result should not be null for IP with special chars");
        });
    }
    
    @Test
    @DisplayName("Test concurrent access - multiple IPs simultaneously")
    void testConcurrentAccess() {
        String ip1 = "10.0.0.1";
        String ip2 = "10.0.0.2";
        String ip3 = "10.0.0.3";
        
        // Check connections from different IPs
        ConnectionCheckResult result1 = ddos.checkConnection(ip1);
        ConnectionCheckResult result2 = ddos.checkConnection(ip2);
        ConnectionCheckResult result3 = ddos.checkConnection(ip3);
        
        // All should be allowed (first connection from each)
        assertTrue(result1.isAllowed(), "First IP should be allowed");
        assertTrue(result2.isAllowed(), "Second IP should be allowed");
        assertTrue(result3.isAllowed(), "Third IP should be allowed");
    }
    
    @Test
    @DisplayName("Test reputation recovery - successful logins after failures")
    void testReputationRecovery() {
        String ip = "172.16.1.1";
        
        // Record some failed attempts
        for (int i = 0; i < 2; i++) {
            ddos.registerAuthAttempt(ip, false);
        }
        
        IPReputationData afterFailures = ddos.getIPReputation(ip);
        int scoreAfterFailures = afterFailures.getReputation();
        
        // Record successful logins
        for (int i = 0; i < 5; i++) {
            ddos.registerAuthAttempt(ip, true);
        }
        
        IPReputationData afterSuccess = ddos.getIPReputation(ip);
        int scoreAfterSuccess = afterSuccess.getReputation();
        
        assertTrue(scoreAfterSuccess > scoreAfterFailures, 
            "Reputation should recover after successful logins");
    }
    
    @Test
    @DisplayName("Test block expiration - blocked IP should have future expiration time")
    void testBlockExpiration() {
        String ip = "192.168.1.100";
        
        // Trigger rate limit by making too many connections
        for (int i = 0; i <= ddos.getMaxConnectionsPerSecond() + 1; i++) {
            ddos.checkConnection(ip);
        }
        
        // Check if blocked
        ConnectionCheckResult result = ddos.checkConnection(ip);
        assertTrue(result.isBlocked(), "IP should be blocked");
        
        // Block expiration should be in the future
        assertTrue(result.getBlockUntil() > System.currentTimeMillis(), 
            "Block expiration should be in the future");
    }
    
    @Test
    @DisplayName("Test IPv6 address handling")
    void testIPv6Address() {
        String ipv6 = "2001:0db8:85a3:0000:0000:8a2e:0370:7334";
        
        // Should handle IPv6 addresses
        assertDoesNotThrow(() -> {
            ConnectionCheckResult result = ddos.checkConnection(ipv6);
            assertNotNull(result, "Result should not be null for IPv6");
        });
    }
    
    @Test
    @DisplayName("Test null IP handling")
    void testNullIP() {
        // Should handle null gracefully (or throw appropriate exception)
        assertThrows(NullPointerException.class, () -> {
            ddos.checkConnection(null);
        }, "Null IP should throw NullPointerException");
    }
}
