package com.s1steam.veloauth.api.models;

/**
 * Результат проверки подключения через DDoS Protection
 */
public class ConnectionCheckResult {
    
    private final boolean allowed;
    private final String reason;
    private final int reputation;
    private final long blockUntil;
    
    public ConnectionCheckResult(boolean allowed, String reason, int reputation, long blockUntil) {
        this.allowed = allowed;
        this.reason = reason;
        this.reputation = reputation;
        this.blockUntil = blockUntil;
    }
    
    /**
     * Создает результат для разрешенного подключения
     */
    public static ConnectionCheckResult allowed(int reputation) {
        return new ConnectionCheckResult(true, "Connection allowed", reputation, 0);
    }
    
    /**
     * Создает результат для заблокированного подключения
     */
    public static ConnectionCheckResult blocked(String reason, long blockUntil) {
        return new ConnectionCheckResult(false, reason, 0, blockUntil);
    }
    
    /**
     * Создает результат для rate limit превышения
     */
    public static ConnectionCheckResult rateLimited(long blockUntil) {
        return new ConnectionCheckResult(false, "Rate limit exceeded", 0, blockUntil);
    }
    
    public boolean isAllowed() {
        return allowed;
    }
    
    public String getReason() {
        return reason;
    }
    
    public int getReputation() {
        return reputation;
    }
    
    public long getBlockUntil() {
        return blockUntil;
    }
    
    public boolean isBlocked() {
        return !allowed;
    }
    
    public long getBlockDuration() {
        if (blockUntil == 0) return 0;
        return Math.max(0, blockUntil - System.currentTimeMillis());
    }
}
