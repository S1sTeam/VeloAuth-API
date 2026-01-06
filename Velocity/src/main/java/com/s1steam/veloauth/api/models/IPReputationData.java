package com.s1steam.veloauth.api.models;

/**
 * Данные репутации IP адреса для DDoS защиты
 * Reputation score: 0-100 (0 = плохой, 100 = отличный)
 */
public class IPReputationData {
    
    private final String ip;
    private int reputation;
    private int successfulLogins;
    private int failedAttempts;
    private long lastAttempt;
    private boolean whitelisted;
    private boolean blacklisted;
    private boolean isVPN;
    private long blockUntil;
    private String blockReason;
    private String country;
    
    public IPReputationData(String ip) {
        this.ip = ip;
        this.reputation = 50; // Нейтральная репутация по умолчанию
        this.successfulLogins = 0;
        this.failedAttempts = 0;
        this.lastAttempt = 0;
        this.whitelisted = false;
        this.blacklisted = false;
        this.isVPN = false;
        this.blockUntil = 0;
        this.blockReason = null;
        this.country = null;
    }
    
    /**
     * Обновляет репутацию после успешного входа
     */
    public void recordSuccessfulLogin() {
        successfulLogins++;
        failedAttempts = Math.max(0, failedAttempts - 1); // Уменьшаем счетчик неудач
        lastAttempt = System.currentTimeMillis();
        recalculateReputation();
    }
    
    /**
     * Обновляет репутацию после неудачной попытки
     */
    public void recordFailedAttempt() {
        failedAttempts++;
        lastAttempt = System.currentTimeMillis();
        recalculateReputation();
    }
    
    /**
     * Пересчитывает reputation score на основе истории
     */
    private void recalculateReputation() {
        if (whitelisted) {
            reputation = 100;
            return;
        }
        
        if (blacklisted) {
            reputation = 0;
            return;
        }
        
        // Базовая репутация 50
        int score = 50;
        
        // Успешные входы повышают репутацию (+2 за каждый, макс +30)
        score += Math.min(30, successfulLogins * 2);
        
        // Неудачные попытки понижают репутацию (-5 за каждую, макс -40)
        score -= Math.min(40, failedAttempts * 5);
        
        // VPN понижает репутацию на 20
        if (isVPN) {
            score -= 20;
        }
        
        // Ограничиваем диапазон 0-100
        reputation = Math.max(0, Math.min(100, score));
    }
    
    /**
     * Проверяет заблокирован ли IP
     */
    public boolean isBlocked() {
        if (blockUntil == 0) return false;
        if (System.currentTimeMillis() >= blockUntil) {
            // Блокировка истекла
            blockUntil = 0;
            blockReason = null;
            return false;
        }
        return true;
    }
    
    /**
     * Блокирует IP на указанное время
     */
    public void block(long durationMs, String reason) {
        this.blockUntil = System.currentTimeMillis() + durationMs;
        this.blockReason = reason;
        this.reputation = Math.min(reputation, 20); // Понижаем репутацию при блокировке
    }
    
    /**
     * Разблокирует IP
     */
    public void unblock() {
        this.blockUntil = 0;
        this.blockReason = null;
    }
    
    // Getters and Setters
    
    public String getIp() {
        return ip;
    }
    
    public int getReputation() {
        return reputation;
    }
    
    public void setReputation(int reputation) {
        this.reputation = Math.max(0, Math.min(100, reputation));
    }
    
    public int getSuccessfulLogins() {
        return successfulLogins;
    }
    
    public void setSuccessfulLogins(int successfulLogins) {
        this.successfulLogins = successfulLogins;
    }
    
    public int getFailedAttempts() {
        return failedAttempts;
    }
    
    public void setFailedAttempts(int failedAttempts) {
        this.failedAttempts = failedAttempts;
    }
    
    public long getLastAttempt() {
        return lastAttempt;
    }
    
    public void setLastAttempt(long lastAttempt) {
        this.lastAttempt = lastAttempt;
    }
    
    public boolean isWhitelisted() {
        return whitelisted;
    }
    
    public void setWhitelisted(boolean whitelisted) {
        this.whitelisted = whitelisted;
        if (whitelisted) {
            reputation = 100;
            blacklisted = false;
        }
    }
    
    public boolean isBlacklisted() {
        return blacklisted;
    }
    
    public void setBlacklisted(boolean blacklisted) {
        this.blacklisted = blacklisted;
        if (blacklisted) {
            reputation = 0;
            whitelisted = false;
        }
    }
    
    public boolean isVPN() {
        return isVPN;
    }
    
    public void setVPN(boolean VPN) {
        isVPN = VPN;
        recalculateReputation();
    }
    
    public long getBlockUntil() {
        return blockUntil;
    }
    
    public void setBlockUntil(long blockUntil) {
        this.blockUntil = blockUntil;
    }
    
    public String getBlockReason() {
        return blockReason;
    }
    
    public void setBlockReason(String blockReason) {
        this.blockReason = blockReason;
    }
    
    public String getCountry() {
        return country;
    }
    
    public void setCountry(String country) {
        this.country = country;
    }
    
    /**
     * Alias для getReputation() для совместимости
     */
    public int getReputationScore() {
        return reputation;
    }
    
    /**
     * Возвращает количество блокировок (для статистики)
     */
    public int getBlockCount() {
        // Простая реализация - можно расширить для хранения истории
        return blockUntil > 0 ? 1 : 0;
    }
    
    /**
     * Возвращает время до разблокировки
     */
    public long getBlockedUntil() {
        return blockUntil;
    }
}
