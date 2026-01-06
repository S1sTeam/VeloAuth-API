package com.s1steam.veloauth.api.security.ddos;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.s1steam.veloauth.api.VeloAuthAPI;
import com.s1steam.veloauth.api.models.ConnectionCheckResult;
import com.s1steam.veloauth.api.models.IPReputationData;
import com.s1steam.veloauth.api.registry.AuthRegistry;

import java.time.Duration;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Менеджер DDoS защиты
 * Реализует rate limiting, IP reputation tracking и блокировки
 */
public class DDoSProtectionManager implements DDoSProtection {
    
    private final VeloAuthAPI plugin;
    private final AuthRegistry authRegistry;
    
    // Rate Limiting Caches
    private final Cache<String, AtomicInteger> connectionsPerSecond;
    private final Cache<String, AtomicInteger> connectionsPerMinute;
    private final Cache<String, AtomicInteger> authAttemptsPerMinute;
    private final Cache<String, AtomicInteger> commandsPerSecond;
    
    // IP Reputation Cache (in-memory, синхронизируется с БД)
    private final ConcurrentHashMap<String, IPReputationData> reputationCache;
    
    // Blocked IPs Cache
    private final Cache<String, Long> blockedIPs;
    
    // Configuration
    private int maxConnectionsPerSecond;
    private int maxConnectionsPerMinute;
    private int maxAuthAttemptsPerMinute;
    private int maxCommandsPerSecond;
    private int minReputationForConnection;
    private long baseBlockDuration;
    private double backoffMultiplier;
    
    // Statistics
    private final AtomicInteger totalConnectionsBlocked;
    private final AtomicInteger totalAuthAttemptsBlocked;
    private final AtomicInteger totalCommandsBlocked;
    
    public DDoSProtectionManager(VeloAuthAPI plugin, AuthRegistry authRegistry) {
        this.plugin = plugin;
        this.authRegistry = authRegistry;
        
        // Initialize caches with Caffeine
        this.connectionsPerSecond = Caffeine.newBuilder()
                .expireAfterWrite(Duration.ofSeconds(1))
                .build();
        
        this.connectionsPerMinute = Caffeine.newBuilder()
                .expireAfterWrite(Duration.ofMinutes(1))
                .build();
        
        this.authAttemptsPerMinute = Caffeine.newBuilder()
                .expireAfterWrite(Duration.ofMinutes(1))
                .build();
        
        this.commandsPerSecond = Caffeine.newBuilder()
                .expireAfterWrite(Duration.ofSeconds(1))
                .build();
        
        this.blockedIPs = Caffeine.newBuilder()
                .expireAfterWrite(Duration.ofHours(24))
                .build();
        
        this.reputationCache = new ConcurrentHashMap<>();
        
        // Initialize statistics
        this.totalConnectionsBlocked = new AtomicInteger(0);
        this.totalAuthAttemptsBlocked = new AtomicInteger(0);
        this.totalCommandsBlocked = new AtomicInteger(0);
        
        // Load configuration
        loadConfiguration();
        
        plugin.getLogger().info("DDoS Protection Manager initialized");
    }
    
    /**
     * Загружает конфигурацию из config.yml
     */
    private void loadConfiguration() {
        this.maxConnectionsPerSecond = plugin.getConfigManager().getMaxConnectionsPerSecond();
        this.maxConnectionsPerMinute = plugin.getConfigManager().getMaxConnectionsPerMinute();
        this.maxAuthAttemptsPerMinute = plugin.getConfigManager().getMaxAuthAttemptsPerMinute();
        this.maxCommandsPerSecond = plugin.getConfigManager().getMaxCommandsPerSecond();
        this.minReputationForConnection = plugin.getConfigManager().getMinReputationForConnection();
        this.baseBlockDuration = plugin.getConfigManager().getBaseBlockDuration();
        this.backoffMultiplier = plugin.getConfigManager().getBackoffMultiplier();
        
        if (plugin.getConfigManager().isDebugMode()) {
            plugin.getLogger().info("DDoS Protection configuration loaded:");
            plugin.getLogger().info("  Max connections/sec: " + maxConnectionsPerSecond);
            plugin.getLogger().info("  Max connections/min: " + maxConnectionsPerMinute);
            plugin.getLogger().info("  Max auth attempts/min: " + maxAuthAttemptsPerMinute);
            plugin.getLogger().info("  Min reputation: " + minReputationForConnection);
        }
    }
    
    @Override
    public CompletableFuture<ConnectionCheckResult> checkConnection(String ip) {
        return CompletableFuture.supplyAsync(() -> {
            // 1. Проверка blacklist
            IPReputationData reputation = getOrCreateReputation(ip);
            if (reputation.isBlacklisted()) {
                totalConnectionsBlocked.incrementAndGet();
                return ConnectionCheckResult.blocked("IP is blacklisted", Long.MAX_VALUE);
            }
            
            // 2. Проверка whitelist (пропускаем все проверки)
            if (reputation.isWhitelisted()) {
                return ConnectionCheckResult.allowed(100);
            }
            
            // 3. Проверка активной блокировки
            if (reputation.isBlocked()) {
                totalConnectionsBlocked.incrementAndGet();
                return ConnectionCheckResult.blocked(
                    reputation.getBlockReason(),
                    reputation.getBlockUntil()
                );
            }
            
            // 4. Проверка минимальной репутации
            if (reputation.getReputation() < minReputationForConnection) {
                totalConnectionsBlocked.incrementAndGet();
                long blockDuration = calculateBlockDuration(reputation.getFailedAttempts());
                reputation.block(blockDuration, "Low reputation score");
                saveReputation(reputation);
                return ConnectionCheckResult.blocked("Low reputation score", reputation.getBlockUntil());
            }
            
            // 5. Rate limiting - connections per second
            AtomicInteger perSecond = connectionsPerSecond.get(ip, k -> new AtomicInteger(0));
            if (perSecond.incrementAndGet() > maxConnectionsPerSecond) {
                totalConnectionsBlocked.incrementAndGet();
                long blockDuration = calculateBlockDuration(reputation.getFailedAttempts());
                reputation.block(blockDuration, "Too many connections per second");
                saveReputation(reputation);
                return ConnectionCheckResult.rateLimited(reputation.getBlockUntil());
            }
            
            // 6. Rate limiting - connections per minute
            AtomicInteger perMinute = connectionsPerMinute.get(ip, k -> new AtomicInteger(0));
            if (perMinute.incrementAndGet() > maxConnectionsPerMinute) {
                totalConnectionsBlocked.incrementAndGet();
                long blockDuration = calculateBlockDuration(reputation.getFailedAttempts());
                reputation.block(blockDuration, "Too many connections per minute");
                saveReputation(reputation);
                return ConnectionCheckResult.rateLimited(reputation.getBlockUntil());
            }
            
            // Подключение разрешено
            return ConnectionCheckResult.allowed(reputation.getReputation());
        });
    }
    
    @Override
    public CompletableFuture<Void> registerAuthAttempt(String ip, boolean success) {
        return CompletableFuture.runAsync(() -> {
            IPReputationData reputation = getOrCreateReputation(ip);
            
            if (success) {
                reputation.recordSuccessfulLogin();
            } else {
                reputation.recordFailedAttempt();
                
                // Проверка rate limit на попытки авторизации
                AtomicInteger attempts = authAttemptsPerMinute.get(ip, k -> new AtomicInteger(0));
                if (attempts.incrementAndGet() > maxAuthAttemptsPerMinute) {
                    totalAuthAttemptsBlocked.incrementAndGet();
                    long blockDuration = calculateBlockDuration(reputation.getFailedAttempts());
                    reputation.block(blockDuration, "Too many failed auth attempts");
                }
            }
            
            saveReputation(reputation);
        });
    }
    
    @Override
    public boolean checkCommandLimit(String playerName, String command) {
        AtomicInteger commands = commandsPerSecond.get(playerName, k -> new AtomicInteger(0));
        if (commands.incrementAndGet() > maxCommandsPerSecond) {
            totalCommandsBlocked.incrementAndGet();
            return false;
        }
        return true;
    }
    
    @Override
    public CompletableFuture<IPReputationData> getIPReputation(String ip) {
        return CompletableFuture.supplyAsync(() -> getOrCreateReputation(ip));
    }
    
    @Override
    public CompletableFuture<Void> blockIP(String ip, long durationMs, String reason) {
        return CompletableFuture.runAsync(() -> {
            IPReputationData reputation = getOrCreateReputation(ip);
            reputation.block(durationMs, reason);
            blockedIPs.put(ip, System.currentTimeMillis() + durationMs);
            saveReputation(reputation);
            plugin.getLogger().info("Blocked IP " + ip + " for " + (durationMs / 1000) + "s: " + reason);
        });
    }
    
    @Override
    public CompletableFuture<Void> unblockIP(String ip) {
        return CompletableFuture.runAsync(() -> {
            IPReputationData reputation = reputationCache.get(ip);
            if (reputation != null) {
                reputation.unblock();
                blockedIPs.invalidate(ip);
                saveReputation(reputation);
                plugin.getLogger().info("Unblocked IP " + ip);
            }
        });
    }
    
    @Override
    public CompletableFuture<Void> whitelistIP(String ip) {
        return CompletableFuture.runAsync(() -> {
            IPReputationData reputation = getOrCreateReputation(ip);
            reputation.setWhitelisted(true);
            reputation.unblock();
            saveReputation(reputation);
            plugin.getLogger().info("Added IP " + ip + " to whitelist");
        });
    }
    
    @Override
    public CompletableFuture<Void> blacklistIP(String ip) {
        return CompletableFuture.runAsync(() -> {
            IPReputationData reputation = getOrCreateReputation(ip);
            reputation.setBlacklisted(true);
            saveReputation(reputation);
            plugin.getLogger().info("Added IP " + ip + " to blacklist");
        });
    }
    
    @Override
    public CompletableFuture<Void> removeFromWhitelist(String ip) {
        return CompletableFuture.runAsync(() -> {
            IPReputationData reputation = reputationCache.get(ip);
            if (reputation != null) {
                reputation.setWhitelisted(false);
                saveReputation(reputation);
                plugin.getLogger().info("Removed IP " + ip + " from whitelist");
            }
        });
    }
    
    @Override
    public CompletableFuture<Void> removeFromBlacklist(String ip) {
        return CompletableFuture.runAsync(() -> {
            IPReputationData reputation = reputationCache.get(ip);
            if (reputation != null) {
                reputation.setBlacklisted(false);
                saveReputation(reputation);
                plugin.getLogger().info("Removed IP " + ip + " from blacklist");
            }
        });
    }

    
    @Override
    public String getStatistics() {
        StringBuilder stats = new StringBuilder();
        stats.append("§6=== DDoS Protection Statistics ===\n");
        stats.append("§eTotal Connections Blocked: §f").append(totalConnectionsBlocked.get()).append("\n");
        stats.append("§eTotal Auth Attempts Blocked: §f").append(totalAuthAttemptsBlocked.get()).append("\n");
        stats.append("§eTotal Commands Blocked: §f").append(totalCommandsBlocked.get()).append("\n");
        stats.append("§eIPs in Cache: §f").append(reputationCache.size()).append("\n");
        stats.append("§eCurrently Blocked IPs: §f").append(blockedIPs.estimatedSize()).append("\n");
        return stats.toString();
    }
    
    @Override
    public void cleanup() {
        // Caffeine автоматически очищает устаревшие записи
        // Дополнительно очищаем reputation cache от старых записей
        long now = System.currentTimeMillis();
        long maxAge = Duration.ofDays(7).toMillis();
        
        reputationCache.entrySet().removeIf(entry -> {
            IPReputationData data = entry.getValue();
            return (now - data.getLastAttempt()) > maxAge && 
                   !data.isWhitelisted() && 
                   !data.isBlacklisted();
        });
        
        plugin.getLogger().info("DDoS Protection cleanup completed. IPs in cache: " + reputationCache.size());
    }
    
    /**
     * Получает или создает данные репутации для IP
     */
    private IPReputationData getOrCreateReputation(String ip) {
        return reputationCache.computeIfAbsent(ip, k -> {
            // TODO: Загрузка из БД через Plugin Messaging
            // На уровне Velocity нет прямого доступа к StorageManager
            // Данные репутации хранятся только в кэше
            return new IPReputationData(ip);
        });
    }
    
    /**
     * Сохраняет данные репутации в БД
     */
    private void saveReputation(IPReputationData reputation) {
        // TODO: Сохранение через Plugin Messaging
        // На уровне Velocity нет прямого доступа к StorageManager
        // Данные репутации хранятся только в кэше
    }
    
    /**
     * Вычисляет длительность блокировки с exponential backoff
     * 
     * @param failedAttempts Количество неудачных попыток
     * @return Длительность блокировки в миллисекундах
     */
    private long calculateBlockDuration(int failedAttempts) {
        // Exponential backoff: baseBlockDuration * (backoffMultiplier ^ failedAttempts)
        // Ограничиваем максимум 24 часами
        long duration = (long) (baseBlockDuration * Math.pow(backoffMultiplier, Math.min(failedAttempts, 10)));
        return Math.min(duration, Duration.ofHours(24).toMillis());
    }
    
    /**
     * Перезагружает конфигурацию
     */
    public void reloadConfiguration() {
        loadConfiguration();
        plugin.getLogger().info("DDoS Protection configuration reloaded");
    }
    
    // Getters for configuration (for testing and admin commands)
    
    public int getMaxConnectionsPerSecond() {
        return maxConnectionsPerSecond;
    }
    
    public int getMaxConnectionsPerMinute() {
        return maxConnectionsPerMinute;
    }
    
    public int getMaxAuthAttemptsPerMinute() {
        return maxAuthAttemptsPerMinute;
    }
    
    public int getMaxCommandsPerSecond() {
        return maxCommandsPerSecond;
    }
    
    public int getMinReputationForConnection() {
        return minReputationForConnection;
    }
    
    public long getBaseBlockDuration() {
        return baseBlockDuration;
    }
    
    public double getBackoffMultiplier() {
        return backoffMultiplier;
    }
}
