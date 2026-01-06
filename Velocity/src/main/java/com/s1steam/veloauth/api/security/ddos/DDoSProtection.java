package com.s1steam.veloauth.api.security.ddos;

import com.s1steam.veloauth.api.models.ConnectionCheckResult;
import com.s1steam.veloauth.api.models.IPReputationData;

import java.util.concurrent.CompletableFuture;

/**
 * Интерфейс для DDoS защиты
 * Управляет rate limiting, IP reputation и блокировками
 */
public interface DDoSProtection {
    
    /**
     * Проверяет можно ли разрешить подключение с данного IP
     * 
     * @param ip IP адрес
     * @return Результат проверки подключения
     */
    CompletableFuture<ConnectionCheckResult> checkConnection(String ip);
    
    /**
     * Регистрирует попытку авторизации
     * 
     * @param ip IP адрес
     * @param success Успешна ли попытка
     */
    CompletableFuture<Void> registerAuthAttempt(String ip, boolean success);
    
    /**
     * Проверяет лимит команд для игрока
     * 
     * @param playerName Имя игрока
     * @param command Команда
     * @return true если команда разрешена
     */
    boolean checkCommandLimit(String playerName, String command);
    
    /**
     * Получает данные репутации IP
     * 
     * @param ip IP адрес
     * @return Данные репутации или null
     */
    CompletableFuture<IPReputationData> getIPReputation(String ip);
    
    /**
     * Блокирует IP адрес
     * 
     * @param ip IP адрес
     * @param durationMs Длительность блокировки в миллисекундах
     * @param reason Причина блокировки
     */
    CompletableFuture<Void> blockIP(String ip, long durationMs, String reason);
    
    /**
     * Разблокирует IP адрес
     * 
     * @param ip IP адрес
     */
    CompletableFuture<Void> unblockIP(String ip);
    
    /**
     * Добавляет IP в whitelist
     * 
     * @param ip IP адрес
     */
    CompletableFuture<Void> whitelistIP(String ip);
    
    /**
     * Добавляет IP в blacklist
     * 
     * @param ip IP адрес
     */
    CompletableFuture<Void> blacklistIP(String ip);
    
    /**
     * Удаляет IP из whitelist
     * 
     * @param ip IP адрес
     */
    CompletableFuture<Void> removeFromWhitelist(String ip);
    
    /**
     * Удаляет IP из blacklist
     * 
     * @param ip IP адрес
     */
    CompletableFuture<Void> removeFromBlacklist(String ip);
    
    /**
     * Получает статистику DDoS защиты
     * 
     * @return Строка со статистикой
     */
    String getStatistics();
    
    /**
     * Очищает устаревшие данные из кэша
     */
    void cleanup();
}
