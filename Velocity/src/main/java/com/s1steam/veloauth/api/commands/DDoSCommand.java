package com.s1steam.veloauth.api.commands;

import com.s1steam.veloauth.api.VeloAuthAPI;
import com.s1steam.veloauth.api.models.IPReputationData;
import com.velocitypowered.api.command.SimpleCommand;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.serializer.legacy.LegacyComponentSerializer;

import java.util.ArrayList;
import java.util.List;

/**
 * /va ddos command for DDoS Protection management
 * Subcommands: stats, whitelist, blacklist, block, unblock
 */
public class DDoSCommand implements SimpleCommand {
    
    private final VeloAuthAPI plugin;
    private static final String PERMISSION = "velocityauth.admin.ddos";
    
    public DDoSCommand(VeloAuthAPI plugin) {
        this.plugin = plugin;
    }
    
    @Override
    public void execute(Invocation invocation) {
        String[] args = invocation.arguments();
        
        // Check permission
        if (!invocation.source().hasPermission(PERMISSION)) {
            sendMessage(invocation, "§cУ вас нет прав на выполнение этой команды!");
            return;
        }
        
        // No arguments - show usage
        if (args.length == 0) {
            showUsage(invocation);
            return;
        }
        
        String subcommand = args[0].toLowerCase();
        
        switch (subcommand) {
            case "stats":
                handleStats(invocation);
                break;
                
            case "whitelist":
                handleWhitelist(invocation, args);
                break;
                
            case "blacklist":
                handleBlacklist(invocation, args);
                break;
                
            case "block":
                handleBlock(invocation, args);
                break;
                
            case "unblock":
                handleUnblock(invocation, args);
                break;
                
            case "reputation":
            case "rep":
                handleReputation(invocation, args);
                break;
                
            default:
                sendMessage(invocation, "§cНеизвестная подкоманда: " + subcommand);
                showUsage(invocation);
                break;
        }
    }
    
    private void showUsage(Invocation invocation) {
        sendMessage(invocation, "§6§l=== DDoS Protection ===");
        sendMessage(invocation, "§e/va ddos stats §7- Статистика защиты");
        sendMessage(invocation, "§e/va ddos whitelist <add|remove|list> [ip] §7- Управление whitelist");
        sendMessage(invocation, "§e/va ddos blacklist <add|remove|list> [ip] §7- Управление blacklist");
        sendMessage(invocation, "§e/va ddos block <ip> [duration] §7- Заблокировать IP");
        sendMessage(invocation, "§e/va ddos unblock <ip> §7- Разблокировать IP");
        sendMessage(invocation, "§e/va ddos reputation <ip> §7- Проверить репутацию IP");
    }
    
    private void handleStats(Invocation invocation) {
        String stats = plugin.getDDoSProtection().getStatistics();
        sendMessage(invocation, stats);
    }
    
    private void handleWhitelist(Invocation invocation, String[] args) {
        if (args.length < 2) {
            sendMessage(invocation, "§cИспользование: /va ddos whitelist <add|remove|list> [ip]");
            return;
        }
        
        String action = args[1].toLowerCase();
        
        switch (action) {
            case "add":
                if (args.length < 3) {
                    sendMessage(invocation, "§cУкажите IP адрес!");
                    return;
                }
                plugin.getDDoSProtection().whitelistIP(args[2]);
                sendMessage(invocation, "§aIP " + args[2] + " добавлен в whitelist");
                break;
                
            case "remove":
                if (args.length < 3) {
                    sendMessage(invocation, "§cУкажите IP адрес!");
                    return;
                }
                plugin.getDDoSProtection().removeFromWhitelist(args[2]);
                sendMessage(invocation, "§aIP " + args[2] + " удален из whitelist");
                break;
                
            case "list":
                // TODO: Implement list functionality
                sendMessage(invocation, "§eСписок whitelist пока не реализован");
                break;
                
            default:
                sendMessage(invocation, "§cНеизвестное действие: " + action);
                break;
        }
    }
    
    private void handleBlacklist(Invocation invocation, String[] args) {
        if (args.length < 2) {
            sendMessage(invocation, "§cИспользование: /va ddos blacklist <add|remove|list> [ip]");
            return;
        }
        
        String action = args[1].toLowerCase();
        
        switch (action) {
            case "add":
                if (args.length < 3) {
                    sendMessage(invocation, "§cУкажите IP адрес!");
                    return;
                }
                plugin.getDDoSProtection().blacklistIP(args[2]);
                sendMessage(invocation, "§aIP " + args[2] + " добавлен в blacklist");
                break;
                
            case "remove":
                if (args.length < 3) {
                    sendMessage(invocation, "§cУкажите IP адрес!");
                    return;
                }
                plugin.getDDoSProtection().removeFromBlacklist(args[2]);
                sendMessage(invocation, "§aIP " + args[2] + " удален из blacklist");
                break;
                
            case "list":
                // TODO: Implement list functionality
                sendMessage(invocation, "§eСписок blacklist пока не реализован");
                break;
                
            default:
                sendMessage(invocation, "§cНеизвестное действие: " + action);
                break;
        }
    }
    
    private void handleBlock(Invocation invocation, String[] args) {
        if (args.length < 2) {
            sendMessage(invocation, "§cИспользование: /va ddos block <ip> [duration_ms]");
            return;
        }
        
        String ip = args[1];
        long duration = 3600000; // 1 hour by default
        
        if (args.length >= 3) {
            try {
                duration = Long.parseLong(args[2]);
            } catch (NumberFormatException e) {
                sendMessage(invocation, "§cНеверный формат длительности!");
                return;
            }
        }
        
        plugin.getDDoSProtection().blockIP(ip, duration, "Manual block by admin");
        sendMessage(invocation, "§aIP " + ip + " заблокирован на " + (duration / 1000) + " секунд");
    }
    
    private void handleUnblock(Invocation invocation, String[] args) {
        if (args.length < 2) {
            sendMessage(invocation, "§cИспользование: /va ddos unblock <ip>");
            return;
        }
        
        String ip = args[1];
        plugin.getDDoSProtection().unblockIP(ip);
        sendMessage(invocation, "§aIP " + ip + " разблокирован");
    }
    
    private void handleReputation(Invocation invocation, String[] args) {
        if (args.length < 2) {
            sendMessage(invocation, "§cИспользование: /va ddos reputation <ip>");
            return;
        }
        
        String ip = args[1];
        plugin.getDDoSProtection().getIPReputation(ip).thenAccept(reputation -> {
            if (reputation == null) {
                sendMessage(invocation, "§eIP " + ip + " не найден в базе данных");
                return;
            }
            
            sendMessage(invocation, "§6§l=== Репутация IP " + ip + " ===");
            sendMessage(invocation, "§eРепутация: §f" + reputation.getReputationScore() + "/100");
            sendMessage(invocation, "§eУспешных входов: §f" + reputation.getSuccessfulLogins());
            sendMessage(invocation, "§eНеудачных попыток: §f" + reputation.getFailedAttempts());
            sendMessage(invocation, "§eКоличество блокировок: §f" + reputation.getBlockCount());
            sendMessage(invocation, "§eWhitelist: §f" + (reputation.isWhitelisted() ? "§aДа" : "§cНет"));
            sendMessage(invocation, "§eBlacklist: §f" + (reputation.isBlacklisted() ? "§cДа" : "§aНет"));
            
            if (reputation.getBlockedUntil() > System.currentTimeMillis()) {
                long remaining = (reputation.getBlockedUntil() - System.currentTimeMillis()) / 1000;
                sendMessage(invocation, "§eЗаблокирован на: §f" + remaining + " секунд");
            }
        }).exceptionally(ex -> {
            sendMessage(invocation, "§cОшибка при получении репутации: " + ex.getMessage());
            return null;
        });
    }
    
    private void sendMessage(Invocation invocation, String message) {
        Component component = LegacyComponentSerializer.legacySection().deserialize(message);
        invocation.source().sendMessage(component);
    }
    
    @Override
    public List<String> suggest(Invocation invocation) {
        String[] args = invocation.arguments();
        List<String> suggestions = new ArrayList<>();
        
        // Check permission
        if (!invocation.source().hasPermission(PERMISSION)) {
            return suggestions;
        }
        
        // First argument - subcommands
        if (args.length == 0 || args.length == 1) {
            suggestions.add("stats");
            suggestions.add("whitelist");
            suggestions.add("blacklist");
            suggestions.add("block");
            suggestions.add("unblock");
            suggestions.add("reputation");
            
            // Filter by current input
            if (args.length == 1) {
                String input = args[0].toLowerCase();
                suggestions.removeIf(s -> !s.startsWith(input));
            }
        }
        // Second argument - actions for whitelist/blacklist
        else if (args.length == 2) {
            String subcommand = args[0].toLowerCase();
            if ("whitelist".equals(subcommand) || "blacklist".equals(subcommand)) {
                suggestions.add("add");
                suggestions.add("remove");
                suggestions.add("list");
                
                String input = args[1].toLowerCase();
                suggestions.removeIf(s -> !s.startsWith(input));
            }
        }
        
        return suggestions;
    }
    
    @Override
    public boolean hasPermission(Invocation invocation) {
        return invocation.source().hasPermission(PERMISSION);
    }
}
