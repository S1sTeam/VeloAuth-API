package com.s1steam.veloauth.api.commands;

import com.s1steam.veloauth.api.VeloAuthAPI;
import com.velocitypowered.api.command.SimpleCommand;
import com.velocitypowered.api.proxy.Player;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.serializer.legacy.LegacyComponentSerializer;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * /va command for VeloAuth API
 * Subcommands: reload, info
 */
public class VaCommand implements SimpleCommand {
    
    private final VeloAuthAPI plugin;
    private static final String PERMISSION = "velocityauth.admin";
    
    public VaCommand(VeloAuthAPI plugin) {
        this.plugin = plugin;
    }
    
    @Override
    public void execute(Invocation invocation) {
        String[] args = invocation.arguments();
        
        // Check permission - velocityauth.admin or *
        if (!invocation.source().hasPermission(PERMISSION) && !invocation.source().hasPermission("*")) {
            sendMessage(invocation, plugin.getConfigManager().getMessage("no-permission"));
            return;
        }
        
        // No arguments - show usage
        if (args.length == 0) {
            sendMessage(invocation, "§6VeloAuth API v1.0.0");
            sendMessage(invocation, "§eИспользование:");
            sendMessage(invocation, "§e/va reload §7- Перезагрузить конфигурацию");
            sendMessage(invocation, "§e/va info §7- Информация о плагине");
            sendMessage(invocation, "§e/va ddos §7- Управление DDoS защитой");
            return;
        }
        
        String subcommand = args[0].toLowerCase();
        
        switch (subcommand) {
            case "reload":
                handleReload(invocation);
                break;
                
            case "info":
                handleInfo(invocation);
                break;
                
            case "ddos":
                handleDDoS(invocation, args);
                break;
                
            default:
                sendMessage(invocation, "§cНеизвестная подкоманда: " + subcommand);
                sendMessage(invocation, "§eИспользуйте: /va reload, /va info или /va ddos");
                break;
        }
    }
    
    private void handleReload(Invocation invocation) {
        try {
            plugin.getConfigManager().loadConfig();
            sendMessage(invocation, plugin.getConfigManager().getMessage("reload"));
            plugin.getLogger().info("Configuration reloaded by " + getSourceName(invocation));
        } catch (Exception e) {
            sendMessage(invocation, "§cОшибка при перезагрузке конфигурации!");
            plugin.getLogger().error("Error reloading configuration", e);
        }
    }
    
    private void handleInfo(Invocation invocation) {
        Map<String, String> placeholders = new HashMap<>();
        placeholders.put("version", "1.0.0");
        placeholders.put("author", "S1sTeam");
        placeholders.put("authenticated", String.valueOf(plugin.getAuthRegistry().getAuthenticatedCount()));
        
        String message = plugin.getConfigManager().getMessage("info", placeholders);
        sendMessage(invocation, message);
    }
    
    private void handleDDoS(Invocation invocation, String[] args) {
        // Remove "ddos" from args and pass the rest to DDoSCommand
        String[] ddosArgs = Arrays.copyOfRange(args, 1, args.length);
        
        // Create a new DDoSCommand instance and execute
        DDoSCommand ddosCommand = new DDoSCommand(plugin);
        
        // Create a new invocation with modified arguments
        SimpleCommand.Invocation ddosInvocation = new SimpleCommand.Invocation() {
            @Override
            public String alias() {
                return invocation.alias();
            }
            
            @Override
            public String[] arguments() {
                return ddosArgs;
            }
            
            @Override
            public com.velocitypowered.api.command.CommandSource source() {
                return invocation.source();
            }
        };
        
        ddosCommand.execute(ddosInvocation);
    }
    
    private void sendMessage(Invocation invocation, String message) {
        Component component = LegacyComponentSerializer.legacySection().deserialize(message);
        invocation.source().sendMessage(component);
    }
    
    private String getSourceName(Invocation invocation) {
        if (invocation.source() instanceof Player) {
            return ((Player) invocation.source()).getUsername();
        }
        return "Console";
    }
    
    @Override
    public List<String> suggest(Invocation invocation) {
        String[] args = invocation.arguments();
        List<String> suggestions = new ArrayList<>();
        
        // Check permission
        if (!invocation.source().hasPermission(PERMISSION) && !invocation.source().hasPermission("*")) {
            return suggestions;
        }
        
        // First argument - subcommands
        if (args.length == 0 || args.length == 1) {
            suggestions.add("reload");
            suggestions.add("info");
            suggestions.add("ddos");
            
            // Filter by current input
            if (args.length == 1) {
                String input = args[0].toLowerCase();
                suggestions.removeIf(s -> !s.startsWith(input));
            }
        }
        // Second argument - ddos subcommands
        else if (args.length >= 2 && "ddos".equals(args[0].toLowerCase())) {
            // Delegate to DDoSCommand for suggestions
            DDoSCommand ddosCommand = new DDoSCommand(plugin);
            String[] ddosArgs = Arrays.copyOfRange(args, 1, args.length);
            
            SimpleCommand.Invocation ddosInvocation = new SimpleCommand.Invocation() {
                @Override
                public String alias() {
                    return invocation.alias();
                }
                
                @Override
                public String[] arguments() {
                    return ddosArgs;
                }
                
                @Override
                public com.velocitypowered.api.command.CommandSource source() {
                    return invocation.source();
                }
            };
            
            return ddosCommand.suggest(ddosInvocation);
        }
        
        return suggestions;
    }
    
    @Override
    public boolean hasPermission(Invocation invocation) {
        return invocation.source().hasPermission(PERMISSION) || invocation.source().hasPermission("*");
    }
}
