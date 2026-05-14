using MACRiverProxy.Auth.MAC;
using MACRiverProxy.Auth.Tokens;
using Serilog;

namespace MACRiverProxy;

public static class RouteStatic
{
    public static async Task<bool> AuthorizeTokenForRoute(this Token? token, IServiceProvider sp, string routeId)
    {
        if (token is null) return false;
        
        var tokenStorageServ = sp.GetService<TokenKeyStorage>()!;
        var configServ = sp.GetService<IConfiguration>()!;
        
        var tokenProvider = sp.GetTokenProvider(token);
        if (tokenProvider is null) return false;
        
        return await AuthorizeTokenForRoute(token, routeId, configServ, tokenStorageServ, tokenProvider);
    }
    public static async Task<bool> AuthorizeTokenForRoute(Token token, string routeId, IConfiguration config, TokenKeyStorage tokenStorage,
        TokenProvider tokenProvider)
    {
        byte macLevel;
        ulong macCategory;
        try
        {
            if (config.GetRouteConfigValue<string?>(routeId, "AuthorizationPolicy")?.ToLower() != Restricted)
                return true;

            macLevel = config.GetRouteConfigValue<byte?>(routeId, "MACLevel") ?? byte.MaxValue;
            macCategory = config.GetRouteConfigValue<ulong?>(routeId, "MACCategory") ?? ulong.MaxValue;
        }
        catch (InvalidCastException ex)
        {
            Log.Error("Failed to read config: {exMessage}", ex.Message);
            return false;
        }

        if (!(await token.VerifyToken(tokenStorage, tokenProvider)))
        {
            Log.Information($"Token [{token.TokenKey}:{token.UserIdentifier}] failed to verify.");
            return false;
        }

        if (!token.HaveLevel(macLevel))
        {
            Log.Information($"Token [{token.TokenKey}:{token.UserIdentifier}] failed MAC level check ({token.MACLevel} < {macLevel}).");
            return false;
        }

        if (!token.HaveCategories(macCategory))
        {
            Log.Information($"Token [{token.TokenKey}:{token.UserIdentifier}] failed MAC category check ({token.MACCategory} does not have {macCategory}).");
            return false;
        }

        return true;
    }
    public const string Restricted = "restricted";
    
    public static T? GetRouteConfigValue<T>(this IConfiguration configServ, string routeId, string key)
    {
        return configServ.GetValue<T?>($"ReverseProxy:Routes:{routeId}:{key}");
    }
}