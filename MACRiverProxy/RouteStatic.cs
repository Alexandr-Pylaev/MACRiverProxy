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
        
        if (configServ.GetRouteConfigValue<string?>(routeId, "AuthorizationPolicy")?.ToLower() != Restricted) return true;
        
        var macLevel = configServ.GetRouteConfigValue<byte?>(routeId, "MACLevel") ?? byte.MaxValue;
        var macCategory = configServ.GetRouteConfigValue<ulong?>(routeId, "MACCategory") ?? ulong.MaxValue;
        
        if (!(await token.VerifyToken(tokenStorageServ, tokenProvider)))
        {
            Log.Information($"Token [{token.TokenKeyId}:{token.UserIdentifier}] failed to verify.");
            return false;
        }

        if (!token.HaveLevel(macLevel))
        {
            Log.Information($"Token [{token.TokenKeyId}:{token.UserIdentifier}] failed MAC level check ({token.MACLevel} < {macLevel}).");
            return false;
        }

        if (!token.HaveCategories(macCategory))
        {
            Log.Information($"Token [{token.TokenKeyId}:{token.UserIdentifier}] failed MAC category check ({token.MACCategory} does not have {macCategory}).");
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