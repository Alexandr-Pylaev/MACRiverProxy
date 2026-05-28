using MACRiverProxy.Auth.MAC;
using MACRiverProxy.Auth.Tokens;
using Serilog;
using Yarp.ReverseProxy.Configuration;

namespace MACRiverProxy;
/// <summary>
/// Extension class for YARP proxy routing
/// </summary>
public static class RouteStatic
{
    /// <summary>
    /// <inheritdoc cref="AuthorizeTokenForRoute(Token, string, IConfiguration, TokenKeyStorage, TokenProvider)"/>
    /// </summary>
    /// <param name="token">Token</param>
    /// <param name="routeId">ID of route from config</param>
    /// <param name="sp">Service provider</param>
    /// <returns><inheritdoc cref="AuthorizeTokenForRoute(Token, string, IConfiguration, TokenKeyStorage, TokenProvider)"/></returns>
    public static async Task<bool> AuthorizeTokenForRoute(this Token? token, string routeId, IServiceProvider sp)
    {
        if (token is null) return false;
        
        var tokenStorageServ = sp.GetService<TokenKeyStorage>()!;
        var configServ = sp.GetService<IConfiguration>()!;
        
        var tokenProvider = sp.GetTokenProvider(token);
        if (tokenProvider is null) return false;
        
        return await AuthorizeTokenForRoute(token, routeId, configServ, tokenStorageServ, tokenProvider);
    }

    /// <summary>
    /// Authorize token against route with <see cref="Restricted"/> <see cref="RouteConfig.AuthorizationPolicy"/>
    /// </summary>
    /// <param name="token">Token</param>
    /// <param name="routeId">ID of route from config</param>
    /// <param name="config">Configuration of proxy</param>
    /// <param name="tokenStorage">Token storage</param>
    /// <param name="tokenProvider">Token provider</param>
    /// <returns>Is token authorized for this route</returns>
    public static async Task<bool> AuthorizeTokenForRoute(Token token, string routeId, IConfiguration config, TokenKeyStorage tokenStorage,
        TokenProvider tokenProvider)
    {
        byte macLevel;
        ulong macCategory;
        try
        {
            if (config.GetRouteConfigValue<string?>(routeId, "AuthorizationPolicy")?.ToLower() != Restricted)
                return true;

            macLevel = config.GetRouteConfigValue<byte?>(routeId, "MACLevel") ?? byte.MinValue;
            macCategory = config.GetRouteConfigValue<ulong?>(routeId, "MACCategory") ?? ulong.MinValue;
        }
        catch (InvalidCastException ex)
        {
            Log.Error("Failed to read config: {exMessage}", ex.Message);
            return false;
        }

        Log.Debug("Route: {routeId}: MAC Level={level}, Category={cat}", routeId, macLevel, macCategory);
        
        if (!(await token.VerifyToken(tokenStorage, tokenProvider)))
        {
            Log.Information("Token [{tokenKey}:{userId}] failed to verify.", token.TokenKey, token.UserIdentifier);
            return false;
        }

        if (!token.HaveLevel(macLevel))
        {
            Log.Information("Token [{tokenKey}:{userId}] failed MAC level check ({tokenLevel} < {macLevel}).", token.TokenKey, token.UserIdentifier, token.MACLevel, macLevel);
            return false;
        }

        if (!token.HaveCategories(macCategory))
        {
            Log.Information("Token [{tokenKey}:{userId}] failed MAC category check ({tokenCategory} does not have {macCategory}).", token.TokenKey, token.UserIdentifier, token.MACCategory, macCategory);
            return false;
        }

        return true;
    }

    public const string Restricted = "restricted";
    /// <summary>
    /// Gets config value from ReverseProxy:Routes config path
    /// </summary>
    /// <param name="configServ">Configuration</param>
    /// <param name="routeId">ID of route from config</param>
    /// <param name="key">Value key</param>
    /// <returns><typeparamref name="T"/> from config or null, when value is not found.</returns>
    /// <exception cref="InvalidOperationException">Throws when value cannot be converted to target type.</exception>
    public static T? GetRouteConfigValue<T>(this IConfiguration configServ, string routeId, string key)
    {
        return configServ.GetValue<T?>($"{Program.REVERSE_PROXY_CONFIG_NAME}:Routes:{routeId}:{key}");
    }
}