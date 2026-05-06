using System.Reflection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace MACRiverProxy.Auth.Tokens;

public abstract class TokenProvider
{
    public abstract Token CreateToken(params dynamic[]? args);
    public abstract bool VerifyToken(Token token);
    public abstract bool DestroyToken(Token token);
    public static Token Empty => _empty;
    private static Token _empty = NullTokenProvider.Singleton.CreateToken();
    protected string TokenProviderName 
    {
        get
        {
            var name = this.GetType().Name;
            return name[..(name.Contains(TOKEN_PROVIDER_POSTFIX) 
                ? name.LastIndexOf(TOKEN_PROVIDER_POSTFIX, StringComparison.InvariantCulture) 
                : name.Length)];
        }
    }

    public const string TOKEN_PROVIDER_POSTFIX = "TokenProvider";
}

public static class TokenProviderStatic
{
    public static TokenProvider CreateTokenProvider(this Token token, params object?[]? args)
    {
        return Activator.CreateInstance(token.GetTokenProviderType(), args) as TokenProvider;
    }

    public static Type? GetTokenProviderType(this Token token)
    {
        return AppDomain.CurrentDomain.GetAssemblies()
            .SelectMany(ass => ass.GetTypes()).FirstOrDefault(t => 
                t?.Name.EndsWith(token.AuthMethod + TokenProvider.TOKEN_PROVIDER_POSTFIX) ?? false, null);
    }

    public static bool TryCreateTokenProvider(this Token token, out TokenProvider? provider, params object?[]? args)
    {
        provider = null;
        try
        {
            provider = token.CreateTokenProvider(args);
            return true;
        }
        catch (Exception ex) when (ex is ArgumentNullException or TargetInvocationException 
                                       or TypeLoadException or ArgumentException 
                                       or MethodAccessException or MemberAccessException 
                                       or MissingMethodException)
        {
            return false;
        }
    }
    
    public static void AddTokenStorage(this IServiceCollection col)
    {
        col.TryAddScoped<TokenStorage>();
    }
    public static void UseTokenStorage(this WebApplication app)
    {
        var tokenStorage = app.Services.GetService<TokenStorage>();
        tokenStorage?.Database.Migrate();
        tokenStorage?.TokenStorageCleanup();
    }
}