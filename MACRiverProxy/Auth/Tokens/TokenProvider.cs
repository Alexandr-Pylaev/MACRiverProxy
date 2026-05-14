using System.Reflection;

namespace MACRiverProxy.Auth.Tokens;
/// <summary>
/// Base class for all token providers
/// </summary>
public abstract class TokenProvider
{
    /// <summary>
    /// Creates new token
    /// </summary>
    /// <param name="args">Arguments for creating token</param>
    /// <returns>New token or <see cref="Empty"/></returns>
    public abstract Token CreateToken(params dynamic[]? args);
    /// <summary>
    /// Verifies if token is valid for token provider.
    /// </summary>
    public abstract bool VerifyToken(Token token);
    /// <summary>
    /// Destroys token. 
    /// </summary>
    /// <returns>Is token destroyed</returns>
    /// <remarks>Use this method even if token provider does nothing with token.</remarks>
    public abstract bool DestroyToken(Token token);
    /// <summary>
    /// Empty token. 
    /// </summary>
    public static Token Empty => _empty;
    // Just to not create new empty token every time
    private static Token _empty = new Token("Null", "");
    /// <summary>
    /// Generates token provider name for using inside token provider
    /// </summary>
    protected string TokenProviderName 
    {
        get
        { // Just strips TOKEN_PROVIDER_POSTFIX from class name if exists
            var name = this.GetType().Name;
            return name[..(name.Contains(TOKEN_PROVIDER_POSTFIX) 
                ? name.LastIndexOf(TOKEN_PROVIDER_POSTFIX, StringComparison.InvariantCulture) 
                : name.Length)];
        }
    }

    public const string TOKEN_PROVIDER_POSTFIX = "TokenProvider";
    /// <summary>
    /// Finds <see cref="Type"/> for <see cref="TokenProvider"/> by name
    /// </summary>
    /// <param name="authMethod"><see cref="TokenProvider"/> name</param>
    /// <returns>Type of <see cref="TokenProvider"/></returns>
    public static Type? GetTokenProviderType(string authMethod)
    {
        // Scans all loaded assemblies
        return AppDomain.CurrentDomain.GetAssemblies()
            // Gets all types from them
            .SelectMany(ass => ass.GetTypes()).FirstOrDefault(t => 
                // And finds type, that have name authMethod + TOKEN_PROVIDER_POSTFIX
                t?.Name.EndsWith(authMethod + TokenProvider.TOKEN_PROVIDER_POSTFIX) ?? false, null);
    }
}

public static class TokenProviderStatic
{
    /// <summary>
    /// Creates <see cref="TokenProvider"/> from token
    /// </summary>
    /// <param name="token">Token</param>
    /// <param name="args">Args</param>
    /// <returns>Newly created <see cref="TokenProvider"/></returns>
    public static TokenProvider CreateTokenProvider(this Token token, params object?[]? args)
    {
        return (Activator.CreateInstance(token.GetTokenProviderType()!, args) as TokenProvider)!;
    }

    /// <summary>
    /// Gets <see cref="Type"/> for <see cref="TokenProvider"/> from <see cref="Token"/>
    /// </summary>
    /// <param name="token">Token</param>
    /// <returns>Type of <see cref="TokenProvider"/></returns>
    public static Type? GetTokenProviderType(this Token token) => TokenProvider.GetTokenProviderType(token.AuthMethod);

    /// <summary>
    /// Tries to create <see cref="TokenProvider"/> from <see cref="Token"/>
    /// </summary>
    /// <param name="token">Token</param>
    /// <param name="provider">Result</param>
    /// <param name="args">Args</param>
    /// <returns>Is created successfully</returns>
    public static bool TryCreateTokenProvider(this Token token, out TokenProvider? provider, params object?[]? args)
    {
        provider = null;
        try
        {
            provider = token.CreateTokenProvider(args);
            return true;
        }
        // All this exception types are types from Activator.CreateInstance()
        catch (Exception ex) when (ex is ArgumentNullException or TargetInvocationException 
                                       or TypeLoadException or ArgumentException 
                                       or MethodAccessException or MemberAccessException 
                                       or MissingMethodException)
        {
            return false;
        }
    }
    
    /// <summary>
    /// Gets token provider from <see cref="IServiceProvider"/>
    /// </summary>
    /// <param name="sp">Service provider</param>
    /// <param name="token">Token</param>
    /// <returns>Token provider or null if not found</returns>
    public static TokenProvider? GetTokenProvider(this IServiceProvider sp, Token token)
    {
        var tokenProviderType = token.GetTokenProviderType();
        if (tokenProviderType is null) return null;
        return (TokenProvider?) sp.GetService(tokenProviderType);
    }
    /// <summary>
    /// Gets token provider from <see cref="IServiceProvider"/>
    /// </summary>
    /// <param name="sp">Service provider</param>
    /// <param name="authMethod">Token provider name</param>
    /// <returns>Token provider or null if not found</returns>
    public static TokenProvider? GetTokenProvider(this IServiceProvider sp, string authMethod)
    {
        var tokenProviderType = TokenProvider.GetTokenProviderType(authMethod);
        if (tokenProviderType is null) return null;
        return (TokenProvider?) sp.GetService(tokenProviderType);
    }
}