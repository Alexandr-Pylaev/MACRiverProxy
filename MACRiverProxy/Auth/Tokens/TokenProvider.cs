using System.Reflection;

namespace MACRiverProxy.Auth.Tokens;

public abstract class TokenProvider
{
    public abstract Token CreateToken(params dynamic[]? args);
    public abstract bool VerifyToken(Token token);
    public abstract bool DestroyToken(Token token);
    public static Token Empty => NullTokenProvider.Singleton.CreateToken();
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
        return Activator.CreateInstance(Type.GetType(token.AuthMethod + TokenProvider.TOKEN_PROVIDER_POSTFIX), args) as TokenProvider;
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
}