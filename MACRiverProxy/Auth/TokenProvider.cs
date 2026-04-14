using System.Reflection;

namespace MACRiverProxy.Auth;

public abstract class TokenProvider
{
    public abstract bool VerifyToken(Token token);
    public static Token Empty => NullTokenProvider.CreateNull();
}

public static class TokenProviderStatic
{
    public static TokenProvider CreateTokenProvider(this Token token, params object?[]? args)
    {
        return Activator.CreateInstance(Type.GetType(token.AuthMethod + "TokenProvider"), args) as TokenProvider;
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