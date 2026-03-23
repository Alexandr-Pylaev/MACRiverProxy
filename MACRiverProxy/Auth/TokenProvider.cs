namespace MACRiverProxy.Auth;

public abstract class TokenProvider
{
    public abstract bool VerifyToken(Token token);
    public static Token Empty => NullTokenProvider.CreateNull();
}

public static class TokenProviderStatic
{
    public static TokenProvider CreateTokenProvider(this Token token)
    {
        return Activator.CreateInstance(Type.GetType(token.AuthMethod + "TokenProvider")) as TokenProvider;
    }
}