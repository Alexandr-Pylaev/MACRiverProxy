namespace MACRiverProxy.Auth.Tokens;

/// <summary>
/// Debug-only token provider for testing. Always return true in debug and always false in release configuration.
/// </summary>
/// <remarks>Use only in debug environment!</remarks>
public class DebugTokenProvider : TokenProvider
{
    public Token CreateToken()
    {
        return new Token(this.TokenProviderName);
    }

    public override Token CreateToken(params dynamic[]? args) => CreateToken();

    public override bool VerifyToken(Token token)
    {
        return
#if DEBUG
            true
#else
            false
#endif
            ;
    }
}