using MACRiverProxy.Auth.Tokens;

namespace MACRiverProxy.Auth.Null;

/// <summary>
/// Token provider, that used when token is empty.
/// Always return false when verifying token.
/// </summary>
public class NullTokenProvider : TokenProvider
{
    public static NullTokenProvider Singleton = new ();
    /// <remarks>Same as <see cref="TokenProvider.Empty"/>, but creates as a new token</remarks>
    public override Token CreateToken(params dynamic[]? args) => new Token(this.TokenProviderName, "");

    public override bool VerifyToken(Token token)
    {
        return false;
    }

    public override bool DestroyToken(Token token)
    {
        return true;
    }
}
