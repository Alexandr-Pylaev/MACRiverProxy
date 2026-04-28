namespace MACRiverProxy.Auth.Tokens;

/// <summary>
/// Fallback provider for token. Always returns false.
/// </summary>
public class NullTokenProvider : TokenProvider
{
    // ReSharper disable once StaticMemberInitializerReferesToMemberBelow
    public static NullTokenProvider Singleton = new ();
    public override Token CreateToken(params dynamic[]? args) => new Token(this.TokenProviderName);

    public override bool VerifyToken(Token token)
    {
        return false;
    }

    public override bool DestroyToken(Token token)
    {
        return true;
    }
}
