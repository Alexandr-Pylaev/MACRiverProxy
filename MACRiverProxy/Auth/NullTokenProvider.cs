using System.Text.Json.Serialization;

namespace MACRiverProxy.Auth;

/// <summary>
/// Fallback provider for token. Always returns false.
/// </summary>
public class NullTokenProvider : TokenProvider
{
    // ReSharper disable once StaticMemberInitializerReferesToMemberBelow
    public static NullTokenProvider Singleton = _singleton!.Value;
    private static Lazy<NullTokenProvider> _singleton = new();
    public override Token CreateToken(params dynamic[]? args) => new Token(this.TokenProviderName);

    public override bool VerifyToken(Token token)
    {
        return false;
    }
}
