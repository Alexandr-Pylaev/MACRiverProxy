using System.Text.Json.Serialization;

namespace MACRiverProxy.Auth;

/// <summary>
/// Fallback provider for token. Always returns false.
/// </summary>
public class NullTokenProvider : TokenProvider
{
    public const string TokenProviderName = "null";
    public override bool VerifyToken(Token token)
    {
        return false;
    }
    public static Token CreateNull() => new Token(NullTokenProvider.TokenProviderName);
}
