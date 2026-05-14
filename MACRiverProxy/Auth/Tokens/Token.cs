using System.Security.Claims;
using System.Text.Json;
using System.Text.Json.Serialization;
using MACRiverProxy.Auth.MAC;

namespace MACRiverProxy.Auth.Tokens;
/// <summary>
/// Object, that used for authenticating and authorizing user.
/// </summary>
/// <param name="authMethod">Token auth method</param>
/// <param name="userIdentifier">Identifier, that can help identify
/// user for administrator</param>
public sealed class Token(string authMethod, string userIdentifier) : IMACTag
{
    /// <summary>
    /// ID of Token Key
    /// </summary>
    public string TokenKey { get; set; }
    public DateTime ExpireTime { get; private set; }
    public byte MACLevel { get; set; }
    public ulong MACCategory { get; set; }
    public string AuthMethod { get; set; } = authMethod;
    public byte[] AuthPayload { get; set; } = [];
    /// <summary>
    /// Text, that identifies user and allow user tracking
    /// </summary>
    /// <remarks>Always set this field in <see cref="TokenProvider"/> because this field is used for tracking user activity</remarks>
    public string UserIdentifier { get; set; } = userIdentifier;

    /// <summary>
    /// Token key object.
    /// </summary>
    /// <remarks>Can be null when <see cref="TokenKey"/> is not same as in <see cref="TokenKeyModel"/></remarks>
    [JsonIgnore]
    public TokenKey? TokenKeyModel
    {
        get
        {
            // Return TokenKey object only if keys are equal
            if (_tokenKey?.Key != TokenKey)
            {
                _tokenKey = null;
                return null;
            }
            return _tokenKey;
        }
        set
        {
            // Sets token key values to token
            if (value is null) return;
            TokenKey = value.Key;
            ExpireTime = value.ExpireTime;
            UserIdentifier = value.UserIdentifier;
            _tokenKey = value;
        }
    }

    private TokenKey? _tokenKey;

    /// <summary>
    /// Converts token to a <see cref="Claim"/>
    /// </summary>
    /// <returns>Claim with <see cref="TOKEN_CLAIM_NAME"/> type and token's JSON as value</returns>
    public Claim AsClaim()
    {
        return new Claim(TOKEN_CLAIM_NAME, JsonSerializer.Serialize(this));
    }

    /// <summary>
    /// Token claim type name
    /// </summary>
    public const string TOKEN_CLAIM_NAME = "Token";

    public static bool operator ==(Token a, Token b)
    {
        return a.TokenKey == b.TokenKey && a.ExpireTime == b.ExpireTime
                                        && a.MACLevel == b.MACLevel && a.MACCategory == b.MACCategory &&
                                        a.AuthMethod == b.AuthMethod && a.UserIdentifier == b.UserIdentifier &&
                                        a.AuthPayload == b.AuthPayload;
    }
    public static bool operator !=(Token a, Token b)
    {
        return a.TokenKey != b.TokenKey || a.ExpireTime != b.ExpireTime
                                        || a.MACLevel != b.MACLevel || a.MACCategory != b.MACCategory ||
                                        a.AuthMethod != b.AuthMethod || a.UserIdentifier != b.UserIdentifier ||
                                        a.AuthPayload !=  b.AuthPayload;
    }
}

public static class TokenStatic
{
    /// <summary>
    /// Gets token from <see cref="HttpContext.User"/> claims
    /// </summary>
    /// <returns>Token if claim exists or null if not</returns>
    public static Token? GetUserToken(this HttpContext context)
    {
        return context.User
            .FindFirst(Token.TOKEN_CLAIM_NAME)?
            .ToToken();
    }
    /// <summary>
    /// Converts claim to token.
    /// </summary>
    /// <param name="claim">Claim with type <see cref="Token.TOKEN_CLAIM_NAME"/></param>
    /// <returns>Deserialized token from claim value</returns>
    /// <remarks>Returns <see cref="TokenProvider.Empty"/> when claim is null or cannot be deserialized.</remarks>
    public static Token ToToken(this Claim? claim)
    {
        try
        {
            return JsonSerializer.Deserialize<Token>(claim?.Value ?? JsonSerializer.Serialize(TokenProvider.Empty), // Serializes empty if claim is null
                new JsonSerializerOptions()
                {
                    AllowOutOfOrderMetadataProperties = true
                })!;
        }
        catch (JsonException)
        {
            return TokenProvider.Empty;
        }
    }
    
    /// <summary>
    /// Verifies token against specified <see cref="TokenKeyStorage"/> and <see cref="TokenProvider"/>
    /// </summary>
    public static async Task<bool> VerifyToken(this Token? token, TokenKeyStorage? tokenStorage, TokenProvider? tokenProvider) =>
        (await (tokenStorage?.CheckToken(token) ?? Task.FromResult(false))) 
        && (tokenProvider?.VerifyToken(token!) ?? false);
}