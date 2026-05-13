using System.Security.Claims;
using System.Text.Json;
using System.Text.Json.Serialization;
using MACRiverProxy.Auth.MAC;

namespace MACRiverProxy.Auth.Tokens;

public sealed class Token(string authMethod, string userIdentifier) : IMACTag
{
    public string Id { get; set; }
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

    [JsonIgnore]
    public TokenKey? TokenKey
    {
        get => _tokenKey;
        set
        {
            if (value is null) return;
            Id = value.Key;
            ExpireTime = value.ExpireTime;
            UserIdentifier = value.UserIdentifier;
            _tokenKey = value;
        }
    }

    private TokenKey? _tokenKey;

    public Claim AsClaim()
    {
        return new Claim(TOKEN_CLAIM_NAME, JsonSerializer.Serialize(this));
    }

    public const string TOKEN_CLAIM_NAME = "Token";
}

public static class TokenStatic
{
    public static Token? GetUserToken(this HttpContext context)
    {
        return context.User
            .FindFirst(Token.TOKEN_CLAIM_NAME)?
            .ToToken();
    }
    public static Token ToToken(this Claim? claim)
    {
        try
        {
            return JsonSerializer.Deserialize<Token>(claim?.Value ?? JsonSerializer.Serialize(NullTokenProvider.Singleton.CreateToken()),
                new JsonSerializerOptions()
                {
                    AllowOutOfOrderMetadataProperties = true
                })!;
        }
        catch (JsonException)
        {
            return NullTokenProvider.Singleton.CreateToken();
        }
    }
    
    public static async Task<bool> VerifyToken(this Token? token, TokenKeyStorage? tokenStorage, TokenProvider? tokenProvider) =>
        (await (tokenStorage?.CheckToken(token) ?? Task.FromResult(false))) 
        && (tokenProvider?.VerifyToken(token!) ?? false);
}