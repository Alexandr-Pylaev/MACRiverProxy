using System.Security.Claims;
using System.Text.Json;
using System.Text.Json.Serialization;
using MACRiverProxy.Auth.MAC;
using Serilog;

namespace MACRiverProxy.Auth.Tokens;

public sealed class Token(string authMethod) : IMAC
{
    public string Id { get; set; }
    public DateTime ExpireTime { get; private set; }
    public byte MACLevel { get; set; }
    public ulong MACCategory { get; set; }
    public string AuthMethod { get; set; } = authMethod;
    public byte[] AuthPayload { get; set; } = [];

    [JsonIgnore]
    public TokenKey? TokenKey
    {
        get => _tokenKey;
        set
        {
            if (value is null) return;
            Id = value.Key;
            ExpireTime = value.ExpireTime;
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
        catch (JsonException _)
        {
            return NullTokenProvider.Singleton.CreateToken();
        }
    }
    
    public static bool VerifyToken(this Token? token, TokenStorage? tokenStorage, TokenProvider? tokenProvider) =>
        (tokenStorage?.CheckToken(token)?? false) 
        && (tokenProvider?.VerifyToken(token!) ?? false);
}