using System.Security.Claims;
using System.Text.Json;
using System.Text.Json.Serialization;

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