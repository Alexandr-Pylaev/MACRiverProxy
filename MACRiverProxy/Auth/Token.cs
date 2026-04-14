using System.Security.Claims;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace MACRiverProxy.Auth;

public sealed class Token(string authMethod)
{
    public string Id { get; private set; }
    public DateTime ExpireTime { get; private set; }
    public string AuthMethod { get; set; } = authMethod;
    public byte MACLevel { get; set; } = 0;
    public ulong MACCategory { get; set; }= 0;
    public byte[] AuthPayload { get; set; } = [];

    [JsonIgnore]
    public TokenKey? TokenKey
    {
        get => _tokenKey;
        set
        {
            Id = value.Key;
            ExpireTime = value.ExpireTime;
            _tokenKey = value;
        }
    }

    private TokenKey? _tokenKey;

    public void SetMACCategory(byte number, bool state)
    {
        if (number > 64) throw new ArgumentOutOfRangeException(nameof(number), "Maximum category number is 64.");

        if (state)
        {
            MACCategory |= 1ul << number;
        }
        else
        {
            MACCategory &= ~(1ul << number);
        }
    }

    public void AddMACCategory(byte number) => SetMACCategory(number, true);
    public void RemoveMACCategory(byte number) => SetMACCategory(number, false);

    public void AddMACLevel(byte level)
    {
        if (MACLevel < level) MACLevel = level;
    }

    public void RemoveMACLevel(byte level)
    {
        if (MACLevel > level) MACLevel = level;
    }

    public Claim AsClaim()
    {
        return new Claim(TOKEN_CLAIM_NAME, JsonSerializer.Serialize(this));
    }

    public const string TOKEN_CLAIM_NAME = "Token";
}