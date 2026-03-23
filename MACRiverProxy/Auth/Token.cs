using System.Security.Claims;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace MACRiverProxy.Auth;

[JsonPolymorphic(
    UnknownDerivedTypeHandling = JsonUnknownDerivedTypeHandling.FallBackToNearestAncestor, TypeDiscriminatorPropertyName = "AuthMethod")]
[JsonDerivedType(typeof(NullToken), "null")]
public abstract partial class Token(DateTime expireTime)
{
    public byte MACLevel { get; set; } = 0;
    public ulong MACCategory { get; set; }= 0;
    public byte[] AuthPayload { get; set; } = [];
    public DateTime ExpireTime { get; init; } = expireTime;

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
    public void RemoveMACCategory(byte number) => SetMACCategory(number, true);

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

    public abstract bool VerifyToken();
    public const string TOKEN_CLAIM_NAME = "Token";
}