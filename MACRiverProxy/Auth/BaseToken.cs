using System.Text.Json.Serialization;

namespace MACRiverProxy.Auth;

[JsonDerivedType(typeof(BaseToken), typeDiscriminator:"BaseToken")]
public abstract partial class Token {}
public class BaseToken : Token
{
    public BaseToken()
    {
        AuthPayload = ""u8.ToArray();
        MACCategory = uint.MaxValue;
        MACLevel = 255;
    }
    public override bool VerifyToken()
    {
        return true;
    }
}