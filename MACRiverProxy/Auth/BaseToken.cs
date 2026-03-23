using System.Text.Json.Serialization;

namespace MACRiverProxy.Auth;

[JsonDerivedType(typeof(DebugToken), typeDiscriminator:nameof(DebugToken))]
public abstract partial class Token {}
/// <summary>
/// Debug-only token for testing. Always return true in debug and always false in release configuration.
/// </summary>
/// <remarks>Use only in debug environment!</remarks>
public class DebugToken : Token
{
    public DebugToken()
    {
        AuthPayload = ""u8.ToArray();
        MACCategory = uint.MaxValue;
        MACLevel = 255;
    }
    public override bool VerifyToken()
    {
        return
#if DEBUG
            true
#else
            false
#endif
            ;
    }
}