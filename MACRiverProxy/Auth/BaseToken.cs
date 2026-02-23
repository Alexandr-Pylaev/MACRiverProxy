namespace MACRiverProxy.Auth;

public class BaseToken : Token
{
    public override string AuthMethod => "BaseToken";

    public BaseToken()
    {
        AuthPayload = "hello"u8.ToArray();
        MACCategory = uint.MaxValue;
        MACLevel = 255;
    }
    public override bool VerifyToken()
    {
        return true;
    }
}