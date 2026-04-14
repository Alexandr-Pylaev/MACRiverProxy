using MACRiverProxy.Auth.Tokens;

namespace MACRiverProxy.Auth.LocalAuth;

public class LocalAuthTokenProvider : TokenProvider
{
    public override Token CreateToken(params dynamic[]? args)
    {
        throw new NotImplementedException();
    }

    public override bool VerifyToken(Token token)
    {
        throw new NotImplementedException();
    }
}