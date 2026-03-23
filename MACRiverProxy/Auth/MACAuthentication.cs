using Microsoft.AspNetCore.Authentication;

namespace MACRiverProxy.Auth;

public class MACAuthentication
{
    private static Lazy<MACAuthentication> _singleton = new();
    public static MACAuthentication Singleton => _singleton.Value;
    public async Task SignOut(HttpContext context, TokenStorage tokenStorage)
    {
        tokenStorage.RevokeToken(context.User.FindFirst(Token.TOKEN_CLAIM_NAME).ToToken());
        await context.SignOutAsync();
    }
}