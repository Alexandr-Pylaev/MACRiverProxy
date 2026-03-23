using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;

namespace MACRiverProxy.Auth;

public class MACAuthentication
{
    private static Lazy<MACAuthentication> _singleton = new();
    public static MACAuthentication Singleton => _singleton.Value;

    public async Task SignIn(HttpContext context, TokenStorage tokenStorage, DateTime expires)
    {
        var token = new DebugTokenProvider().CreateToken();
        tokenStorage.RegisterToken(expires, token);
        await context.Request.HttpContext.SignInAsync(
            new ClaimsPrincipal(
                new ClaimsIdentity([token.AsClaim()], CookieAuthenticationDefaults.AuthenticationScheme)));
    }
    public async Task SignOut(HttpContext context, TokenStorage tokenStorage)
    {
        tokenStorage.RevokeToken(context.User.FindFirst(Token.TOKEN_CLAIM_NAME).ToToken());
        await context.SignOutAsync();
    }
}