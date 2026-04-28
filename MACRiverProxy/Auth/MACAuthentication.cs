using System.Net;
using System.Security.Claims;
using MACRiverProxy.Auth.Tokens;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;

namespace MACRiverProxy.Auth;

public class MACAuthentication
{
    private static Lazy<MACAuthentication> _singleton = new();
    public static MACAuthentication Singleton => _singleton.Value;

    public async Task<bool> SignIn(HttpContext context, TokenProvider provider, TokenStorage tokenStorage, DateTime expires, params dynamic[]? args)
    {
        var token = provider.CreateToken(args);
        if (token == TokenProvider.Empty)
        {
            context.Response.Redirect("/login?error=Failed%20to%20verify%20info%20you%20provided.");
            return false;
        }
        tokenStorage.RegisterToken(expires, token);
        await context.Request.HttpContext.SignInAsync(
            new ClaimsPrincipal(
                new ClaimsIdentity([token.AsClaim()], CookieAuthenticationDefaults.AuthenticationScheme)));
        return true;
    }
    public async Task SignOut(HttpContext context, TokenStorage tokenStorage, TokenProvider provider)
    {
        SignOut(context.User.FindFirst(Token.TOKEN_CLAIM_NAME).ToToken(), tokenStorage, provider);
        await context.SignOutAsync();
    }

    public void SignOut(Token token, TokenStorage tokenStorage, TokenProvider provider)
    {
        tokenStorage.RevokeToken(token);
        provider.DestroyToken(token);
    }
}