using System.Security.Claims;
using MACRiverProxy.Auth.Tokens;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;

namespace MACRiverProxy.Auth.MAC;

public static class MACAuthenticationStatic
{
    public static async Task<bool> SignIn(this HttpContext context, TokenProvider provider, DateTime expires, params dynamic[]? args)
    {
        var token = provider.CreateToken(args);
        var tokenStorage = context.RequestServices.GetService<TokenStorage>();
        if (tokenStorage is null)
        {
            throw new InvalidOperationException("Context does not have TokenStorage service.");
        }
        if (token == TokenProvider.Empty)
        {
            return false;
        }
        tokenStorage.RegisterToken(expires, token);
        await context.SignInAsync(
            new ClaimsPrincipal(
                new ClaimsIdentity([token.AsClaim()], CookieAuthenticationDefaults.AuthenticationScheme)));
        return true;
    }
    public static async Task<bool> SignOut(this HttpContext context)
    {
        bool successful = true;
        var token = context.GetUserToken();
        if (token is null) return false;
        var provider = context.RequestServices.GetTokenProvider(token);
        
        successful = provider is null;
        
        context.RequestServices.GetService<TokenStorage>()!.RevokeToken(token);
        provider?.DestroyToken(token);
        await context.SignOutAsync();
        return successful;
    }
}