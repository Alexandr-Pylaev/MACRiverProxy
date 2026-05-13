using System.Security.Claims;
using MACRiverProxy.Auth.Tokens;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;

namespace MACRiverProxy.Auth.MAC;

// ReSharper disable once InconsistentNaming
public static class MACAuthenticationStatic
{
    public static async Task<bool> SignIn(this HttpContext context, FormTokenProvider provider, DateTime expires)
    {
        var token = provider.CreateTokenFromForm(context.Request.Form);
        var tokenStorage = context.RequestServices.GetService<TokenKeyStorage>();
        if (tokenStorage is null)
        {
            throw new InvalidOperationException("Context does not have TokenStorage service.");
        }
        if (token == TokenProvider.Empty)
        {
            return false;
        }
        await tokenStorage.RegisterToken(expires, token);
        await context.SignInAsync(
            new ClaimsPrincipal(
                new ClaimsIdentity([token.AsClaim()], CookieAuthenticationDefaults.AuthenticationScheme)));
        return true;
    }
    public static async Task<bool> SignOut(this HttpContext context)
    {
        var token = context.GetUserToken();
        if (token is null) return false;
        var provider = context.RequestServices.GetTokenProvider(token);
        
        var successful = provider is null;
        
        await context.RequestServices.GetService<TokenKeyStorage>()!.RevokeToken(token);
        provider?.DestroyToken(token);
        await context.SignOutAsync();
        return successful;
    }
}