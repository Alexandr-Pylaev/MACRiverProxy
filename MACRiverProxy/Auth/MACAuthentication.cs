using System.Net;
using System.Security.Claims;
using MACRiverProxy.Auth.Tokens;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Serilog;

namespace MACRiverProxy.Auth;

public class MACAuthentication
{
    private static Lazy<MACAuthentication> _singleton = new();
    public static MACAuthentication Singleton => _singleton.Value;

    public async Task<bool> SignIn(HttpContext context, TokenProvider provider, DateTime expires, params dynamic[]? args)
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
    public async Task<bool> SignOut(HttpContext context)
    {
        bool successful = true;
        var token = context.GetUserToken();
        if (token is null) return false;
        var provider = Program.GetTokenProvider(token, context.RequestServices);
        
        successful = provider is null;
        
        context.RequestServices.GetService<TokenStorage>()!.RevokeToken(token);
        provider?.DestroyToken(token);
        await context.SignOutAsync();
        return successful;
    }
}