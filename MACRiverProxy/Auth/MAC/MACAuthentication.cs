using System.Security.Claims;
using MACRiverProxy.Auth.Tokens;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;

namespace MACRiverProxy.Auth.MAC;

// ReSharper disable once InconsistentNaming
/// <summary>
/// Authentication extensions for mandatory access control
/// </summary>
public static class MACAuthenticationStatic
{
    
    /// <summary>
    /// Sign in user, if data is valid.
    /// </summary>
    /// <param name="context">Request context</param>
    /// <param name="provider">Token provider, that supports form auth</param>
    /// <param name="expires">Expiration date</param>
    /// <returns>Is user sign in</returns>
    /// <exception cref="InvalidOperationException">Context does not have TokenStorage service.</exception>
    public static async Task<bool> SignIn(this HttpContext context, FormTokenProvider provider, DateTime expires)
    {
        var token = provider.CreateTokenFromForm(context.Request.Form);
        return await SignIn(context, expires, token);
    }

    /// <summary>
    /// Sign in user
    /// </summary>
    /// <param name="context">Request context</param>
    /// <param name="token">Token</param>
    /// <param name="expires">Expiration date</param>
    /// <returns>Is user sign in</returns>
    /// <exception cref="InvalidOperationException">Context does not have TokenStorage service.</exception>
    public static async Task<bool> SignIn(this HttpContext context, DateTime expires, Token token)
    {
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

    /// <summary>
    /// Sign in user, if data is valid.
    /// </summary>
    /// <param name="context">Request context</param>
    /// <param name="provider">Token provider</param>
    /// <param name="expires">Expiration date</param>
    /// <param name="args">Args for auth</param>
    /// <returns>Is user sign in</returns>
    /// <exception cref="InvalidOperationException">Context does not have TokenStorage service.</exception>
    public static async Task<bool> SignIn(this HttpContext context, TokenProvider provider, DateTime expires, params dynamic[]? args)
    {
        var token = provider.CreateToken(args);
        return await SignIn(context, expires, token);
    }
    /// <summary>
    /// Sign out user
    /// </summary>
    /// <param name="context">Request context</param>
    /// <returns>Is user successfully sign out</returns>
    /// <remarks>If token is not set up, always returns true.</remarks>
    public static async Task<bool> SignOut(this HttpContext context)
    {
        var token = context.GetUserToken();
        if (token is null) return true;
        var provider = context.RequestServices.GetTokenProvider(token);
        
        var successful = provider is null;
        
        await context.RequestServices.GetService<TokenKeyStorage>()!.RevokeToken(token);
        provider?.DestroyToken(token);
        await context.SignOutAsync();
        return successful;
    }
}