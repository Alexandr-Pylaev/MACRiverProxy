using System.Security.Cryptography;
using System.Text;
using MACRiverProxy.Auth.Tokens;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace MACRiverProxy.Auth.LocalAuth;

public class LocalAuthTokenProvider(LocalAuthStorage localAuthStorage, TokenStorage tokenStorage) : TokenProvider
{
    public override Token CreateToken(params dynamic[]? args) => CreateTokenAsync(args?[0], args?[1]).Result;

    public async Task<Token> CreateTokenAsync(string login, string password)
    {
        if (string.IsNullOrEmpty(login))
            throw new ArgumentNullException(nameof(login));
        if (string.IsNullOrEmpty(password))
            throw new ArgumentNullException(nameof(password));

        var findedUser = await localAuthStorage.FindUser(login);
        if (!(findedUser?.VerifyPassword(password) ?? false)) return Empty;
        var token = new Token(TokenProviderName)
        {
            MACCategory = findedUser.MACCategory,
            MACLevel = findedUser.MACLevel,
            AuthPayload = Encoding.UTF8.GetBytes(findedUser.Login)
        };
        tokenStorage.RegisterToken(DateTime.Now.AddDays(1), token);
        return token;
    }

    public override bool VerifyToken(Token token)
    {
        return localAuthStorage.IsUserRegistered(Encoding.UTF8.GetString(token.AuthPayload)).Result;
    }

    public override bool DestroyToken(Token token)
    {
        return true;
    }
}

public static class LocalAuthTokenProviderStatic
{
    public static void AddLocalAuthTokenProvider(this IServiceCollection col)
    {
        col.AddTokenStorage();
        col.TryAddScoped<LocalAuthStorage>();
        col.TryAddScoped<LocalAuthTokenProvider>();
    }
    
    public static void UseLocalAuthTokenProvider(this WebApplication app)
    {
        app.UseTokenStorage();
        using var scope = app.Services.CreateScope();
        scope.ServiceProvider.GetService<LocalAuthStorage>()?.Database.Migrate();
    }
}