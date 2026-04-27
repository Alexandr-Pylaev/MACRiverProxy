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
            MACLevel = findedUser.MACLevel
        };
        tokenStorage.RegisterToken(DateTime.Now.AddDays(1), token);
        return token;
    }

    public override bool VerifyToken(Token token)
    {
        return true;
    }
}

public static class LocalAuthTokenProviderStatic
{
    public static void AddLocalAuthTokenProvider(this IServiceCollection col, LocalAuthStorage? localAuthStorage = null,
        TokenStorage? tokenStorage = null,
        LocalAuthTokenProvider? authTokenProvider = null)
    {
        tokenStorage ??= new TokenStorage();
        localAuthStorage ??= new LocalAuthStorage();
        col.TryAddSingleton(tokenStorage);
        col.TryAddSingleton(localAuthStorage);
        col.TryAddSingleton(authTokenProvider ?? new LocalAuthTokenProvider(localAuthStorage, tokenStorage));
    }
}