using MACRiverProxy.Auth.Tokens;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace MACRiverProxy.Auth.LocalAuth;
/// <summary>
/// Local auth token provider, that uses local database for user management.
/// </summary>
/// <param name="localAuthStorage">Local user storage</param>
/// <param name="tokenStorage">Token storage</param>
public class LocalAuthTokenProvider(LocalAuthStorage localAuthStorage, TokenKeyStorage tokenStorage) : FormTokenProvider
{
    /// <summary>
    /// Creates new token from login and password
    /// </summary>
    /// <param name="args">[0] - login, [1] - password</param>
    /// <returns>Token or <see cref="TokenProvider.Empty"/> is data is incorrect.</returns>
    /// <exception cref="ArgumentNullException">Args empty on null</exception>
    /// <remarks>Please, use <see cref="CreateTokenAsync"/> instead, this method is used for <see cref="TokenProvider.CreateToken"/> impl.</remarks>
    public override Token CreateToken(params dynamic[]? args) => CreateTokenAsync(args?[0], args?[1]).Result;
    /// <summary>
    /// Creates new token from login and password
    /// </summary>
    /// <param name="login">Login</param>
    /// <param name="password">Password</param>
    /// <returns>Token or <see cref="TokenProvider.Empty"/> is data is incorrect.</returns>
    /// <exception cref="ArgumentNullException">Args empty on null</exception>
    public async Task<Token> CreateTokenAsync(string login, string password)
    {
        if (string.IsNullOrEmpty(login))
            throw new ArgumentNullException(nameof(login));
        if (string.IsNullOrEmpty(password))
            throw new ArgumentNullException(nameof(password));

        var findedUser = await localAuthStorage.FindUser(login);
        if (!(findedUser?.VerifyPassword(password) ?? false)) return Empty;
        var token = new Token(TokenProviderName, findedUser.Login)
        {
            MACCategory = findedUser.MACCategory,
            MACLevel = findedUser.MACLevel
        };
        await tokenStorage.RegisterToken(DateTime.Now.Add(Program.TokenLifeSpan), token);
        return token;
    }
    /// <summary>
    /// Checks if user is registered.
    /// </summary>
    public override bool VerifyToken(Token token)
    {
        return localAuthStorage.IsUserRegistered(token.UserIdentifier).Result;
    }

    public override bool DestroyToken(Token token)
    {
        return true;
    }

    /// <summary>
    /// <inheritdoc/>
    /// </summary>
    /// <param name="form">Form from <see cref="HttpRequest.Form"/> or any other forms,
    /// that contains <see cref="PASSWORD_INPUT_FORM_NAME"/> and <see cref="LOGIN_INPUT_FORM_NAME"/> fields.</param>
    /// <returns><inheritdoc/></returns>
    public override Token CreateTokenFromForm(IFormCollection form)
    {
        if (!form.TryGetValue(PASSWORD_INPUT_FORM_NAME, out var pass)
            || !form.TryGetValue(LOGIN_INPUT_FORM_NAME, out var login)
            || string.IsNullOrEmpty(pass) || string.IsNullOrEmpty(login))
        {
            return Empty;
        }

        return CreateToken(login, pass);
    }
    
    const string PASSWORD_INPUT_FORM_NAME = "passwordInput";
    const string LOGIN_INPUT_FORM_NAME = "loginInput";
}
/// <summary>
/// Extension methods for adding <see cref="LocalAuthTokenProvider"/>
/// </summary>
public static class LocalAuthTokenProviderStatic
{
    /// <summary>
    /// Adds <see cref="LocalAuthTokenProvider"/> to <see cref="IServiceCollection"/>
    /// </summary>
    /// <param name="col">Service collection</param>
    public static void AddLocalAuthTokenProvider(this IServiceCollection col)
    {
        col.AddTokenKeyStorage();
        col.TryAddScoped<LocalAuthStorage>();
        col.TryAddScoped<LocalAuthTokenProvider>();
    }
    /// <summary>
    /// Activates <see cref="LocalAuthTokenProvider"/> for <see cref="WebApplication"/>
    /// </summary>
    /// <param name="app">Application</param>
    public static void UseLocalAuthTokenProvider(this WebApplication app)
    {
        app.UseTokenStorage();
        using var scope = app.Services.CreateScope(); // Migrates db for LocalAuthStorage
        scope.ServiceProvider.GetService<LocalAuthStorage>()?.Database.Migrate();
    }
}