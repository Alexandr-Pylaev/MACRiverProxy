using System.Security.Cryptography;
using Microsoft.AspNetCore.Authorization;

namespace MACRiverProxy.Auth;
/// <summary>
/// Extensions for auth
/// </summary>
public static class AuthStatic
{
    // Fix: IServiceCollection.AddAuthorization() does not have service provider
    /// <summary>
    /// Adds authorization and adds <see cref="IServiceProvider"/> to configure arguments
    /// </summary>
    /// <param name="services">Service collection</param>
    /// <param name="configure">Configure action</param>
    /// <returns><paramref name="services"/></returns>
    public static IServiceCollection AddAuthorization(this IServiceCollection services,
        Action<AuthorizationOptions, IServiceProvider> configure) {
        services.AddOptions<AuthorizationOptions>().Configure(configure);
        return services.AddAuthorization();
    }

    /// <summary>
    /// All password symbols for <see cref="GenerateRandomPassword"/>
    /// </summary>
    const string PASSWORD_SYMBOLS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@)(_-+=/.,<>;'\"][}{#$%^&*\\|`~";
    /// <summary>
    /// Generates cryptographically-safe password
    /// </summary>
    /// <param name="lenght">Password lenght</param>
    /// <returns>New password</returns>
    /// <exception cref="ArgumentException">Password lenght is lower than 8 symbols.</exception>
    public static string GenerateRandomPassword(int lenght)
    {
        if (lenght < 8) throw new ArgumentException("Password should not be less that 8 symbols.");
        char[] passSymbols = new char[lenght];
        for (int i = 0; i < lenght; i++)
        {
            passSymbols[i] = PASSWORD_SYMBOLS[RandomNumberGenerator.GetInt32(0, PASSWORD_SYMBOLS.Length)];
        }

        return new string(passSymbols);
    }
}