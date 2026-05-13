using System.Security.Cryptography;
using Microsoft.AspNetCore.Authorization;

namespace MACRiverProxy.Auth;

public static class AuthStatic
{
    public static IServiceCollection AddAuthorization(this IServiceCollection services,
        Action<AuthorizationOptions, IServiceProvider> configure) {
        services.AddOptions<AuthorizationOptions>().Configure(configure);
        return services.AddAuthorization();
    }

    const string PASSWORD_SYMBOLS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@)(_-+=/.,<>;'\"][}{#$%^&*\\|`~";
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