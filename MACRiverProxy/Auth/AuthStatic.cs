using Microsoft.AspNetCore.Authorization;

namespace MACRiverProxy.Auth;

public static class AuthStatic
{
    public static IServiceCollection AddAuthorization(this IServiceCollection services,
        Action<AuthorizationOptions, IServiceProvider> configure) {
        services.AddOptions<AuthorizationOptions>().Configure<IServiceProvider>(configure);
        return services.AddAuthorization();
    }
}