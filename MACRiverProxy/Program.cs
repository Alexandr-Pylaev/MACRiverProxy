using System.Net;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using MACRiverProxy;
using MACRiverProxy.Auth;
using MACRiverProxy.Auth.LocalAuth;
using MACRiverProxy.Auth.Tokens;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Infrastructure;
using Microsoft.EntityFrameworkCore;
using Serilog;

internal class Program
{
    private static WebApplication app;
    public static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);

        #region App builder setup   
        builder.Services.AddReverseProxy().LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"));;
        builder.Services.AddSerilog(ser =>
        {
            ser.WriteTo.Console();
        });
        builder.Services.AddSingleton<TokenStorage>();
        builder.Services.AddSingleton<MACAuthentication>();
        builder.Services.AddHttpContextAccessor();  
        builder.Services.AddLocalAuthTokenProvider();
        
        #endregion
        
        #region App builder auth setup

        builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
            .AddCookie(options =>
            {
                options.LoginPath = "/login";
                options.LogoutPath = "/logout";
                options.ExpireTimeSpan = TimeSpan.FromMinutes(30); 
            });

        builder.Services.AddAuthorization((options, sp) =>
        {
            options.AddPolicy("none", policyBuilder =>
            {
                policyBuilder.Requirements.Add(new AssertionRequirement(_ => true));
            });
            options.AddPolicy("restricted", policyBuilder =>
            {
                policyBuilder.RequireAuthenticatedUser().RequireAssertion( context =>
                {
                    var tokenStorage = sp.GetService<TokenStorage>();
                    var token = sp.GetService<IHttpContextAccessor>()!.HttpContext?.User
                        .FindFirst(Token.TOKEN_CLAIM_NAME)?
                        .ToToken();
                    return (tokenStorage?
                        .CheckToken(token)?? false) && (token?.CreateTokenProvider().VerifyToken(token)?? false) ;
                });
            });
        });

        #endregion

        app = builder.Build();
        
        app.Services.GetService<TokenStorage>()?.Database.Migrate();

        #region App auth setup
        app.MapStaticAssets().ShortCircuit();

        app.UseAuthentication();
        app.UseAuthorization();

        #endregion

        #region Login pages

        app.MapGet("/login", (context) => MACAuthentication.Singleton.SignIn(context, NullTokenProvider.Singleton, 
            context.RequestServices.GetService<TokenStorage>()!, DateTime.Now.AddMinutes(5)));
        app.MapGet("/logout", (context) => MACAuthentication.Singleton.SignOut(context, 
            context.RequestServices.GetService<TokenStorage>()!, NullTokenProvider.Singleton));
        #if DEBUG
        app.MapGet("/test/error", async (context) =>
        {
            context.Response.ThrowError(HttpStatusCode.InternalServerError);
        });
        #endif
        #endregion

        #region App setup

        app.MapReverseProxy();
        app.UseSerilogRequestLogging();

        app.Start();

        IsHttpsEnabled(app);

        #endregion

        while (!app.Lifetime.ApplicationStopping.IsCancellationRequested) { }

        void IsHttpsEnabled(WebApplication webApplication)
        {
            bool isHttpsEnabled = false;

            foreach (var url in webApplication.Urls)
            {
                if (url.ToLower().StartsWith("https://"))
                {
                    isHttpsEnabled = true;
                    break;
                }
            }

            if (!isHttpsEnabled)
            {
                Log.Error("=========================================");
                Log.Error("HTTPS is not enabled on this proxy.");
                Log.Error("This means, that all proxy traffic is transferred in plain-text."); 
                Log.Error("Please enable HTTPS for traffic encryption.");
                Log.Error("=========================================");
            }
        }

        
    }
    
    public static bool IsAppDevelopment () => app.Environment.IsDevelopment();
}