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
using Microsoft.Extensions.Primitives;
using Serilog;
using Yarp.ReverseProxy.Forwarder;
using Yarp.ReverseProxy.Model;

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
            ser.WriteTo.File($"./logs/{DateTime.Now:u}.log");
        });
        builder.WebHost.ConfigureKestrel(kestOpt =>
        {
            kestOpt.ListenAnyIP(80);
            if (Environment.GetEnvironmentVariable("ENABLE_HTTPS") == "1")
            {
                kestOpt.ListenAnyIP(443, lisOpt =>
                {
                    lisOpt.UseHttps("/certs/cert.pfx");
                });
            }
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
                options.AccessDeniedPath = "/denied";
            });

        builder.Services.AddAuthorization((options, sp) =>
        {
            options.AddPolicy("none", policyBuilder =>
            {
                policyBuilder.Requirements.Add(new AssertionRequirement(_ => true));
            });
            options.AddPolicy("restricted", policyBuilder =>
            {
                var tokenStorageServ = sp.GetService<TokenStorage>()!;
                var configServ = sp.GetService<IConfiguration>()!;
                var httpContextServ = sp.GetService<IHttpContextAccessor>()!;
                policyBuilder.RequireAuthenticatedUser().RequireAssertion( context =>
                {
                    var token = httpContextServ.HttpContext?.User
                        .FindFirst(Token.TOKEN_CLAIM_NAME)?
                        .ToToken();
                    if (token is null)
                    {
                        context.Fail();
                        return false;
                    }

                    var tokenProvider = GetTokenProvider(token, sp);
                    if (tokenProvider is null)
                    {
                        context.Fail();
                        return false;
                    }
                    var configRouteId = "ReverseProxy:Routes:"+httpContextServ.HttpContext?.GetEndpoint()?.Metadata.GetMetadata<RouteModel>()?.Config.RouteId;
                    var macLevel = configServ.GetValue<byte?>($"{configRouteId}:MACLevel") ?? byte.MaxValue;
                    var macCategory = configServ.GetValue<ulong?>($"{configRouteId}:MACCategory") ?? ulong.MaxValue;
                    return VerifyToken(token, tokenStorageServ, tokenProvider) 
                           && token?.MACLevel >= macLevel
                           && (token?.IsCategory((byte)macCategory) ?? false);
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

        app.MapGet("/denied",  (context =>
        {
            try
            {
                context.Request.Query.TryGetValue("ReturnURL", out var returnUrl);
                context.Response.ThrowError(HttpStatusCode.Forbidden, "Access denied.", "Proxy failed to authorize you and forbidden access to this resource. \n" +
                    $"<a href=\'/logout?ReturnURL=/login?ReturnURL={returnUrl}\'>You can re-login</a> if you using wrong account and try again.\n", "ERR_ACCESS_DENIED");
                return Task.CompletedTask;
            }
            catch (Exception exception)
            {
                return Task.FromException(exception);
            }
        }));
        app.MapGet("/login", async (context) => { context.Response.RedirectToLogin();});
        app.MapPost("/login", async (HttpContext context) =>
        {
            bool isSuccessful = false;
            try
            {
                if (!context.Request.Form.TryGetValue("passwordInput", out var pass)
                    || !context.Request.Form.TryGetValue("loginInput", out var login) 
                    || string.IsNullOrEmpty(pass) || string.IsNullOrEmpty(login)) return;
                isSuccessful = await MACAuthentication.Singleton.SignIn(context, context.RequestServices.GetService<LocalAuthTokenProvider>()!,
                    context.RequestServices.GetService<TokenStorage>()!, DateTime.Now.AddDays(1), login,pass);
            }
            finally
            {
                if (isSuccessful)
                {
                    if (context.Request.Query.TryGetValue("ReturnURL", out var returnUrl))
                    {
                        context.Response.Redirect(returnUrl);
                    }
                    else
                    {
                        context.Response.Redirect("/");
                    }
                }
            }
        });
        app.MapGet("/logout", (context) =>
        {
            if (context.Request.Query.TryGetValue("ReturnURL", out var returnUrl))
            {
                context.Response.Redirect(returnUrl);
            }
            else
            {
                context.Response.Redirect("/");
            }
            return MACAuthentication.Singleton.SignOut(context,
                context.RequestServices.GetService<TokenStorage>()!, NullTokenProvider.Singleton);
        });
        #if DEBUG
        app.MapGet("/test/error", async (context) =>
        {
            context.Response.ThrowError(HttpStatusCode.InternalServerError);
        });
        #endif
        #endregion

        #region App setup

        app.MapReverseProxy(options =>
        {
            options.Use(async (context, next) =>
            {
                await next();
                
                var errorFeature = context.GetForwarderErrorFeature(); 
                if (errorFeature is not null && errorFeature.Exception is not null)
                {
                    switch (errorFeature.Error)
                    {
                        case ForwarderError.NoAvailableDestinations:
                        case ForwarderError.RequestTimedOut:
                        case ForwarderError.Request:
                            context.Response.ThrowError(HttpStatusCode.BadGateway, "Target resource is not responding.", 
                                "Resource you trying to access is not responding.", $"ERR_{errorFeature.Error.ToString().ToUpper()}"
                            );
                            break;
                        default:
                            context.Response.ThrowError(HttpStatusCode.BadGateway,
                                "Failed to connect to target resource.",
                                "While trying to connect to target resource, error happened.\nUse error code for more info.",
                                $"ERR_{errorFeature.Error.ToString().ToUpper()}");
                            break;
                    }

                    Log.Error(errorFeature.Exception, $"[{context.TraceIdentifier}] Failed to redirect request.");
                } 
            });
        });
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

    public static TokenProvider? GetTokenProvider(Token token, IServiceProvider sp)
    {
        return (TokenProvider?) sp.GetService(token?.GetTokenProviderType());
    }

    public static bool VerifyToken(Token? token, TokenStorage? tokenStorage, TokenProvider? tokenProvider)
    {
        return (tokenStorage?.CheckToken(token)?? false) 
               && (tokenProvider?.VerifyToken(token!) ?? false);
    }

    public static bool IsAppDevelopment () => app.Environment.IsDevelopment();
}