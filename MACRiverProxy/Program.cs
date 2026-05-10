using System.Net;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using MACRiverProxy;
using MACRiverProxy.Auth;
using MACRiverProxy.Auth.LocalAuth;
using MACRiverProxy.Auth.MAC;
using MACRiverProxy.Auth.Tokens;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Infrastructure;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Primitives;
using Serilog;
using Yarp.ReverseProxy.Forwarder;
using Yarp.ReverseProxy.Model;

internal class Program
{
    private static WebApplication app;
    public static TimeSpan TokenLifeSpan;
    public static void Main(string[] args)
    {
        Log.Logger = new LoggerConfiguration()
            .WriteTo.Console()
            .WriteTo.File($"./logs/{DateTime.Now:yyyy-mm-dd hh:mm:ss}.log")
            .CreateLogger();
        if (args.Length > 0)
        {
            string command = args[0];
            switch (command)
            {
                case "user":
                    if (args.Length >= 3)
                    {
                        string userCommand = args[1];
                        string username = args[2];
                        var storage = new LocalAuthStorage();
                        var user = storage.FindUser(username).Result;
                        switch (userCommand)
                        {
                            case "set":
                            case "delete":
                            {
                                if (user is null)
                                {
                                    Console.WriteLine("User not found.");
                                    return;
                                }
                                break;
                            }
                        }
                        switch (userCommand)
                        {
                            case "add":
                                if (args.Length == 4)
                                {
                                    string pass = args[3];
                                    if (pass.Length < 8)
                                    {
                                        Console.WriteLine("Password is too short.");
                                        return;
                                    }
                                    storage.RegisterUser(username, pass).Wait();
                                    Console.WriteLine($"User {username} was added.");
                                }
                                else if (args.Length > 4)
                                {
                                    Console.WriteLine("Too many arguments. Use help for more info.");
                                    return;
                                }
                                else
                                {
                                    Console.WriteLine("Not enough arguments. Use help for more info.");
                                    return;
                                }
                                break;
                            case "set": 
                                if (args.Length > 4)
                                {
                                    string setType = args[3];
                                    switch (setType)
                                    {
                                        case "mac":
                                            if (args.Length > 6)
                                            {
                                                Console.WriteLine("Too many arguments. Use help for more info.");
                                                return;
                                            }
                                            else if (args.Length >= 5)
                                            {
                                                string levelRaw = args[4];
                                                string catRaw = $"{user!.MACCategory}";
                                                if (args.Length == 6)
                                                {
                                                    catRaw = args[5];
                                                }
                                                if (!byte.TryParse(levelRaw, out var level) || !ulong.TryParse(catRaw, out var category))
                                                {
                                                    Console.WriteLine("Invalid arguments.");
                                                    return;
                                                }
                                                user!.MACLevel = level;
                                                user!.MACCategory = category;
                                                storage.SaveChanges();
                                                Console.WriteLine($"MAC for {username} was changed. \n" +
                                                                  $"Be aware, that updated MAC will work only after proxy restart and user re-login.");
                                            }
                                            else
                                            {
                                                Console.WriteLine("Not enough arguments. Use help for more info.");
                                                return;
                                            }
                                            break;
                                        case "pass":
                                                if (args.Length == 5)
                                                {
                                                    string pass = args[4];
                                                    if (pass.Length < 8)
                                                    {
                                                        Console.WriteLine("Password is too short.");
                                                        return;
                                                    }
                                                    storage.ChangePassword(username, pass).Wait();
                                                    storage.SaveChanges();
                                                    Console.WriteLine($"Password for {username} was changed.");
                                                }
                                                else if (args.Length > 5)
                                                {
                                                    Console.WriteLine("Too many arguments. Use help for more info.");
                                                    return;
                                                }
                                                else
                                                {
                                                    Console.WriteLine("Not enough arguments. Use help for more info.");
                                                    return;
                                                } 
                                                break;
                                        default:
                                            Console.WriteLine("Unknown set command.");
                                            break;
                                    }
                                }
                                else
                                {
                                    Console.WriteLine("Not enough arguments. Use help for more info.");
                                    return;
                                }
                                break;
                            case "delete":
                                Console.WriteLine(storage.DeleteUser(user!).Result
                                    ? $"User {user!.Login} was removed."
                                    : $"Failed to remove user {user!.Login}.");
                                break;
                            default:
                                Console.WriteLine("Unknown user command.");
                                break;
                        }
                    }
                    else
                    {
                        Console.WriteLine("Not enough arguments. Use help for more info.");
                        break;
                    }
                    break;
                case "help": 
                    Console.WriteLine("user add [username] [pass] - add user");
                    Console.WriteLine("user set [username] mac [level] [?category] - set user level (and category)");
                    Console.WriteLine("user set [username] pass [pass] - set user password");
                    Console.WriteLine("user delete [username] - deletes user");
                    break;
                default:
                    Console.WriteLine("Unknown command.");
                    break;
            }
            return;
        }
        
        var builder = WebApplication.CreateBuilder(args);

        #region Builder app setup

        builder.Services.AddSerilog();
        builder.Services.AddDataProtection()
            .PersistKeysToDbContext<PersistentKeysDb>();
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

        #endregion
        #region Builder mac proxy setup
        
        TokenLifeSpan = TimeSpan.FromMinutes(builder.Configuration.GetValue<int?>("MACRiver:TokenLifeSpanMinutes") ?? 30);
        builder.Services.AddReverseProxy().LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"));
        builder.Services.AddHttpContextAccessor();
        builder.Services.AddDbContext<TokenStorage>();
        builder.Services.AddLocalAuthTokenProvider();
        
        #endregion
        
        #region Builder auth setup

        builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
            .AddCookie(options =>
            {
                options.LoginPath = "/login";
                options.LogoutPath = "/logout";
                options.ExpireTimeSpan = TokenLifeSpan;
                options.Events = new CookieAuthenticationEvents()
                {
                    OnRedirectToAccessDenied = _FakeRedirectAccessDenied
                };
            });

        builder.Services.AddAuthorization((options, sp) =>
        {
            options.AddPolicy("none", policyBuilder =>
            {
                policyBuilder.Requirements.Add(new AssertionRequirement(_ => true));
            });
            options.AddPolicy(RouteStatic.Restricted, policyBuilder =>
            {
                policyBuilder.RequireAssertion(_ => AuthorizeTokenForContext(sp.GetService<IHttpContextAccessor>()?.HttpContext!));
            });
        });

        #endregion

        app = builder.Build();

        #region App auth setup
        
        app.MapStaticAssets().ShortCircuit();
        app.UseLocalAuthTokenProvider();
        app.UseAuthentication();
        app.UseAuthorization();

        #endregion

        #region Login pages
        
        app.MapGet("/login", _LoginPage);
        app.MapPost("/login", _LoginPost);
        app.MapGet("/logout", _Logout);
        
        #endregion

        #region App setup

        app.MapReverseProxy(options =>
        {
            options.UseForwarderErrorDisplayMiddleware();
        });
        app.UseSerilogRequestLogging();

        app.Start();
        IsHttpsEnabled = _IsHttpsEnabled();
        if (IsHttpsEnabled)
        {
            Log.Error("=========================================");
            Log.Error("HTTPS is not enabled on this proxy.");
            Log.Error("This means, that all proxy traffic is transferred in plain-text."); 
            Log.Error("Please enable HTTPS for traffic encryption.");
            Log.Error("=========================================");
        }

        #endregion

        while (!app.Lifetime.ApplicationStopping.IsCancellationRequested) { }
    }

    private static async Task _FakeRedirectAccessDenied(RedirectContext<CookieAuthenticationOptions> redirContext)
    {
        // Prevent redirection when access is denied
        redirContext.Response.StatusCode = StatusCodes.Status403Forbidden;
        var returnUrl = redirContext.HttpContext.GetRedirectUrl();
        await redirContext.HttpContext.SendErrorPageAsync(HttpStatusCode.Forbidden, "Access denied.", 
            "Proxy failed to authorize you and forbidden access to this resource. \n" +
            $"<a href=\'/logout?ReturnURL=/login?ReturnURL={returnUrl}\'>You can re-login</a> if you using wrong account and try again.\n", 
            "ERR_ACCESS_DENIED");
    }

    private static async Task _LoginPage(HttpContext context)
    {
        var token = context.GetUserToken();
        if (token is not null && token.VerifyToken(context.RequestServices.GetService<TokenStorage>(),
                context.RequestServices.GetTokenProvider(token)))
        {
            context.RedirectToUrl();
        }
        await context.Response.SendLoginAsync();
    }

    private static async Task _LoginPost(HttpContext context)
    {
        if (!context.Request.Form.TryGetValue("passwordInput", out var pass)
            || !context.Request.Form.TryGetValue("loginInput", out var login)
            || string.IsNullOrEmpty(pass) || string.IsNullOrEmpty(login))
        {
            context.Response.Redirect("/");
            return;
        }
        if (await context.SignIn(context.RequestServices.GetService<LocalAuthTokenProvider>()!, 
                DateTime.Now.Add(TokenLifeSpan), login,pass))
        {
            context.RedirectToUrl();
            return;
        }
        context.Response.Redirect("/login?error=Failed%20to%20verify%20info%20you%20provided.");
    }

    private static async Task _Logout(HttpContext context)
    {
        var tokenAuthMethod = context.GetUserToken()?.AuthMethod;
        if (string.IsNullOrEmpty(tokenAuthMethod)) return;
        if (await context.SignOut())
        {
            Log.Warning($"Token provider {tokenAuthMethod} was not found. Maybe token is not properly destroyed.");
        }
        context.RedirectToUrl();
    }
    public static bool IsHttpsEnabled { get; private set; }
    private static bool _IsHttpsEnabled()
    {
        foreach (var url in app.Urls)
        {
            if (url.ToLower().StartsWith("https://"))
            {
                return true;
            }
        }
        return false;
    }
    
    private static bool AuthorizeTokenForContext(HttpContext context) =>
        context.GetUserToken().AuthorizeTokenForRoute(context.RequestServices, 
            context.GetEndpoint()?.Metadata.GetMetadata<RouteModel>()?.Config.RouteId!);

    public static bool IsAppDevelopment () => app.Environment.IsDevelopment();
}