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
using Microsoft.AspNetCore.DataProtection;
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

        #region App builder setup  
        builder.Services.AddSerilog();
        builder.Services.AddDataProtection()
            .PersistKeysToDbContext<PersistentKeysDb>();
        builder.Services.AddReverseProxy().LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"));;
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
        builder.Services.AddDbContext<TokenStorage>();
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
                    if (!VerifyToken(token, tokenStorageServ, tokenProvider))
                    {
                        Log.Information($"Token {token.Id} failed to verify.");
                        return false;
                    }

                    if (token?.MACLevel < macLevel)
                    {
                        Log.Information($"Token {token.Id} failed MAC level check ({token?.MACLevel} < {macLevel}).");
                        return false;
                    }

                    if (!(token?.IsCategory((byte)macCategory) ?? true))
                    {
                        Log.Information($"Token {token.Id} failed MAC category check (no {macCategory}).");
                        return false;
                    }

                    return true;
                });
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

        app.MapGet("/denied",  (context =>
        {
            try
            {
                context.Request.Query.TryGetValue("ReturnURL", out var returnUrl);
                context.SendErrorPage(HttpStatusCode.Forbidden, "Access denied.", "Proxy failed to authorize you and forbidden access to this resource. \n" +
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
                    context.RedirectToUrl();
                }
            }
        });
        app.MapGet("/logout", (context) =>
        {
            context.RedirectToUrl();
            return MACAuthentication.Singleton.SignOut(context,
                context.RequestServices.GetService<TokenStorage>()!, NullTokenProvider.Singleton);
        });
        #endregion

        #region App setup

        app.MapReverseProxy(options =>
        {
            options.UseForwaredErrorDisplayMiddleware();
        });
        app.UseSerilogRequestLogging();

        app.Start();

        IsHttpsEnabled(app);

        #endregion

        while (!app.Lifetime.ApplicationStopping.IsCancellationRequested) { }

        void IsHttpsEnabled(WebApplication webApplication)
        {
            foreach (var url in webApplication.Urls)
            {
                if (url.ToLower().StartsWith("https://"))
                {
                    return;
                }
            }
            Log.Error("=========================================");
            Log.Error("HTTPS is not enabled on this proxy.");
            Log.Error("This means, that all proxy traffic is transferred in plain-text."); 
            Log.Error("Please enable HTTPS for traffic encryption.");
            Log.Error("=========================================");
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