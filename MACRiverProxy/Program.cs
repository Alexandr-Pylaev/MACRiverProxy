using System.CommandLine;
using System.CommandLine.Parsing;
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
            .WriteTo.File($"./logs/{DateTime.Now:yyyy-mm-dd hh.mm.ss}.log")
            .CreateLogger();
        bool bootServer = false;
        bootServer = ExecuteCmd(args);
        if (!bootServer) return;
        try
        {
            Directory.CreateDirectory("./db");
        }
        catch (Exception ex) when(ex is IOException or UnauthorizedAccessException 
                                      or PathTooLongException or DirectoryNotFoundException)
        {
            Log.Error($"Failed to create folder for databases: {ex.Message}");
            return;
        }
        var builder = WebApplication.CreateBuilder(args);

        #region Builder app setup

        builder.Services.AddSerilog();
        builder.Services.AddPersistentKeysDb();
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

        app.UsePersistentKeysDb();
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

    private static bool ExecuteCmd(string[] args)
    {
        bool bootServer = false;
        RootCommand rootCmd = new RootCommand( "MAC River proxy server and CLI tool.\nNo command is same as boot.")
        {
            TreatUnmatchedTokensAsErrors = false
        };
        Command bootCmd = new Command("boot", "Starts a proxy.");
        Command userCmd = new Command("user", "User management");
        Command userAddCmd = new Command("add", "Creates new user");
        Command userDeleteCmd = new Command("del", "Deletes user by login");
        Command userSetCmd = new Command("set", "Sets user's settings");
        Command userSetPasswordCmd = new Command("password", "Sets user's password");
        Command userSetMACCmd = new Command("mac", "Sets user's mandatory access control tag");
        Command userSetMACLevelCmd = new Command("level", "Sets user's mandatory access control level");
        Command userSetMACCategoryCmd = new Command("category", "Sets user's mandatory access control category");
        Argument<string[]> loginsArg = new Argument<string[]>("logins")
        {
            Arity = ArgumentArity.OneOrMore,
            Description = "All logins that will be affected by command"
        };
        Argument<string> loginArg = new Argument<string>("login")
        {
            Arity = ArgumentArity.ExactlyOne,
            Description = "Login that will be affected by command"
        };

        Argument<byte?> macLevelArg = new Argument<byte?>("mac-level")
        {
            Arity = ArgumentArity.ExactlyOne,
            Description = "Mandatory access control level (0-255)",
            DefaultValueFactory = _ => null
        };
        Argument<ulong?> macCategoryArg = new Argument<ulong?>("mac-category")
        {
            Arity = ArgumentArity.ExactlyOne,
            Description = "Mandatory access control category (ulong bitmask)",
            DefaultValueFactory = _ => null
        };
        
        rootCmd.Add(userCmd);
        rootCmd.Add(bootCmd);
        
        userCmd.Subcommands.Add(userAddCmd);
        userCmd.Subcommands.Add(userDeleteCmd);
        userCmd.Subcommands.Add(userSetCmd);
        
        userSetCmd.Subcommands.Add(userSetPasswordCmd);
        userSetCmd.Subcommands.Add(userSetMACCmd);
        
        userSetMACCmd.Subcommands.Add(userSetMACLevelCmd);
        userSetMACCmd.Subcommands.Add(userSetMACCategoryCmd);
        
        userAddCmd.Add(loginsArg);
        userDeleteCmd.Add(loginsArg);
        userSetPasswordCmd.Add(loginArg);
        userSetMACCmd.Add(loginArg);
        
        userSetMACLevelCmd.Add(macLevelArg);
        userSetMACCategoryCmd.Add(macCategoryArg);
        
        Action<ParseResult> bootServerAction = _ =>
        {
            bootServer = true;
        };
        
        string[] logins = [];
        List<LocalAuthUser> users = new();
        LocalAuthStorage localAuthStorage = new LocalAuthStorage();
        localAuthStorage.Database.Migrate();
        
        userAddCmd.Validators.Add((parseResult) =>
        {
            try
            {
                logins = parseResult.GetRequiredValue(loginsArg);
            }
            catch (InvalidOperationException ex)
            {
                parseResult.AddError("Login was not provided.");
                return;
            }
            foreach (string login in logins)
            {
                if (localAuthStorage.IsUserRegistered(login).Result)
                {
                    parseResult.AddError($"Login {login} is already registered.");
                }
            }
        });
        
        Action<CommandResult> validateUsersExists = parseResult =>
        {
            try
            {
                logins = parseResult.GetRequiredValue(loginsArg);
            }
            catch (InvalidOperationException ex)
            {
                parseResult.AddError("Login was not provided.");
                return;
            }
            ForeachUserLogins(parseResult);
        };
        Action<CommandResult> validateUserExists = parseResult =>
        {
            try
            {
                logins = [parseResult.GetRequiredValue(loginArg)];
            }
            catch (InvalidOperationException ex)
            {
                parseResult.AddError("Login was not provided.");
                return;
            }
            ForeachUserLogins(parseResult);
        };
        
        userSetPasswordCmd.Validators.Add(validateUserExists);
        userSetMACCmd.Validators.Add(validateUserExists);
        userDeleteCmd.Validators.Add(validateUsersExists);
        
        ulong? category = 0;
        userSetMACCategoryCmd.Validators.Add(result =>
        {
            try
            {
                category = result.GetValue(macCategoryArg);
            }
            catch (InvalidOperationException ex)
            {
                result.AddError("Mandatory access control category is invalid.");
                return;
            }

            if (category is null) 
                result.AddError("Mandatory access control category is not set.");
        });
        
        byte? level = 0;
        userSetMACLevelCmd.Validators.Add(result =>
        {
            try
            {
                level = result.GetValue(macLevelArg);
            }
            catch (InvalidOperationException ex)
            {
                result.AddError("Mandatory access control level is invalid.");
                return;
            }
            if (level is null) 
                result.AddError("Mandatory access control level is not set.");
        });
        
        rootCmd.SetAction(bootServerAction);
        bootCmd.SetAction(bootServerAction);
        
        userAddCmd.SetAction(async _ =>
        {
            var sensitiveLogger = new LoggerConfiguration().WriteTo.Console().CreateLogger();
            foreach (string login in logins)
            {
                var pass = AuthStatic.GenerateRandomPassword(24);
                localAuthStorage.RegisterUser(login, pass).Wait();
                Log.Information($"Added user {login} with password [:::SECRET:::]");
                sensitiveLogger.Information($"Password for user {login}: {pass}.");
            }
            Log.Information("Done.");
        });
        userDeleteCmd.SetAction(async _ =>
        {
            foreach (LocalAuthUser user in users)
            {
                localAuthStorage.DeleteUser(user).Wait();
                Log.Information($"User {user.Login} deleted.");
            }
            Log.Information("Done.");
        });
        
        userSetMACCategoryCmd.SetAction(async _ =>
        {
            LocalAuthUser user = users[0];
            user.MACCategory = category ?? user.MACCategory;
            await localAuthStorage.SaveChangesAsync();
        });
        
        userSetMACLevelCmd.SetAction(async _ =>
        {
            LocalAuthUser user = users[0];
            user.MACLevel = level ?? user.MACLevel;
            await localAuthStorage.SaveChangesAsync();
        });
        
        userSetPasswordCmd.SetAction(async _ =>
        {
            LocalAuthUser user = users[0];
            Console.Write("Enter password: ");
            var pass = string.Empty;
            ConsoleKey key;
            do
            {
                var keyInfo = Console.ReadKey(intercept: true);
                key = keyInfo.Key;

                if (key == ConsoleKey.Backspace && pass.Length > 0)
                {
                    Console.Write("\b \b");
                    pass = pass[0..^1];
                }
                else if (!char.IsControl(keyInfo.KeyChar))
                {
                    Console.Write("*");
                    pass += keyInfo.KeyChar;
                }
            } while (key != ConsoleKey.Enter);
            Console.WriteLine();
            try
            {
                if (pass.Length < 8)
                {
                    Log.Error("Password is too short.");
                    return;
                }
                localAuthStorage.ChangePassword(user, pass).Wait();
                Log.Information($"Password changed for user {user.Login}");
            }
            catch (AggregateException ex)
            {
                if (ex.InnerException is ArgumentException)
                {
                    Log.Error(ex.InnerException.Message);
                }
            }
        });
        
        void ForeachUserLogins(CommandResult parseResult)
        {
            users = new List<LocalAuthUser>(logins.Length);
            LocalAuthUser? findedUser;
            foreach (string login in logins)
            {
                findedUser = localAuthStorage.FindUser(login).Result;
                if (findedUser is null)
                {
                    parseResult.AddError($"Login {login} does not exists.");
                    continue;
                }

                users.Add(findedUser);
            }
        }
        
        rootCmd.Parse(args).Invoke();
        return bootServer;
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