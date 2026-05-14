using System.CommandLine;
using System.CommandLine.Parsing;
using System.Net;
using MACRiverProxy.Auth;
using MACRiverProxy.Auth.LocalAuth;
using MACRiverProxy.Auth.MAC;
using MACRiverProxy.Auth.Tokens;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization.Infrastructure;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption;
using Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption.ConfigurationModel;
using Microsoft.EntityFrameworkCore;
using Serilog;
using Yarp.ReverseProxy.Model;

namespace MACRiverProxy;

internal class Program
{
    private static WebApplication app;
    public static TimeSpan TokenLifeSpan;
    public static void Main(string[] args)
    {
        Log.Logger = new LoggerConfiguration() 
            .WriteTo.Console()
            .WriteTo.File($"./logs/{DateTime.Now:yyyy-mm-dd hh.mm.ss}.log")
            .Enrich.WithCorrelationId()
            .CreateLogger();
        AppDomain.CurrentDomain.ProcessExit += (_, _) => { Log.CloseAndFlush(); };
        bool bootServer = ExecuteCmd(args);
        if (!bootServer) return;
        try
        try // Fix for "SQLite Error 14: 'unable to open database file'." when folder does not exist
        {
            Directory.CreateDirectory("./db");
        }
        catch (Exception ex) when(ex is IOException or UnauthorizedAccessException 
                                      or PathTooLongException or DirectoryNotFoundException)
        {
            Log.Error("Failed to create folder for databases: {exMsg}", ex.Message);
            return;
        }
        var builder = WebApplication.CreateBuilder(args);

        #region Builder app setup

        builder.Services.AddSerilog();
        builder.Services.AddPersistentKeysDb();
        builder.Services.AddDataProtection()
            .PersistKeysToDbContext<PersistentKeysDb>().UseCryptographicAlgorithms(
                new AuthenticatedEncryptorConfiguration
                {
                    EncryptionAlgorithm = EncryptionAlgorithm.AES_256_CBC,
                    ValidationAlgorithm = ValidationAlgorithm.HMACSHA512
                });
        builder.WebHost.ConfigureKestrel(kestOpt =>
        {
            kestOpt.ConfigureHttpsDefaults(httpsOpt =>
            {
                httpsOpt.ServerCertificate = Environment.GetEnvironmentVariable("HTTPS_PEM_PASS") is null ? 
                    X509Certificate2
                        .CreateFromPemFile(
                            "/certs/cert.pem",
                            "/certs/key.pem"):
                    X509Certificate2
                        .CreateFromEncryptedPemFile(
                            "/certs/cert.pem",
                            Environment.GetEnvironmentVariable("HTTPS_PEM_PASS"),
                            "/certs/key.pem");
            });
        });

        #endregion
        #region Builder mac proxy setup
        
        TokenLifeSpan = TimeSpan.FromMinutes(builder.Configuration.GetValue<int?>("MACRiver:TokenLifeSpanMinutes") ?? 30);
        builder.Services.AddReverseProxy().LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"));
        builder.Services.AddHttpContextAccessor();
        builder.Services.AddDbContext<TokenKeyStorage>();
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
                policyBuilder.RequireAssertion(async _ =>
                {
                    var httpContext = sp.GetService<IHttpContextAccessor>()?.HttpContext!;
                    var result = await AuthorizeTokenForContext(httpContext);
                    var token = httpContext.GetUserToken();
                    Log.Information("[{HttpContextTraceIdentifier}{UserIdentifier}]: Token assertion result: {Result}", 
                        httpContext.TraceIdentifier, (token is null ? "" : $":{token.TokenKey}:{token.UserIdentifier}"), result);
                    return result;
                });
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
            options.UseProxyingErrorDisplayMiddleware();
        });
        app.UseSerilogRequestLogging(serilogOpt =>
        {
            serilogOpt.MessageTemplate = "[{TraceIdentifier}{TokenInfo}] " + serilogOpt.MessageTemplate;
            serilogOpt.EnrichDiagnosticContext = (diagnosticContext, httpContext) =>
            {
                diagnosticContext.Set("TraceIdentifier", httpContext.TraceIdentifier);
                var token = httpContext.GetUserToken();
                diagnosticContext.Set("TokenInfo", token is null ? "" : $":{token.UserIdentifier}");
            };
        });
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
        Command tokenCmd = new Command("token", "Token management.");
        Command tokenRevokeCmd = new Command("revoke", "Revokes token for user identifier.");
        Command tokenRevokeAllCmd = new Command("revoke-all", "Revokes all active tokens.");
        Command userCmd = new Command("user", "User management");
        Command userAddCmd = new Command("add", "Creates new user");
        Command userDeleteCmd = new Command("del", "Deletes user by login");
        Command userSetCmd = new Command("set", "Sets user's settings");
        Command userSetPasswordCmd = new Command("password", "Sets user's password");
        // ReSharper disable InconsistentNaming
        Command userSetMACCmd = new Command("mac", "Sets user's mandatory access control tag " +
                                                   
                                                   "(be aware, that old tokens will still have old MAC tag)");
        Command userSetMACLevelCmd = new Command("level", "Sets user's mandatory access control level");
        Command userSetMACCategoryCmd = new Command("category", "Sets user's mandatory access control category");
        // ReSharper restore InconsistentNaming
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
        Argument<string> userIdentifierArg = new Argument<string>("userIdentifier")
        {
            Arity = ArgumentArity.ExactlyOne,
            Description = "Login that will be affected by command",
            HelpName = "User Identifier"
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
        rootCmd.Add(tokenCmd);
        
        tokenCmd.Add(tokenRevokeCmd);
        tokenCmd.Add(tokenRevokeAllCmd);
        
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
        tokenRevokeCmd.Add(userIdentifierArg);
        
        userSetMACLevelCmd.Add(macLevelArg);
        userSetMACCategoryCmd.Add(macCategoryArg);
        
        Action<ParseResult> bootServerAction = _ =>
        {
            bootServer = true;
        };
        
        string[] logins = [];
        List<LocalAuthUser> users = new();
        TokenKeyStorage tokenStorage = new TokenKeyStorage();
        LocalAuthStorage localAuthStorage = new LocalAuthStorage();
        localAuthStorage.Database.Migrate();
        
        userAddCmd.Validators.Add((parseResult) =>
        {
            try
            {
                logins = parseResult.GetRequiredValue(loginsArg);
            }
            catch (InvalidOperationException)
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
            catch (InvalidOperationException)
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
            catch (InvalidOperationException)
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
            catch (InvalidOperationException)
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
            catch (InvalidOperationException)
            {
                result.AddError("Mandatory access control level is invalid.");
                return;
            }
            if (level is null) 
                result.AddError("Mandatory access control level is not set.");
        });
        
        rootCmd.SetAction(bootServerAction);
        bootCmd.SetAction(bootServerAction);
        
        tokenRevokeAllCmd.SetAction(cmdResult =>
        {
            Log.Information("{RemovedTokenCount} token key(s) was removed.", 
                tokenStorage.RevokeTokenKeys(cmdResult.GetRequiredValue(userIdentifierArg)));
        });
        
        tokenRevokeAllCmd.SetAction(async _ =>
        {
            Log.Warning("Attention! This action will revoke all active tokens. " +
                        "This means, that all current sessions will be invalid.");
            Log.Warning("Do you really want to proceed? (y/N)");
            string response;
            do
            {
                Log.Information("Y or N.");
                response = Console.ReadLine()?.ToLower() ?? "n";
            } while (response != "y" || response != "n");
            if (response == "n") return;
            foreach (var activeTokenKey in tokenStorage.GetActiveTokenKeys)
            {
                await tokenStorage.RevokeToken(activeTokenKey);
                Log.Information("Token key {TokenKey} was revoked.", activeTokenKey);
            }
        });
        
        userAddCmd.SetAction( _ =>
        {
            var sensitiveLogger = new LoggerConfiguration().WriteTo.Console().CreateLogger();
            foreach (string login in logins)
            {
                var pass = AuthStatic.GenerateRandomPassword(24);
                localAuthStorage.RegisterUser(login, pass).Wait();
                Log.Information("Added user {login} with password [:::SECRET:::]", login);
                sensitiveLogger.Information("Password for user {login}: {pass}", login, pass);
            }
            Log.Information("Done.");
        });
        userDeleteCmd.SetAction( _ =>
        {
            foreach (LocalAuthUser user in users)
            {
                localAuthStorage.DeleteUser(user).Wait();
                Log.Information("User {login} deleted.", user.Login);
            }
            Log.Information("Done.");
        });
        
        userSetMACCategoryCmd.SetAction(async _ =>
        {
            LocalAuthUser user = users[0];
            user.MACCategory = category ?? user.MACCategory;
            await localAuthStorage.SaveChangesAsync();
            await tokenStorage.RevokeTokenKeys(user.Login);
            Log.Information("Done. All active tokens of this user is removed.");
        });
        
        userSetMACLevelCmd.SetAction(async _ =>
        {
            LocalAuthUser user = users[0];
            user.MACLevel = level ?? user.MACLevel;
            await localAuthStorage.SaveChangesAsync();
            await tokenStorage.RevokeTokenKeys(user.Login);
            Log.Information("Done. All active tokens of this user is removed.");
        });
        
        userSetPasswordCmd.SetAction( _ =>
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
                Log.Information("Password changed for user {login}", user.Login);
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
            foreach (string login in logins)
            {
                var findedUser = localAuthStorage.FindUser(login).Result;
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
        var returnUrl = redirContext.HttpContext.Request.GetRedirectUrl();
        if (!await redirContext.HttpContext.TrySendErrorPageAsync(HttpStatusCode.Forbidden, "Access denied.",
                "Proxy failed to authorize you and forbidden access to this resource. \n" +
                $"<a href=\'/logout?ReturnURL=/login?ReturnURL={returnUrl}\'>You can re-login</a> if you using wrong account and try again.\n",
                "ERR_ACCESS_DENIED"))
        {
            Log.Error("Error page failed to send.");
        }
    }

    private static async Task _LoginPage(HttpContext context)
    {
        var token = context.GetUserToken();
        if (token is not null && await token.VerifyToken(context.RequestServices.GetService<TokenKeyStorage>(),
                context.RequestServices.GetTokenProvider(token)))
        {
            context.RedirectToRedirectUrl();
        }

        try
        {
            await context.Response.SendLoginAsync();
        }
        catch (FileNotFoundException e)
        { 
            Log.Error("Login page was not found. {eMsg}", e.Message);
            Log.Verbose(e.ToString());
        }
        catch (Exception ex)
        {
            Log.Error(ex, $"Unexpected error when sending a page.");
        }
    }

    private static async Task _LoginPost(HttpContext context)
    {
        if (!context.Request.Form.TryGetValue("authMethod", out var authMethod) || string.IsNullOrEmpty(authMethod))
        {
            Log.Warning("Missing authMethod field in form. Skipping.");
            context.Response.Redirect("/");
            return;
        }

        var tokenProvider = context.RequestServices.GetTokenProvider(authMethod!);
        if (tokenProvider is null)
        {
            Log.Warning("Missing token provider {authMethod}.", authMethod);
            context.Response.RedirectWithLoginError("Failed to use selected auth method.");
            return;
        }
        if (tokenProvider is not FormTokenProvider)
        {
            Log.Warning("Requested token provider {authMethod} is not form token provider.", authMethod);
            context.Response.RedirectWithLoginError("This auth method does not supports login form.");
            return;
        }
        if (await context.SignIn((FormTokenProvider)tokenProvider, DateTime.Now.Add(TokenLifeSpan)))
        {
            context.RedirectToRedirectUrl();
            return;
        }
        Log.Information("Failed to verify provided login info.");
        context.Response.RedirectWithLoginError("Failed to verify info you provided.");
    }

    private static async Task _Logout(HttpContext context)
    {
        var tokenAuthMethod = context.GetUserToken()?.AuthMethod;
        if (string.IsNullOrEmpty(tokenAuthMethod)) return;
        if (await context.SignOut())
        {
            Log.Warning("Token provider {tokenAuthMethod} was not found. Maybe token is not properly destroyed.", tokenAuthMethod);
        }
        context.RedirectToRedirectUrl();
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
    
    private static async Task<bool> AuthorizeTokenForContext(HttpContext context) =>
        await context.GetUserToken().AuthorizeTokenForRoute(context.GetEndpoint()?.Metadata.GetMetadata<RouteModel>()?.Config.RouteId!, context.RequestServices);
}