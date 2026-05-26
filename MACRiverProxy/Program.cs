using System.CommandLine;
using System.CommandLine.Parsing;
using System.Net;
using System.Security;
using System.Security.Cryptography.X509Certificates;
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
namespace MACRiverProxy;

internal class Program
{
    private static WebApplication app;
    public static TimeSpan TokenLifeSpan;
    public static void Main(string[] args)
    {
        #region Pre-builder setup

        var logPath = $"./logs/{DateTime.Now:yyyy-mm-dd hh.mm.ss}.log";
        Log.Logger = new LoggerConfiguration() 
            .WriteTo.Console()
            .WriteTo.File(logPath, rollingInterval:RollingInterval.Day)
            .Enrich.WithCorrelationId()
            .CreateBootstrapLogger();
        // Close logger on process exit
        AppDomain.CurrentDomain.ProcessExit += (_, _) => { Log.CloseAndFlush(); };
        try // Fix for "SQLite Error 14: 'unable to open database file'." when folder does not exist
        {
            Directory.CreateDirectory("./db");
        }
        catch (Exception ex) when(ex is IOException or UnauthorizedAccessException 
                                      or PathTooLongException or DirectoryNotFoundException)
        {
            // Exit app because it'll crash anyway
            Log.Error("Failed to create folder for databases: {exMsg}", ex.Message);
            return;
        }
        #endregion

        #region CLI-tool

        bool bootServer = _ExecuteCmd(args); // Execute commands before booting proxy
        if (!bootServer) return; 

        #endregion
        
        var builder = WebApplication.CreateBuilder(args);
        Log.Logger = new LoggerConfiguration()
            .ReadFrom.Configuration(builder.Configuration)
            .WriteTo.Console()
            .WriteTo.File(logPath)
            .Enrich.WithCorrelationId()
            .CreateLogger();
        #region Builder app setup

        builder.Services.AddSerilog();
        builder.Services.AddPersistentKeysDb();
        builder.Services.AddDataProtection()
            .PersistKeysToDbContext<PersistentKeysDb>().UseCryptographicAlgorithms( // Enable encryption
                new AuthenticatedEncryptorConfiguration              // that is disabled for some reason
                {
                    EncryptionAlgorithm = EncryptionAlgorithm.AES_256_CBC,
                    ValidationAlgorithm = ValidationAlgorithm.HMACSHA512
                });
        // Configuring defaults for HTTPS
        builder.WebHost.ConfigureKestrel(kestOpt =>
        {
            bool disableDefaults = false;
            try
            {
                // Setting default certificate to /certs/cert(key).pem
                disableDefaults = Environment.GetEnvironmentVariable("DISABLE_DEFAULT_CERT_PATH") == "1";
            }
            catch (SecurityException ex)
            {
                Log.Error("Failed to get access to environment variables: {exMsg}", ex.Message);
            }
            if (!disableDefaults)
            {
                kestOpt.ConfigureHttpsDefaults(httpsOpt =>
                {
                    // If pem password set, use that
                    httpsOpt.ServerCertificate = Environment.GetEnvironmentVariable(HTTPS_PEM_PASS_ENV_NAME) is null ? 
                        X509Certificate2
                            .CreateFromPemFile(
                                "./certs/cert.pem",
                                "./certs/key.pem"):
                        X509Certificate2
                            .CreateFromEncryptedPemFile(
                                "./certs/cert.pem",
                                Environment.GetEnvironmentVariable(HTTPS_PEM_PASS_ENV_NAME),
                                "./certs/key.pem");
                });
            }
        });

        #endregion
        
        #region Builder mac proxy setup
        //Default is 30 minutes
        TokenLifeSpan = TimeSpan.FromMinutes(builder.Configuration.GetValue<int?>(TOKEN_LIFE_SPAN_MINUTES_CONFIG_NAME) ?? 30);
        builder.Services.AddReverseProxy().LoadFromConfig(builder.Configuration.GetSection(REVERSE_PROXY_CONFIG_NAME));
        builder.Services.AddHttpContextAccessor(); // Creates service for finding HTTP context in authorization
        builder.Services.AddDbContext<TokenKeyStorage>();
        builder.Services.AddLocalAuthTokenProvider(); // Adds Local auth
        
        #endregion
        
        #region Builder auth setup
        //Default cookie auth signs and encrypts data
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
            // None is for disabled auth
            options.AddPolicy("none", policyBuilder =>
            {
                policyBuilder.Requirements.Add(new AssertionRequirement(_ => true));
            });
            // Restricted is MAC auth
            options.AddPolicy(RouteStatic.Restricted, policyBuilder =>
            {
                policyBuilder.RequireAssertion(async _ =>
                {
                    // Gets HTTP context
                    var httpContext = sp.GetService<IHttpContextAccessor>()?.HttpContext!;
                    // and uses it for authorizing token
                    var result = await httpContext.AuthorizeTokenForContext();
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

        app.UsePersistentKeysDb(); // Migrates PersistentKeysDb
        app.MapStaticAssets().ShortCircuit(); // Enable static files without auth
        app.UseLocalAuthTokenProvider(); // Enable Local auth
        app.UseAuthentication();
        app.UseAuthorization();

        #endregion

        #region Registering login/logout pages
        
        app.MapGet("/login", _LoginPage);
        app.MapPost("/login", _LoginPost);
        app.Map("/logout", _Logout);
        
        #endregion

        #region App setup
        // Enables error logging middleware
        app.MapReverseProxy(options =>
        {
            options.UseProxyingErrorDisplayMiddleware();
        });
        // Adds MAC proxy additional info to logs
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
        app.Start(); // Starts app, but does not lock it
        IsHttpsEnabled = _IsHttpsEnabled();
        if (!IsHttpsEnabled) // Warns admin that proxy is not using HTTPS
        {
            Log.Error("=========================================");
            Log.Error("HTTPS is not enabled on this proxy.");
            Log.Error("This means, that all proxy traffic is transferred in plain-text."); 
            Log.Error("Please enable HTTPS for traffic encryption.");
            Log.Error("=========================================");
        }

        #endregion
        // Locking main thread so app does not close
        while (!app.Lifetime.ApplicationStopping.IsCancellationRequested) { }
    }

    /// <summary>
    /// Name for Reverse proxy config section
    /// </summary>
    public const string REVERSE_PROXY_CONFIG_NAME ="MACRiver";
    /// <summary>
    /// Name for token life span number in minutes in config
    /// </summary>
    public const string TOKEN_LIFE_SPAN_MINUTES_CONFIG_NAME = $"{REVERSE_PROXY_CONFIG_NAME}:TokenLifeSpanMinutes";
    /// <summary>
    /// Env name for PEM password
    /// </summary>
    public const string HTTPS_PEM_PASS_ENV_NAME = "HTTPS_PEM_PASS";

    /// <summary>
    /// Executes CLI tool. You can disable that method if you don't use <see cref="LocalAuthTokenProvider"/>.
    /// </summary>
    /// <param name="args">CMD args</param>
    /// <returns>Should server boot</returns>
    private static bool _ExecuteCmd(string[] args)
    {
        bool bootServer = false;
        #region Command objects
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
        // ReSharper disable InconsistentNaming Disable warnings for MAC word
        Command userSetMACCmd = new Command("mac", "Sets user's mandatory access control tag " +
                                                   
                                                   "(be aware, that old tokens will still have old MAC tag)");
        Command userSetMACLevelCmd = new Command("level", "Sets user's mandatory access control level");
        Command userSetMACCategoryCmd = new Command("category", "Sets user's mandatory access control category. When used with --add, " +
                                                                "expects category number, not category bits.");
        // ReSharper restore InconsistentNaming
        #endregion

        #region Options objects

        Option<bool> additiveOpt = new Option<bool>("--add", "-a")
        {
            Description = "Adds to MAC tag and not replaces it.",
            DefaultValueFactory = _ => false
        };

        #endregion
        
        #region Argument objects
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
        #endregion

        #region Registering commands
        rootCmd.Add(userCmd);
        rootCmd.Add(bootCmd);
        rootCmd.Add(tokenCmd);
        
        tokenCmd.Add(tokenRevokeCmd);
        tokenCmd.Add(tokenRevokeAllCmd);
        
        userCmd.Add(userAddCmd);
        userCmd.Add(userDeleteCmd);
        userCmd.Add(userSetCmd);
        
        userSetCmd.Add(userSetPasswordCmd);
        userSetCmd.Add(userSetMACCmd);
        
        userSetMACCmd.Add(userSetMACLevelCmd);
        userSetMACCmd.Add(userSetMACCategoryCmd);
        userSetMACCategoryCmd.Add(additiveOpt);
        userSetMACLevelCmd.Add(additiveOpt);
        #endregion
        
        #region Registering arguments for commands
        userAddCmd.Add(loginsArg);
        userDeleteCmd.Add(loginsArg);
        userSetPasswordCmd.Add(loginArg);
        userSetMACCmd.Add(loginArg);
        tokenRevokeCmd.Add(userIdentifierArg);
        
        userSetMACLevelCmd.Add(macLevelArg);
        userSetMACCategoryCmd.Add(macCategoryArg);
        #endregion
        
        string[]? logins = []; // Stores logins after validators
        List<LocalAuthUser> users = new(); // Stores users after validation
        TokenKeyStorage tokenStorage = new TokenKeyStorage();
        LocalAuthStorage localAuthStorage = new LocalAuthStorage();
        byte? level = 0; // Stores MAC level after validation
        ulong? category = 0; // Stores MAC category after validation
        
        // Migrating dbs just to be sure
        tokenStorage.Database.Migrate();
        localAuthStorage.Database.Migrate(); 
        
        #region Validators
        // GetRequiredValue raises InvalidOperationException on no value or invalid value
        // GetValue raises InvalidOperationException on invalid input
        userAddCmd.Validators.Add((parseResult) =>
        {
            logins = GetLogins(parseResult);
            if (logins is null) return;
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
            logins = GetLogins(parseResult);
            if (logins is null) return;
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
        userSetMACCategoryCmd.Validators.Add(validateUserExists);
        userSetMACLevelCmd.Validators.Add(validateUserExists);
        userDeleteCmd.Validators.Add(validateUsersExists);
        
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
        #endregion

        #region Command actions
        Action<ParseResult> bootServerAction = _ => // boot command just sets bool and returns
        {
            bootServer = true;
        };
        
        rootCmd.SetAction(bootServerAction);
        bootCmd.SetAction(bootServerAction);
        
        tokenRevokeCmd.SetAction(cmdResult =>
        {
            Log.Information("{RemovedTokenCount} token key(s) was removed.", 
                tokenStorage.RevokeTokenKeys(cmdResult.GetRequiredValue(userIdentifierArg)).Result);
        });
        
        tokenRevokeAllCmd.SetAction(async _ =>
        {
            // Critical command accidental execution prevention
            if (!ConsoleHelper.AccidentalExecutionPrevention("This action will revoke all active token keys.\n" +
                                              "This means, that all current sessions will be invalid.")) return;
            await tokenStorage.RevokeTokenKeys(tokenStorage.GetActiveTokenKeys.ToArray());
            Log.Information("All token keys was revoked.");
        });
        
        userAddCmd.SetAction( _ =>
        {
            // Creates separate logger for logging password only in console
            var sensitiveLogger = new LoggerConfiguration().WriteTo.Console().CreateLogger();
            foreach (string login in logins)
            {
                var pass = AuthStatic.GenerateRandomPassword(24); // Generates random default password
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
        
        userSetMACCategoryCmd.SetAction(async parseResult =>
        {
            LocalAuthUser user = users[0]; // Gets first user (because there is only one)
            if (parseResult.GetValue<bool>(additiveOpt))
            {
                user.AddMACCategory((byte)
                    ((category ?? throw new InvalidOperationException("Category cannot be null.")) - 1));
            }
            else user.MACCategory = category ?? user.MACCategory;
            await localAuthStorage.SaveChangesAsync();
            await tokenStorage.RevokeTokenKeys(user.Login); // Revokes all token keys for user
            Log.Information("Done. All active tokens of this user is removed.");
        });
        
        userSetMACLevelCmd.SetAction(async parseResult =>
        {
            LocalAuthUser user = users[0]; // Gets first user (because there is only one)
            if (parseResult.GetValue<bool>(additiveOpt))
            {
                user.AddMACLevel(level ?? user.MACLevel);
            }
            else user.MACLevel = level ?? user.MACLevel;
            await localAuthStorage.SaveChangesAsync();
            await tokenStorage.RevokeTokenKeys(user.Login); // Revokes all token keys for user
            Log.Information("Done. All active tokens of this user is removed.");
        });
        
        userSetPasswordCmd.SetAction( _ =>
        {
            LocalAuthUser user = users[0];
            Console.Write("Enter password: ");
            var pass = ConsoleHelper.HiddenRead(); // Hides input
            Console.WriteLine();
            try
            {
                if (pass.Length < 8) // If password is too short, return
                {
                    Log.Error("Password is too short.");
                    return;
                }
                localAuthStorage.ChangePassword(user, pass).Wait();
                Log.Information("Password changed for user {login}", user.Login);
            }
            catch (AggregateException ex)
            {
                if (ex.InnerException is ArgumentException) // Show error if password change fails
                {
                    Log.Error(ex.InnerException.Message);
                }
            }
        });
        
        // Finds and add users to list by logins
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
        // Gets logins from argument and shows error if fails
        string[]? GetLogins(CommandResult parseResult)
        {
            try
            {
                logins = parseResult.GetRequiredValue(loginsArg);
            }
            catch (InvalidOperationException)
            {
                parseResult.AddError("Logins was not provided or invalid.");
                return null;
            }

            return logins;
        }
        #endregion
        
        rootCmd.Parse(args).Invoke(); // Running command
        return bootServer;
    }

    /// <summary>
    /// Prevent redirection when access is denied
    /// </summary>
    /// <param name="redirContext">Redirect context</param>
    private static async Task _FakeRedirectAccessDenied(RedirectContext<CookieAuthenticationOptions> redirContext)
    {
        redirContext.Response.StatusCode = StatusCodes.Status403Forbidden;
        var returnUrl = redirContext.HttpContext.Request.Path;
        if (!await redirContext.HttpContext.TrySendErrorPageAsync(HttpStatusCode.Forbidden, "Access denied.",
                "Proxy failed to authorize you and forbidden access to this resource. \n" +
                $"<a href=\'/logout?ReturnURL=/login?ReturnURL={returnUrl}\'>You can re-login</a> if you using wrong account and try again.\n",
                "ERR_ACCESS_DENIED"))
        {
            Log.Error("Error page failed to send.");
        }
    }

    /// <summary>
    /// Login GET route
    /// </summary>
    private static async Task _LoginPage(HttpContext context)
    {
        var token = context.GetUserToken();
        if (token is not null && await token.VerifyToken(context.RequestServices.GetService<TokenKeyStorage>(),
                context.RequestServices.GetTokenProvider(token))) // If user already auth, redirect
        {
            context.RedirectToRedirectUrl();
            return;
        }

        try
        {
            await context.Response.SendLoginAsync(); // else, send login page
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

    /// <summary>
    /// Login POST route
    /// </summary>
    private static async Task _LoginPost(HttpContext context)
    {
        // If Form does not contain auth method, throwing user to login page with error
        if (!context.Request.Form.TryGetValue("authMethod", out var authMethod) || string.IsNullOrEmpty(authMethod))
        {
            Log.Warning("Missing authMethod field in form. Skipping.");
            context.Response.RedirectWithLoginError("Missing authentication method field.");
            return;
        }

        var tokenProvider = context.RequestServices.GetTokenProvider(authMethod!);
        if (tokenProvider is null) // If no provider, error user
        {
            Log.Warning("Missing token provider {authMethod}.", authMethod);
            context.Response.RedirectWithLoginError("Failed to use selected auth method.");
            return;
        }
        if (tokenProvider is not FormTokenProvider provider) // If provider is not for Form login, error user
        {
            Log.Warning("Requested token provider {authMethod} is not form token provider.", authMethod);
            context.Response.RedirectWithLoginError("This auth method does not supports login form.");
            return;
        }
        if (await context.SignIn(provider, DateTime.Now.Add(TokenLifeSpan)))
        {
            context.RedirectToRedirectUrl();
            return;
        }
        Log.Information("Failed to verify provided login info.");
        context.Response.RedirectWithLoginError("Failed to verify info you provided.");
    }

    /// <summary>
    /// Logout route
    /// </summary>
    private static async Task _Logout(HttpContext context)
    {
        var tokenAuthMethod = context.GetUserToken()?.AuthMethod;
        if (string.IsNullOrEmpty(tokenAuthMethod)) return; // Null when token is null
        if (await context.SignOut())
        {
            Log.Warning("Token provider {tokenAuthMethod} was not found. Maybe token is not properly destroyed.", tokenAuthMethod);
        }
        context.RedirectToRedirectUrl();
    }
    /// <summary>
    /// Is HTTPS enabled in app. Works after app start.
    /// </summary>
    public static bool IsHttpsEnabled { get; private set; }
    /// <summary>
    /// Searches for https:// endpoint
    /// </summary>
    /// <returns>Is HTTPS endpoint exists</returns>
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
}