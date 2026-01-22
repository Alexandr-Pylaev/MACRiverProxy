using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Infrastructure;
using Serilog;

var builder = WebApplication.CreateBuilder(args);

#region App builder setup

builder.Services.AddReverseProxy().LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"));;
builder.Services.AddSerilog(ser =>
{
    ser.WriteTo.Console();
});

#endregion

#region App builder auth setup

builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.LoginPath = "/login";
        options.LogoutPath = "/logout";
    });

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("none", policyBuilder =>
    {
        policyBuilder.Requirements.Add(new AssertionRequirement(_ => true));
    });
    options.AddPolicy("restricted", policyBuilder =>
    {
        policyBuilder.RequireAuthenticatedUser();
    });
});

#endregion

var app = builder.Build();

#region App auth setup

app.UseAuthentication();
app.UseAuthorization();

#endregion

#region Login pages

app.MapGet("/login", (context) => context.Request.HttpContext.
    SignInAsync(new ClaimsPrincipal(new ClaimsIdentity([new Claim("test", "100")], CookieAuthenticationDefaults.AuthenticationScheme))));
app.MapGet("/logout", (context) => context.Request.HttpContext.SignOutAsync());

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