using Serilog;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddReverseProxy().LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"));;
builder.Services.AddSerilog(ser =>
{
    ser.WriteTo.Console();
});
var app = builder.Build();

app.MapReverseProxy();
app.UseSerilogRequestLogging();

app.Start();

IsHttpsEnabled(app);

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