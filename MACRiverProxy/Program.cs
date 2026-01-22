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
app.Run();