using System.Net;
using Serilog;

namespace MACRiverProxy;

public static class Pages
{
    public static async Task SendStoredPageAsync(this HttpResponse response, string pagePath,
        HttpStatusCode code = HttpStatusCode.TemporaryRedirect)
    {
        try
        {
            await response.SendPageAsync(await File.ReadAllTextAsync(pagePath), code);
        }
        catch (FileNotFoundException e)
        {
            Log.Error("Login page was not found. {eMsg}", e.Message);
            if (Program.IsAppDevelopment()) Log.Error(e.ToString());
            throw;
        }
    }
    public static async Task SendPageAsync(this HttpResponse response, string pageData, HttpStatusCode code = HttpStatusCode.TemporaryRedirect)
    {
        response.StatusCode = (int)code;
        await response.WriteAsync(pageData);
    }

    public static void SendPage(this HttpResponse response, string pagePath,
        HttpStatusCode code = HttpStatusCode.TemporaryRedirect) => SendPageAsync(response, pagePath, code).Wait();
}