using System.Net;
using Serilog;

namespace MACRiverProxy;

public static class LoginPage
{
    public static async Task SendLoginAsync(this HttpResponse response, HttpStatusCode code = HttpStatusCode.TemporaryRedirect)
    {
        Log.Information($"Sending client to login page with {code} code");
        try
        {
            await response.SendStoredPageAsync("./Pages/Login.html");
        }
        catch (Exception e)
        {
            Log.Error($"Unexpected error when sending a page.");
            Log.Error(e.ToString());
            response.StatusCode = StatusCodes.Status500InternalServerError;
            throw;
        }
    }

    public static void SendLogin(this HttpResponse response,
        HttpStatusCode code = HttpStatusCode.TemporaryRedirect) => SendLoginAsync(response, code).Wait();
}