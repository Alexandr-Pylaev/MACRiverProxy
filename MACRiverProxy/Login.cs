using System.Net;
using System.Text;
using MACRiverProxy.Auth.Tokens;
using Microsoft.AspNetCore.Mvc;
using Serilog;

namespace MACRiverProxy;

public static class Login
{
    public static async Task SendLoginAsync(this HttpResponse response, HttpStatusCode code = HttpStatusCode.TemporaryRedirect)
    {
        bool isDone = false;
        try
        {
            Log.Information($"Sending client to login page with {code} code");
            response.StatusCode = (int)code;
            await response.WriteAsync(await File.ReadAllTextAsync("./Pages/Login.html"));

            isDone = true;
        }
        catch (FileNotFoundException e)
        {
            Log.Error($"Login page was not found. {e.Message}");
            if (Program.IsAppDevelopment()) Log.Error(e.ToString());
            throw;
        }
        catch (Exception e)
        {
            Log.Error("Unexpected error when sending a login page.");
            Log.Error(e.ToString());
        }
        finally
        {
            if (!isDone)
            {
                response.StatusCode = ((int)HttpStatusCode.InternalServerError);
            }
        }
    }

    public static void SendLogin(this HttpResponse response,
        HttpStatusCode code = HttpStatusCode.TemporaryRedirect) => SendLoginAsync(response, code).Wait();
}