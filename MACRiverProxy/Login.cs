using System.Net;
using System.Text;
using Microsoft.AspNetCore.Mvc;
using Serilog;

namespace MACRiverProxy;

public static class Login
{
    public static void RedirectToLogin(this HttpResponse response, HttpStatusCode code = HttpStatusCode.TemporaryRedirect)
    {
        bool isDone = false;
        try
        {
            Log.Information($"Sending client to login page with {code} code");
            response.StatusCode = (int)code;
            response.WriteAsync(File.ReadAllText("./Pages/Login.html"));

            isDone = true;
        }
        catch (FileNotFoundException e)
        {
            Log.Error($"Error page was not found. {e.Message}");
            if (Program.IsAppDevelopment()) Log.Error(e.ToString());
            throw;
        }
        catch (Exception e)
        {
            Log.Error("Unexpected error when sending a error.");
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
}