using System.Net;
using System.Text;
using MACRiverProxy.Auth.Tokens;
using Microsoft.AspNetCore.Mvc;
using Serilog;

namespace MACRiverProxy;

public static class Login
{
    public static async Task RedirectToLoginAsync(this HttpResponse response, HttpStatusCode code = HttpStatusCode.TemporaryRedirect)
    {
        var context = response.HttpContext;
        var token = context.User
            .FindFirst(Token.TOKEN_CLAIM_NAME)?
            .ToToken();
        if (token is not null && Program.VerifyToken(token,
                context.RequestServices.GetService<TokenStorage>(),
                Program.GetTokenProvider(token, context.RequestServices)))
        {
            context.RedirectToUrl();
        }
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

    public static void RedirectToLogin(this HttpResponse response,
        HttpStatusCode code = HttpStatusCode.TemporaryRedirect) => RedirectToLoginAsync(response, code).Wait();
}