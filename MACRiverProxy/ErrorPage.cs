using System.Net;
using System.Text;
using Microsoft.AspNetCore.Mvc;
using Serilog;

namespace MACRiverProxy;

public static class ErrorPage
{
    const string ERR_GENERIC = "ERR_GENERIC";
    public static async Task SendErrorPageAsync(this HttpContext context, HttpStatusCode code = HttpStatusCode.InternalServerError, 
        string errorHeader = "Some error happened", string errorMessage = "Proxy thrown an error.\n" +
                                                                           "No additional information provided.\n\n" +
                                                                           "Contact administrator for additional help.",
        string errorCode = ERR_GENERIC)
    {
        context.Response.StatusCode = ((int)HttpStatusCode.InternalServerError);
        if (errorCode == ERR_GENERIC) Log.Error($"{ERR_GENERIC} was used. This error should be used only in development.");
        try
        {
            Log.Information($"Throwing error to client: {errorCode}");
            context.Response.StatusCode = (int)code;
            await context.Response.WriteAsync(string.Format(await File.ReadAllTextAsync("./Pages/ErrorPage.html"), errorHeader,
                errorMessage.Replace("\n", "<br/>"), errorCode));
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
    }

    public static void SendErrorPage(this HttpContext context, HttpStatusCode code = HttpStatusCode.InternalServerError,
        string errorHeader = "Some error happened", string errorMessage = "Proxy thrown an error.\n" +
                                                                          "No additional information provided.\n\n" +
                                                                          "Contact administrator for additional help.",
        string errorCode = ERR_GENERIC) =>
        SendErrorPageAsync(context, code, errorHeader, errorMessage, errorCode).Wait();
}