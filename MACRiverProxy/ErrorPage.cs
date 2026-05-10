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
        if (errorCode == ERR_GENERIC) Log.Error($"{ERR_GENERIC} was used. This error should be used only in development.");
        Log.Information($"Throwing error to client: {errorCode}");
        try
        {
            await context.Response.SendPageAsync(await GenerateErrorPage(errorHeader, errorMessage), code);
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

    private static async Task<string> GenerateErrorPage(string errorHeader, string errorMessage)
    {
        return string.Format(await File.ReadAllTextAsync("./Pages/ErrorPage.html"),
            errorHeader,
            errorMessage.Replace("\n", "<br/>"));
    }

    public static void SendErrorPage(this HttpContext context, HttpStatusCode code = HttpStatusCode.InternalServerError,
        string errorHeader = "Some error happened", string errorMessage = "Proxy thrown an error.\n" +
                                                                          "No additional information provided.\n\n" +
                                                                          "Contact administrator for additional help.",
        string errorCode = ERR_GENERIC) =>
        SendErrorPageAsync(context, code, errorHeader, errorMessage, errorCode).Wait();
}