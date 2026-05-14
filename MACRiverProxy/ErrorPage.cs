using System.Net;
using Serilog;

namespace MACRiverProxy;
/// <summary>
/// Extension method for sending error page
/// </summary>
public static class ErrorPage
{
    /// <summary>
    /// Default error value. 
    /// </summary>
    /// <remarks>Do not use this error for production, this error means nothing and only confuses user.</remarks>
    const string ERR_GENERIC = "ERR_GENERIC";
    /// <summary>
    /// Sends error page
    /// </summary>
    /// <param name="context">HTTP context</param>
    /// <param name="code">Status code</param>
    /// <param name="errorHeader">Error title/header</param>
    /// <param name="errorMessage">Error text</param>
    /// <param name="errorCode">Error code for user</param>
    public static async Task SendErrorPageAsync(this HttpContext context, HttpStatusCode code = HttpStatusCode.InternalServerError, 
        string errorHeader = "Some error happened", string errorMessage = "Proxy thrown an error.\n" +
                                                                           "No additional information provided.\n\n" +
                                                                           "Contact administrator for additional help.",
        string errorCode = ERR_GENERIC)
    {
        if (errorCode == ERR_GENERIC) Log.Error($"{ERR_GENERIC} was used. This error should be used only in development.");
        Log.Information("Throwing error to client: {errorCode}",errorCode);
        try
        {
            await context.Response.SendPageAsync(await GenerateErrorPage(errorHeader, errorMessage, errorCode), code);
        }
        catch (FileNotFoundException e)
        { // TODO: why throwing here?
            Log.Error("Error page was not found. {eMessage}", e.Message);
            if (Program.IsAppDevelopment()) Log.Error(e.ToString());
            throw;
        }
        catch (Exception e)
        { // TODO: but not here????
            Log.Error(e, "Unexpected error when sending a error.");
        }
    }

    /// <summary>
    /// Generates error page
    /// </summary>
    /// <param name="errorHeader">Error title/header</param>
    /// <param name="errorMessage">Error text</param>
    /// <param name="errorCode">Error code for user</param>
    /// <returns></returns>
    private static async Task<string> GenerateErrorPage(string errorHeader, string errorMessage,
        string errorCode = ERR_GENERIC)
    {
        var fileData = await File.ReadAllTextAsync("./Pages/ErrorPage.html");
        return fileData.Replace("@errorHeader",
            errorHeader).Replace("@errorMessage",
            errorMessage.Replace("\n", "<br/>"))
            .Replace("@errorCode", errorCode);
    }

    /// <inheritdoc cref="SendErrorPageAsync(HttpContext, HttpStatusCode, string, string, string)"/>
    public static void SendErrorPage(this HttpContext context, HttpStatusCode code = HttpStatusCode.InternalServerError,
        string errorHeader = "Some error happened", string errorMessage = "Proxy thrown an error.\n" +
                                                                          "No additional information provided.\n\n" +
                                                                          "Contact administrator for additional help.",
        string errorCode = ERR_GENERIC) =>
        SendErrorPageAsync(context, code, errorHeader, errorMessage, errorCode).Wait();
}