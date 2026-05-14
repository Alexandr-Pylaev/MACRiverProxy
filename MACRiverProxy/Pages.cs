using System.Net;
using Serilog;

namespace MACRiverProxy;
/// <summary>
/// Extensions for sending text pages
/// </summary>
public static class Pages
{
    /// <summary>
    /// Sends page, that loaded from file
    /// </summary>
    /// <param name="response">HTTP response</param>
    /// <param name="pagePath">Path to page</param>
    /// <param name="code">Status code</param>
    public static async Task SendStoredPageAsync(this HttpResponse response, string pagePath,
        HttpStatusCode code = HttpStatusCode.TemporaryRedirect)
    {
        try
        {
            await response.SendPageAsync(await File.ReadAllTextAsync(pagePath), code);
        }
        catch (FileNotFoundException e)
        { // TODO: why throwing here??
            Log.Error("Page was not found. {eMsg}", e.Message);
            if (Program.IsAppDevelopment()) Log.Error(e.ToString());
            throw;
        }
    }
    /// <summary>
    /// Sends page from string
    /// </summary>
    /// <param name="response">HTTP response</param>
    /// <param name="pageData">Page string</param>
    /// <param name="code">Status code</param>
    public static async Task SendPageAsync(this HttpResponse response, string pageData, HttpStatusCode code = HttpStatusCode.TemporaryRedirect)
    {
        response.StatusCode = (int)code;
        await response.WriteAsync(pageData);
    }
    /// <inheritdoc cref="SendStoredPageAsync(HttpResponse, string, HttpStatusCode)"/>
    public static void SendPage(this HttpResponse response, string pagePath,
        HttpStatusCode code = HttpStatusCode.TemporaryRedirect) => SendPageAsync(response, pagePath, code).Wait();
}