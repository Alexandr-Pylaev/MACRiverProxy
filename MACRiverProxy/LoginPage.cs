using System.Net;
using Serilog;

namespace MACRiverProxy;
/// <summary>
/// Extensions for sending login page
/// </summary>
public static class LoginPage
{
    /// <summary>
    /// Sends login page
    /// </summary>
    /// <param name="response">HTTP response</param>
    /// <param name="code">Status code</param>
    public static async Task SendLoginAsync(this HttpResponse response, HttpStatusCode code = HttpStatusCode.TemporaryRedirect)
    {
        Log.Information("Sending client to login page with {code} code",code);
        await response.SendStoredPageAsync("./Pages/Login.html");
    }
    /// <inheritdoc cref="SendLoginAsync(HttpResponse, HttpStatusCode)"/>
    public static void SendLogin(this HttpResponse response,
        HttpStatusCode code = HttpStatusCode.TemporaryRedirect) => SendLoginAsync(response, code).Wait();
    /// <summary>
    /// Redirects user to login page with error
    /// </summary>
    /// <param name="response">HTTP response</param>
    /// <param name="error">Error text</param>
    public static void RedirectWithLoginError(this HttpResponse response, string error) {
        response.Redirect($"/login?error={error.EscapeCharactersForUrl()}");
    }
}