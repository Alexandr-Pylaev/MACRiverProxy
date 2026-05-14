using System.Net;
using Serilog;
using Yarp.ReverseProxy.Forwarder;

namespace MACRiverProxy;
/// <summary>
/// Extension class for YARP proxying
/// </summary>
public static class ReverseProxyStatic
{
    /// <summary>
    /// Gets return URL from request URL.
    /// </summary>
    /// <param name="request">Request</param>
    /// <returns>Value of ReturnURL query</returns>
    public static string GetRedirectUrl(this HttpRequest request)
    {
        if (request.Query.TryGetValue("ReturnURL", out var returnUrl))
        {
            return returnUrl!;
        }

        return "/";
    }
    /// <summary>
    /// Redirects <see cref="HttpContext.Response"/> to ReturnURL value.
    /// </summary>
    /// <param name="context">Http context</param>
    public static void RedirectToRedirectUrl(this HttpContext context)
    {
        context.Response.Redirect(context.Request.GetRedirectUrl());
    }
    /// <summary>
    /// Adds failed proxying error display middleware.
    /// </summary>
    /// <param name="proxyOpt">Proxy options</param>
    /// <returns><paramref name="proxyOpt"/></returns>
    public static IReverseProxyApplicationBuilder UseProxyingErrorDisplayMiddleware(this IReverseProxyApplicationBuilder proxyOpt)
    {
        proxyOpt.Use(async (context, next) =>
        {
            // Awaiting when other middlewares finishes
            await next();
            // Gets YARP ForwarderErrorFeature, that contains proxying error
            var errorFeature = context.GetForwarderErrorFeature();
            if (errorFeature?.Exception == null) return;
            string header, msg;
            switch (errorFeature.Error)
            {   // Resource is not responding
                case ForwarderError.RequestTimedOut:
                case ForwarderError.Request:
                    header = "Target resource is not responding.";
                    msg = "Resource you trying to access is not responding.";
                    break;
                case ForwarderError.NoAvailableDestinations: 
                    header = "Resource is not available.";
                    msg = "Resource you trying to access is not available.";
                    break;
                // Default response
                default:
                    header = "Failed to connect to target resource.";
                    msg =
                        "While trying to connect to target resource, error happened.\nUse error code for more info.";
                    break;
            }
            // Send user error page with proxying error
            await context.SendErrorPageAsync(HttpStatusCode.BadGateway,
                header,
                msg,
                $"ERR_{errorFeature.Error.ToString().ToUpper()}");
            Log.Error(errorFeature.Exception, "[{traceIdentifier}] Failed to redirect request.", context.TraceIdentifier);
        });
        return proxyOpt;
    }
    /// <summary>
    /// Escapes spaces with %20
    /// </summary>
    /// <param name="text">Original text</param>
    /// <returns>Escaped text</returns>
    public static string EscapeCharactersForUrl(this string text)
    {
        return text.Replace(" ", "%20");
    }
}