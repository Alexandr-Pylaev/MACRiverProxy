using System.Net;
using Serilog;
using Yarp.ReverseProxy.Forwarder;

namespace MACRiverProxy;

public static class ReverseProxyStatic
{
    public static IReverseProxyApplicationBuilder UseForwaredErrorDisplayMiddleware(this IReverseProxyApplicationBuilder proxyOpt)
    {
        proxyOpt.Use(async (context, next) =>
        {
            await next();

            var errorFeature = context.GetForwarderErrorFeature();
            if (errorFeature?.Exception == null) return;
            string header, msg;
            switch (errorFeature.Error)
            {
                case ForwarderError.NoAvailableDestinations:
                case ForwarderError.RequestTimedOut:
                case ForwarderError.Request:
                    header = "Target resource is not responding.";
                    msg = "Resource you trying to access is not responding.";
                    break;
                default:
                    header = "Failed to connect to target resource.";
                    msg =
                        "While trying to connect to target resource, error happened.\nUse error code for more info.";
                    break;
            }

            context.SendToErrorPage(HttpStatusCode.BadGateway,
                header,
                msg,
                $"ERR_{errorFeature.Error.ToString().ToUpper()}");
            Log.Error(errorFeature.Exception, $"[{context.TraceIdentifier}] Failed to redirect request.");
        });
        return proxyOpt;
    }
}