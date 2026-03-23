using System.Security.Claims;
using System.Text.Json;

namespace MACRiverProxy.Auth;

public static class ClaimStatic
{
    public static Token ToToken(this Claim? claim)
    {
        try
        {
            return JsonSerializer.Deserialize<Token>(claim?.Value ?? JsonSerializer.Serialize(NullTokenProvider.CreateNull()),
                new JsonSerializerOptions()
                {
                    AllowOutOfOrderMetadataProperties = true
                })!;
        }
        catch (JsonException _)
        {
            return NullTokenProvider.CreateNull();
        }
    }
}