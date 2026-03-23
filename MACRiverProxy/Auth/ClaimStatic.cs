using System.Security.Claims;
using System.Text.Json;

namespace MACRiverProxy.Auth;

public static class ClaimStatic
{
    public static Token ToToken(this Claim? claim)
    {
        return JsonSerializer.Deserialize<Token>(claim?.Value ?? JsonSerializer.Serialize(new NullToken()), new JsonSerializerOptions()
        {
            AllowOutOfOrderMetadataProperties = true
        })!;
    }
}