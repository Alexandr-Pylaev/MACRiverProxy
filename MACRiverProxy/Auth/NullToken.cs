namespace MACRiverProxy.Auth;

/// <summary>
/// Fallback token type, that represents empty or null token.
/// This shouldn't be used anywhere except when token is null or don't exist.
/// </summary>
/// <remarks>Always returns false on verify.</remarks>

public sealed class NullToken() : Token(DateTime.Now)
{
    public override bool VerifyToken() => false;
}