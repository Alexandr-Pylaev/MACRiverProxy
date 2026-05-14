namespace MACRiverProxy.Auth.Tokens;

/// <summary>
/// Token provider, that uses <see cref="IFormCollection"/> for creating tokens.
/// </summary>
public abstract class FormTokenProvider : TokenProvider
{
    /// <summary>
    /// Creates token from <see cref="IFormCollection"/>
    /// </summary>
    /// <param name="form">Form from <see cref="HttpRequest.Form"/> or any other forms</param>
    /// <returns>Token or <see cref="TokenProvider.Empty"/> if form does not have all info for token.</returns>
    public abstract Token CreateTokenFromForm(IFormCollection form);
}