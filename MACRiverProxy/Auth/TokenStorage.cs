namespace MACRiverProxy.Auth;

public class TokenStorage
{
    protected List<Token> ActiveTokens = new List<Token>();

    public Token[] GetAllTokens()
    {
        lock (ActiveTokens)
        {
            return ActiveTokens.ToArray();
        }
    }

    public void RegisterToken(Token token)
    {
        lock (ActiveTokens)
        {
            ActiveTokens.Add(token);
        }
    }

    public void RevokeToken(Token token)
    {
        lock (ActiveTokens)
        {
            ActiveTokens.Remove(token);
        }
    }

    public void RegisterTokens(params Token[] tokens)
    {
        lock (ActiveTokens)
        {
            ActiveTokens.AddRange(tokens);
        }
    }

    public void RevokeTokens(params Token[] tokens)
    {
        lock (ActiveTokens)
        {
            foreach (var token in tokens)
            {
                ActiveTokens.Remove(token);
            }
        }
    }

    public bool CheckToken(Token? token)
    {
        if (token is null) return false;
        lock (ActiveTokens)
        {
            return ActiveTokens.Contains(token) && token!.VerifyToken();
        }
    }
}