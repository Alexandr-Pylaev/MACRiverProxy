using Microsoft.EntityFrameworkCore;

namespace MACRiverProxy.Auth.Tokens;

public class TokenStorage : DbContext
{
    protected DbSet<TokenKey> ActiveTokens { get; set; }
    public string DbPath { get; } = Path.Combine(Directory.GetCurrentDirectory(), "tokenstorage.db");
    protected override void OnConfiguring(DbContextOptionsBuilder options)
        => options.UseSqlite($"Data Source={DbPath}");

    public void RegisterToken(DateTime expires, Token token)
    {
        _RegisterToken(expires, token);
        this.SaveChanges();
    }

    private void _RegisterToken(DateTime expires, Token token)
    {
        TokenKey k = new TokenKey() {ExpireTime = expires};
        token.TokenKey = k;
        lock (ActiveTokens)
        {
            var ent = ActiveTokens.Add(token.TokenKey);
            token.TokenKey = ent.Entity;
        }
    }

    public void RevokeToken(Token token) => RevokeTokens([token]);
    public void RevokeToken(TokenKey token) => RevokeTokens([token]);

    public void RegisterTokens(DateTime expires, params Token[] tokens)
    {
        foreach (var token in tokens)
        {
            _RegisterToken(expires, token);
        }

        this.SaveChanges();
    }
    
    public void RevokeTokens(params TokenKey[] tokens)
    {
        lock (ActiveTokens)
        {
            foreach (var token in tokens)
            { 
                ActiveTokens.Remove(token);
            }
        }
        this.SaveChanges();
    }

    public void RevokeTokens(params Token[] tokens) => RevokeTokens(tokens.Where(x => x.TokenKey is not null).Select(x => x.TokenKey!).ToArray());

    public bool CheckToken(Token? token)
    {
        if (token is null || token == TokenProvider.Empty) return false;
        token.TokenKey ??= ActiveTokens.Find(token.Id);
        return CheckToken(token.TokenKey);
    }
    
    public bool CheckToken(TokenKey? token)
    {
        if (token is null) return false;
        lock (ActiveTokens)
        {
            return ActiveTokens.Contains(token) && token!.ExpireTime >= DateTime.Now ;
        }
    }
    /// <summary>
    /// Clean-ups all invalid tokens from storage
    /// </summary>
    public void TokenStorageCleanup()
    {
        lock (ActiveTokens)
        {
            List<TokenKey> invalidTokens = new();
            foreach (var token in ActiveTokens)
            {
                if (!CheckToken(token))invalidTokens.Add(token);
            }
            RevokeTokens(invalidTokens.ToArray());
        }
    }
}