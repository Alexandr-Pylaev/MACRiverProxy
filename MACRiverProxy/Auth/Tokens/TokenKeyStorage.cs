using Microsoft.EntityFrameworkCore;

namespace MACRiverProxy.Auth.Tokens;

public class TokenKeyStorage : DbContext
{
    protected DbSet<TokenKey> ActiveTokens { get; set; }
    public string DbPath { get; } = Path.Combine(Directory.GetCurrentDirectory(), "db/tokenstorage.db");
    protected override void OnConfiguring(DbContextOptionsBuilder options)
        => options.UseSqlite($"Data Source={DbPath}");

    public async Task RegisterToken(DateTime expires, Token token)
    {
        _RegisterToken(expires, token);
        await this.SaveChangesAsync();
    }

    public IEnumerable<TokenKey> GetActiveTokenKeys => ActiveTokens;

    private void _RegisterToken(DateTime expires, Token token)
    {
        TokenKey k = new TokenKey() {ExpireTime = expires};
        token.TokenKeyEntry = k;
        var ent = ActiveTokens.Add(token.TokenKeyEntry);
        token.TokenKeyEntry = ent.Entity;
    }

    public async Task RevokeToken(Token token) => await RevokeToken([token]);
    public async Task RevokeToken(TokenKey token) => await RevokeToken([token]);

    public async Task RegisterTokens(DateTime expires, params Token[] tokens)
    {
        foreach (var token in tokens)
        {
            _RegisterToken(expires, token);
        }

        await this.SaveChangesAsync();
    }
    
    public async Task RevokeToken(params TokenKey[] tokens)
    {
        foreach (var token in tokens)
        { 
            ActiveTokens.Remove(token);
        }
        await this.SaveChangesAsync();
    }
    public async Task<int> RevokeTokens(string userIdentifier)
    {
        int count = 0;
        foreach (var token in ActiveTokens.Where(t => t.UserIdentifier == userIdentifier))
        { 
            ActiveTokens.Remove(token);
            count++;
        }
        await this.SaveChangesAsync();
        return count;
    }

    public async Task RevokeToken(params Token[] tokens) => await RevokeToken(tokens.Where(x => x.TokenKeyEntry is not null).Select(x => x.TokenKeyEntry!).ToArray());

    public async Task<bool> CheckToken(Token? token)
    {
        if (token is null || token == TokenProvider.Empty) return false;
        token.TokenKeyEntry ??= await ActiveTokens.FindAsync(token.TokenKey);
        return await CheckToken(token.TokenKeyEntry);
    }
    
    public async Task<bool> CheckToken(TokenKey? token)
    {
        if (token is null) return false;
        return await ActiveTokens.ContainsAsync(token) && token.ExpireTime >= DateTime.Now ;
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
                if (!CheckToken(token).Result)invalidTokens.Add(token);
            }
            RevokeToken(invalidTokens.ToArray()).Wait();
        }
    }
}