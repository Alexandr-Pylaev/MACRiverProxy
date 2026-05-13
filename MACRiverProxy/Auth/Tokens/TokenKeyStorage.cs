using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace MACRiverProxy.Auth.Tokens;

/// <summary>
/// Database context for storing token keys
/// </summary>
public class TokenKeyStorage : DbContext
{
    /// <summary>
    /// All active token keys in db
    /// </summary>
    protected DbSet<TokenKey> ActiveTokenKeys { get; set; }
    /// <summary>
    /// Path to database file
    /// </summary>
    private string DbPath { get; } = Path.Combine(Directory.GetCurrentDirectory(), "db/tokenstorage.db"); // Database is always in same folder
    protected override void OnConfiguring(DbContextOptionsBuilder options)
        => options.UseSqlite($"Data Source={DbPath}");

    /// <summary>
    /// Registers token in storage and sets it's <see cref="Token.TokenKeyModel"/>
    /// </summary>
    /// <param name="expires">Expiration date</param>
    /// <param name="token">Token</param>
    public async Task RegisterToken(DateTime expires, Token token)
    {
        _RegisterToken(expires, token);
        await this.SaveChangesAsync();
    }
    /// <summary>
    /// Register tokens in storage and sets it's <see cref="Token.TokenKeyModel"/>
    /// </summary>
    /// <param name="expires">Expiration date</param>
    /// <param name="tokens">Tokens</param>
    public async Task RegisterTokens(DateTime expires, params Token[] tokens)
    {
        foreach (var token in tokens)
        {
            _RegisterToken(expires, token);
        }

        await this.SaveChangesAsync();
    }
    /// <summary>
    /// Same as <see cref="RegisterToken"/>, but does not <see cref="DbContext.SaveChangesAsync(CancellationToken)"/>
    /// for optimisation
    /// </summary>
    private void _RegisterToken(DateTime expires, Token token)
    {
        TokenKey k = new TokenKey() {ExpireTime = expires};
        token.TokenKeyModel = k;
        var ent = ActiveTokenKeys.Add(token.TokenKeyModel);
        token.TokenKeyModel = ent.Entity; // Update key model because it is not updates on object automatically
    }
    
    /// <summary>
    /// Returns all active token keys
    /// </summary>
    public IEnumerable<TokenKey> GetActiveTokenKeys => ActiveTokenKeys;
    
    /// <summary>
    /// Revokes token's key
    /// </summary>
    /// <param name="token">Token to revoke</param>
    public async Task RevokeToken(Token token) => await RevokeToken([token]);
    /// <summary>
    /// Revokes token key
    /// </summary>
    /// <param name="token">Token key to revoke</param>
    public async Task RevokeToken(TokenKey token) => await RevokeToken([token]);
    
    /// <summary>
    /// Revoke token keys
    /// </summary>
    /// <param name="tokens">Token keys to revoke</param>
    public async Task RevokeToken(params TokenKey[] tokens)
    {
        foreach (var token in tokens)
        { 
            ActiveTokenKeys.Remove(token);
        }
        await this.SaveChangesAsync();
    }
    /// <summary>
    /// Revokes all token keys with specified <see cref="TokenKey.UserIdentifier"/> 
    /// </summary>
    /// <returns>Count of revoked keys</returns>
    /// <remarks>Can be slow because it's scans all database.</remarks>
    public async Task<int> RevokeTokenKeys(string userIdentifier)
    {
        int count = 0;
        foreach (var token in ActiveTokenKeys.Where(t => t.UserIdentifier == userIdentifier))
        { 
            ActiveTokenKeys.Remove(token);
            count++;
        }
        await this.SaveChangesAsync();
        return count;
    }
    /// <summary>
    /// Revoke tokens' keys
    /// </summary>
    /// <param name="tokens">Tokens to revoke</param>

    public async Task RevokeToken(params Token[] tokens) => await RevokeToken(tokens.Where(x => x.TokenKeyModel is not null).Select(x => x.TokenKeyModel!).ToArray());

    /// <summary>
    /// Verifies token key of token
    /// </summary>
    public async Task<bool> CheckToken(Token? token)
    {
        if (token is null || token == TokenProvider.Empty) return false;
        token.TokenKeyModel ??= await ActiveTokenKeys.FindAsync(token.TokenKey);
        return await CheckToken(token.TokenKeyModel);
    }
    /// <summary>
    /// Verifies token key
    /// </summary>
    public async Task<bool> CheckToken(TokenKey? token)
    {
        if (token is null) return false;
        return await ActiveTokenKeys.ContainsAsync(token) && token.ExpireTime >= DateTime.Now ;
    }
    /// <summary>
    /// Cleanup all invalid tokens from storage
    /// </summary>
    /// <remarks>Locks all storage tasks while doing cleanup</remarks>
    public void TokenStorageCleanup()
    {
        lock (ActiveTokenKeys)
        {
            List<TokenKey> invalidTokens = new();
            foreach (var token in ActiveTokenKeys)
            {
                if (!CheckToken(token).Result)invalidTokens.Add(token);
            }
            RevokeToken(invalidTokens.ToArray()).Wait();
        }
    }
}

public static class TokenKeyStorageStatic
{
    /// <summary>
    /// Add <see cref="TokenKeyStorage"/> to <see cref="IServiceCollection"/>
    /// </summary>
    /// <param name="col">Service collection</param>
    public static void AddTokenKeyStorage(this IServiceCollection col)
    {
        col.TryAddScoped<TokenKeyStorage>();
    }
    /// <summary>
    /// Activates <see cref="TokenKeyStorage"/>
    /// </summary>
    /// <param name="app">Web application</param>
    public static void UseTokenStorage(this WebApplication app)
    {
        using var scope = app.Services.CreateScope();
        var tokenStorage = scope.ServiceProvider.GetService<TokenKeyStorage>();
        tokenStorage?.Database.Migrate();
        tokenStorage?.TokenStorageCleanup();
    }
}