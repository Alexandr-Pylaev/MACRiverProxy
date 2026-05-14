
using Microsoft.AspNetCore.DataProtection.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace MACRiverProxy;
/// <summary>
/// <see cref="DbContext"/> for storing data protection keys 
/// </summary>
public class PersistentKeysDb : DbContext, IDataProtectionKeyContext
{
    public DbSet<DataProtectionKey> DataProtectionKeys { get; set; }
    /// <summary>
    /// Path to SQLite database file
    /// </summary>
    private string DbPath { get; } = Path.Combine(Directory.GetCurrentDirectory(), "db/persistent-keys.db");
    protected override void OnConfiguring(DbContextOptionsBuilder options)
        => options.UseSqlite($"Data Source={DbPath}");
}
/// <summary>
/// Extension for adding <see cref="PersistentKeysDb"/>
/// </summary>
public static class PersistentKeysDbStatic
{
    /// <summary>
    /// Adds <see cref="PersistentKeysDb"/> to <see cref="IServiceCollection"/>
    /// </summary>
    /// <param name="servCollection">The <see cref="IServiceCollection"/> to add services to.</param>
    /// <returns><paramref name="servCollection"/></returns>
    public static IServiceCollection AddPersistentKeysDb(this IServiceCollection servCollection)
    {
        servCollection.AddDbContext<PersistentKeysDb>();
        return servCollection;
    }

    /// <summary>
    /// Enables <see cref="PersistentKeysDb"/> in <see cref="WebApplication"/>
    /// </summary>
    /// <param name="app">Web app</param>
    /// <returns><paramref name="app"/></returns>
    public static WebApplication UsePersistentKeysDb(this WebApplication app)
    {
        using var scope = app.Services.CreateScope();
        scope.ServiceProvider.GetService<PersistentKeysDb>()!.Database.Migrate();
        return app;
    }
}