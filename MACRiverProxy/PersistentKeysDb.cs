
using Microsoft.AspNetCore.DataProtection.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace MACRiverProxy;

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

public static class PersistentKeysDbStatic
{
    public static IServiceCollection AddPersistentKeysDb(this IServiceCollection servCollection)
    {
        servCollection.AddDbContext<PersistentKeysDb>();
        return servCollection;
    }

    public static WebApplication UsePersistentKeysDb(this WebApplication app)
    {
        using var scope = app.Services.CreateScope();
        scope.ServiceProvider.GetService<PersistentKeysDb>()!.Database.Migrate();
    }
}