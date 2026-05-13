
using Microsoft.AspNetCore.DataProtection.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace MACRiverProxy;

public class PersistentKeysDb : DbContext, IDataProtectionKeyContext
{
    public DbSet<DataProtectionKey> DataProtectionKeys { get; set; }
    public string DbPath { get; } = Path.Combine(Directory.GetCurrentDirectory(), "db/persistent-keys.db");
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

    public static WebApplication UsePersistentKeysDb(this WebApplication servProvider)
    {
        using var scope = servProvider.Services.CreateScope();
        scope.ServiceProvider.GetService<PersistentKeysDb>()!.Database.Migrate();
        return servProvider;
    }
}