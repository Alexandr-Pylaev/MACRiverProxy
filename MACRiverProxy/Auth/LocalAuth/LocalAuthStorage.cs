using Microsoft.EntityFrameworkCore;

namespace MACRiverProxy.Auth.LocalAuth;

public class LocalAuthStorage : DbContext
{
    public DbSet<LocalAuthUser> Users { get; set; }
    public string DbPath { get; } = Path.Combine(Directory.GetCurrentDirectory(), "local-auth.db");
    protected override void OnConfiguring(DbContextOptionsBuilder options)
        => options.UseSqlite($"Data Source={DbPath}");
}