using Microsoft.EntityFrameworkCore;

namespace MACRiverProxy.Auth.LocalAuth;

public class LocalAuthStorage : DbContext
{
    public DbSet<LocalAuthUser> Users { get; set; }
    /// <summary>
    /// Path to SQLite database file
    /// </summary>
    public string DbPath { get; } = Path.Combine(Directory.GetCurrentDirectory(), "db/local-auth.db");
    protected override void OnConfiguring(DbContextOptionsBuilder options)
        => options.UseSqlite($"Data Source={DbPath}");

    public async Task<LocalAuthUser> RegisterUser(string login, string password)
    {
        LocalAuthUser user = LocalAuthUser.CreateNewUser(login, password);
        user = (await Users.AddAsync(user)).Entity;
        await SaveChangesAsync();
        return user;
    }

    public async Task<bool> DeleteUser(string login)
    {
        var user = await FindUser(login);
        if (user is null) return false;
        return await DeleteUser(user);
    }
    
    public async Task<bool> DeleteUser(LocalAuthUser user)
    {
        var result = Users.Remove(user).State == EntityState.Deleted;
        await SaveChangesAsync();
        return result;
    }

    public async Task<LocalAuthUser?> FindUser(string login)
    {
        return await Users.FindAsync(login);
    }

    public async Task<LocalAuthUser?> ChangePassword(string login, string newPassword) =>
       await ChangePassword(await FindUser(login), newPassword);
    public async Task<LocalAuthUser?> ChangePassword(LocalAuthUser? user, string newPassword)
    {
        user?.SetPassword(newPassword);
        await SaveChangesAsync();
        return user;
    }
    public async Task<bool> IsUserRegistered(LocalAuthUser? user) => user is not null && await IsUserRegistered(user.Login);
    public async Task<bool> IsUserRegistered(string login) => (await FindUser(login)) is not null;

    public async Task<bool> VerifyPassword(string login, string password) =>
        await VerifyPassword(await FindUser(login), password);
    public async Task<bool> VerifyPassword(LocalAuthUser? user, string password) =>
        await IsUserRegistered(user) && (user?.VerifyPassword(password) ?? false);
}