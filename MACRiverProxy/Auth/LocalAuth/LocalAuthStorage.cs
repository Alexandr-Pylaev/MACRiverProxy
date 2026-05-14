using Microsoft.EntityFrameworkCore;

namespace MACRiverProxy.Auth.LocalAuth;
/// <summary>
/// Storage for registered <see cref="LocalAuthUser"/>
/// </summary>
public class LocalAuthStorage : DbContext
{
    /// <summary>
    /// All registered <see cref="LocalAuthUser"/>
    /// </summary>
    public DbSet<LocalAuthUser> Users { get; set; }
    /// <summary>
    /// Path to SQLite database file
    /// </summary>
    private string DbPath { get; } = Path.Combine(Directory.GetCurrentDirectory(), "db/local-auth.db");
    protected override void OnConfiguring(DbContextOptionsBuilder options)
        => options.UseSqlite($"Data Source={DbPath}");

    /// <summary>
    /// Creates new registered <see cref="LocalAuthUser"/>
    /// </summary>
    /// <param name="login">Login</param>
    /// <param name="password">Password</param>
    /// <returns>New registered <see cref="LocalAuthUser"/></returns>
    public async Task<LocalAuthUser> RegisterUser(string login, string password)
    {
        LocalAuthUser user = LocalAuthUser.CreateNewUser(login, password);
        user = (await Users.AddAsync(user)).Entity;
        await SaveChangesAsync(); // always save changes when changing user
        return user;
    }

    /// <summary>
    /// Deletes user by login
    /// </summary>
    /// <param name="login">Login</param>
    /// <returns>If user was found and deleted</returns>
    public async Task<bool> DeleteUser(string login)
    {
        var user = await FindUser(login);
        if (user is null) return false;
        return await DeleteUser(user);
    }
    
    /// <summary>
    /// Deletes registered <see cref="LocalAuthUser"/>
    /// </summary>
    /// <param name="user">Registered user</param>
    /// <returns>If user was deleted from storage</returns>
    public async Task<bool> DeleteUser(LocalAuthUser user)
    {
        var result = Users.Remove(user).State == EntityState.Deleted;
        await SaveChangesAsync();
        return result;
    }

    /// <summary>
    /// Finds user by login
    /// </summary>
    /// <param name="login">Login</param>
    /// <returns><see cref="LocalAuthUser"/> or null if not found</returns>
    public async Task<LocalAuthUser?> FindUser(string login)
    {
        return await Users.FindAsync(login);
    }

    /// <summary>
    /// Changes password for user
    /// </summary>
    /// <param name="login">Login of user</param>
    /// <param name="newPassword">New password</param>
    /// <returns>Updated <see cref="LocalAuthUser"/> or null if not registered.</returns>
    public async Task<LocalAuthUser?> ChangePassword(string login, string newPassword) =>
       await ChangePassword(await FindUser(login), newPassword);
    /// <summary>
    /// <inheritdoc cref="ChangePassword(string, string)"/>
    /// </summary>
    /// <param name="user"><inheritdoc cref="ChangePassword(string, string)"/></param>
    /// <param name="newPassword">New password</param>
    /// <returns><inheritdoc cref="ChangePassword(string, string)"/></returns>
    public async Task<LocalAuthUser?> ChangePassword(LocalAuthUser? user, string newPassword)
    {
        user?.SetPassword(newPassword);
        await SaveChangesAsync();
        return user;
    }
    /// <summary>
    /// Checks if user is registered
    /// </summary>
    /// <param name="user">User</param>
    /// <returns>Is user registered</returns>
    public async Task<bool> IsUserRegistered(LocalAuthUser? user) => user is not null && await IsUserRegistered(user.Login);
    /// <summary>
    /// <inheritdoc cref="IsUserRegistered(LocalAuthUser?)"/>
    /// </summary>
    /// <param name="login">Login of user</param>
    /// <returns><inheritdoc cref="IsUserRegistered(LocalAuthUser?)"/></returns>
    public async Task<bool> IsUserRegistered(string login) => (await FindUser(login)) is not null;

    /// <summary>
    /// Verifies user password
    /// </summary>
    /// <param name="login">Login of user</param>
    /// <param name="password">Password</param>
    /// <returns>Is user registered and is password valid</returns>
    public async Task<bool> VerifyPassword(string login, string password) =>
        await VerifyPassword(await FindUser(login), password);
    /// <summary>
    /// <inheritdoc cref="VerifyPassword(string, string)"/>
    /// </summary>
    /// <param name="user">User</param>
    /// <param name="password">Password</param>
    /// <returns><inheritdoc cref="VerifyPassword(string, string)"/></returns>
    public async Task<bool> VerifyPassword(LocalAuthUser? user, string password) =>
        await IsUserRegistered(user) && (user?.VerifyPassword(password) ?? false);
}