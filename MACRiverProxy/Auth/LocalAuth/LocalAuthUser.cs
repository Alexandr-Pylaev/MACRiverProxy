using System.ComponentModel.DataAnnotations;
using MACRiverProxy.Auth.MAC;

namespace MACRiverProxy.Auth.LocalAuth;

/// <summary>
/// User model for <see cref="LocalAuthTokenProvider"/>
/// </summary>
public class LocalAuthUser : IMACTag
{
    /// <summary>
    /// Password pepper
    /// </summary>
    /// <remarks>Always add pepper to password for more security.</remarks>
    private const string PASSWORD_PEPPER = "f9gfbnd98";
    /// <summary>
    /// Maximum password lenght. Required because BCrypt does not support more than 72 symbols - pepper.
    /// </summary>
    public static readonly int MAX_PASSWORD_LENGTH = 72 - (PASSWORD_PEPPER.Length);
    /// <summary>
    /// User login, also, a primary key.
    /// </summary>
    [Key]
    public string Login { get; set; }
    public byte MACLevel { get; set; } = 0;
    public ulong MACCategory { get; set; }= 0;
    /// <summary>
    /// Password BCrypt hash. Limited to 60 characters.
    /// </summary>
    [StringLength(60)]
    public string PasswordHash { get; protected set; }

    /// <summary>
    /// Creates new <see cref="LocalAuthUser"/> user.
    /// </summary>
    /// <param name="login">User login</param>
    /// <param name="password">User password</param>
    /// <returns>New unregistered user.</returns>
    public static LocalAuthUser CreateNewUser(string login, string password)
    {
        var user = new LocalAuthUser()
        {
            Login = login
        };
        user.SetPassword(password);
        return user;
    }
    /// <summary>
    /// Sets new password for user.
    /// </summary>
    /// <param name="password">New password</param>
    /// <exception cref="ArgumentException">Password is longer than <see cref="MAX_PASSWORD_LENGTH"/></exception>
    public void SetPassword(string password)
    {
        if (password.Length > MAX_PASSWORD_LENGTH)
            throw new ArgumentException($"Password is too long ({password.Length} > {MAX_PASSWORD_LENGTH})");
        PasswordHash = BCrypt.Net.BCrypt.HashPassword(_PepperPassword(password));
    }

    /// <summary>
    /// Peppers password
    /// </summary>
    /// <param name="password">Password</param>
    /// <returns>Peppered password</returns>
    private static string _PepperPassword(string password)
    {
        return PASSWORD_PEPPER + password;
    }

    /// <summary>
    /// Verifies password for this user
    /// </summary>
    /// <param name="password">Password</param>
    /// <returns>Is password is the same</returns>
    public bool VerifyPassword(string password)
    {
        return BCrypt.Net.BCrypt.Verify(_PepperPassword(password), PasswordHash);
    }
}