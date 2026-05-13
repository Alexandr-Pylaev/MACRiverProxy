using System.ComponentModel.DataAnnotations;
using MACRiverProxy.Auth.MAC;

namespace MACRiverProxy.Auth.LocalAuth;

public class LocalAuthUser : IMAC
{
    private const string PASSWORD_PEPPER = "f9gfbnd98";
    public static readonly int MAX_PASSWORD_LENGTH = 72 - (PASSWORD_PEPPER.Length);
    [Key]
    public string Login { get; set; }
    public byte MACLevel { get; set; } = 0;
    public ulong MACCategory { get; set; }= 0;
    [StringLength(60)]
    public string PasswordHash { get; protected set; }

    public static LocalAuthUser CreateNewUser(string login, string password)
    {
        var user = new LocalAuthUser()
        {
            Login = login
        };
        user.SetPassword(password);
        return user;
    }
    
    public void SetPassword(string password)
    {
        if (password.Length > MAX_PASSWORD_LENGTH)
            throw new ArgumentException($"Password is too long ({password.Length} > {MAX_PASSWORD_LENGTH})");
        PasswordHash = BCrypt.Net.BCrypt.HashPassword(_PepperPassword(password));
    }

    private static string _PepperPassword(string password)
    {
        return PASSWORD_PEPPER + password;
    }

    public bool VerifyPassword(string password)
    {
        return BCrypt.Net.BCrypt.Verify(_PepperPassword(password), PasswordHash);
    }
}