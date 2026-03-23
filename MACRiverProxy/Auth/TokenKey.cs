using System.ComponentModel.DataAnnotations;

namespace MACRiverProxy.Auth;

public class TokenKey
{
    [Key]
    public string Key { get; init; }
    public DateTime ExpireTime { get; set; }
}