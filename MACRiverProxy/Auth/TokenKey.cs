using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace MACRiverProxy.Auth;

public class TokenKey
{
    [Key]
    [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
    public string Key { get; init; }
    public DateTime ExpireTime { get; set; }
}