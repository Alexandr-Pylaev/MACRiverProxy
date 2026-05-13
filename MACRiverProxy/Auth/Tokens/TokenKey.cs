using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace MACRiverProxy.Auth.Tokens;

/// <summary>
/// Database model for storing token key and associated values
/// </summary>
public class TokenKey
{
    [Key]
    [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
    public string Key { get; init; }
    public DateTime ExpireTime { get; set; }
    /// <summary>
    /// Text, that identifies user and allow user tracking
    /// </summary>
    public string UserIdentifier { get; set; }
}