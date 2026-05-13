namespace MACRiverProxy.Auth.MAC;

// ReSharper disable InconsistentNaming
/// <summary>
/// Interface for objects, that uses mandatory access control tag
/// </summary>
public interface IMACTag
{
    /// <summary>
    /// Hierarchical mandatory access level
    /// </summary>
    public byte MACLevel { get; set; }
    /// <summary>
    /// Non-hierarchical mandatory access category bit layer. If bit N is 1, then object have category N. Limited to 64 categories.
    /// </summary>
    public ulong MACCategory { get; set; }
}
/// <summary>
/// Static extension class for <see cref="IMACTag"/>
/// </summary>
// This class is literally bitwise magic class 
public static class MACStatic
{
    /// <summary>
    /// Sets MAC tag category
    /// </summary>
    /// <param name="mac">MAC tag object</param>
    /// <param name="number">Category number</param>
    /// <param name="state">Add or remove category</param>
    /// <exception cref="ArgumentOutOfRangeException">Category number is higher than 64.</exception>
    public static void SetMACCategory(this IMACTag mac, byte number, bool state)
    {
        if (number > 64) throw new ArgumentOutOfRangeException(nameof(number), "Maximum category number is 64.");
        if (state)
        {
            mac.MACCategory |= 1ul << number;
        }
        else
        {
            mac.MACCategory &= ~(1ul << number);
        }
    }

    /// <summary>
    /// Checks level of <see cref="IMACTag"/>
    /// </summary>
    /// <param name="mac">MAC tag object</param>
    /// <param name="level">MAC level</param>
    public static bool HaveLevel(this IMACTag mac, byte level) => mac.MACLevel >= level;

    /// <summary>
    /// Check all categories of <see cref="IMACTag"/>
    /// </summary>
    /// <param name="mac">MAC tag object</param>
    /// <param name="category">MAC category</param>
    /// <remarks>Always returns true, if <paramref name="category"/> is 0</remarks>
    public static bool HaveCategories(this IMACTag mac, ulong category)
    {
        if (category == 0) return true;
        return (mac.MACCategory & category) != 0;
    }

    /// <summary>
    /// Check single category of <see cref="IMACTag"/>
    /// </summary>
    /// <param name="mac">MAC tag object</param>
    /// <param name="number">Category number</param>
    /// <exception cref="ArgumentOutOfRangeException">Category number is higher than 64.</exception>
    public static bool HaveCategory(this IMACTag mac, byte number)
    {
        if (number > 64) throw new ArgumentOutOfRangeException(nameof(number), "Maximum category number is 64.");
        return mac.HaveCategories((1ul << number));
    }

    /// <summary>
    /// Adds single category for <see cref="IMACTag"/>
    /// </summary>
    /// <param name="mac">MAC tag object</param>
    /// <param name="number">Category number</param>
    public static void AddMACCategory(this IMACTag mac,byte number) => mac.SetMACCategory(number, true);
    /// <summary>
    /// Removes single category for <see cref="IMACTag"/>
    /// </summary>
    /// <param name="mac">MAC tag object</param>
    /// <param name="number">Category number</param>
    public static void RemoveMACCategory(this IMACTag mac,byte number) => mac.SetMACCategory(number, false);

    /// <summary>
    /// Adds level for <see cref="IMACTag"/>
    /// </summary>
    /// <param name="mac">MAC tag object</param>
    /// <param name="level">MAC level</param>
    /// <remarks>If level already higher, nothing changes.</remarks>
    public static void AddMACLevel(this IMACTag mac,byte level)
    {
        mac.MACLevel = Math.Max(level, mac.MACLevel);
    }

    /// <summary>
    /// Removes level for <see cref="IMACTag"/>
    /// </summary>
    /// <param name="mac">MAC tag object</param>
    /// <param name="level">MAC level</param>
    /// <remarks>If level already lower, nothing changes.</remarks>
    public static void RemoveMACLevel(this IMACTag mac,byte level)
    {
        mac.MACLevel = Math.Min(level, mac.MACLevel);
    }
}