namespace MACRiverProxy.Auth.MAC;

public interface IMAC
{
    public byte MACLevel { get; set; }
    public ulong MACCategory { get; set; }
}

public static class MAC
{
    public static void SetMACCategory(this IMAC mac, byte number, bool state)
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

    public static bool HaveLevel(this IMAC mac, byte level) => mac.MACLevel >= level;

    public static bool HaveCategories(this IMAC mac, ulong category)
    {
        if (category == 0) return true;
        return (mac.MACCategory & category) != 0;
    }

    public static bool HaveCategory(this IMAC mac, byte number)
    {
        if (number == 0) return true;
        if (number > 64) throw new ArgumentOutOfRangeException(nameof(number), "Maximum category number is 64.");
        return mac.HaveCategories((1ul << number));
    }

    public static void AddMACCategory(this IMAC mac,byte number) => mac.SetMACCategory(number, true);
    public static void RemoveMACCategory(this IMAC mac,byte number) => mac.SetMACCategory(number, false);

    public static void AddMACLevel(this IMAC mac,byte level)
    {
        if (mac.MACLevel < level) mac.MACLevel = level;
    }

    public static void RemoveMACLevel(this IMAC mac,byte level)
    {
        if (mac.MACLevel > level) mac.MACLevel = level;
    }
}