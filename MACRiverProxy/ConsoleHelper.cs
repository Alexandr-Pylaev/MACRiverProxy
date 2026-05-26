using Serilog;

namespace MACRiverProxy;
/// <summary>
/// Helper class for console
/// </summary>
public static class ConsoleHelper
{
    /// <summary>
    /// Hiddenly reads user input
    /// </summary>
    /// <returns>Read input</returns>
    public static string HiddenRead()
    {
        string input = string.Empty;
        ConsoleKey key;
        do
        {
            var keyInfo = Console.ReadKey(intercept: true);
            key = keyInfo.Key;

            if (key == ConsoleKey.Backspace && input.Length > 0)
            {
                Console.Write("\b \b");
                input = input[0..^1];
            }
            else if (!char.IsControl(keyInfo.KeyChar))
            {
                Console.Write("*");
                input += keyInfo.KeyChar;
            }
        } while (key != ConsoleKey.Enter);

        return input;
    }
    /// <summary>
    /// Prevents user from executing until user enters Y
    /// </summary>
    /// <param name="text">Message to user</param>
    /// <returns>Is user entered Y</returns>
    public static bool AccidentalExecutionPrevention(string text)
    {
        Log.Warning($"Attention! {text}");
        Log.Warning("Do you really want to proceed? (y/N)");
        while (true)
        {
            string? response = Console.ReadLine()?.ToLower();
            Log.Information("User entered {response}", response);
            if (response is ("y" or "n" or "" or null)) return response is "y";
            Log.Information("Y or N.");
        }
    }
}