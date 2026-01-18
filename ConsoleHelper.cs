using System;

namespace TaskPrivEscScanner
{
    public static class ConsoleHelper
    {
        public static void Critical(string message)
        {
            WriteColored("[CRITICAL] ", ConsoleColor.Red);
            Console.WriteLine(message);
        }
        
        public static void High(string message)
        {
            WriteColored("[HIGH] ", ConsoleColor.Yellow);
            Console.WriteLine(message);
        }
        
        public static void Medium(string message)
        {
            WriteColored("[MEDIUM] ", ConsoleColor.DarkYellow);
            Console.WriteLine(message);
        }
        
        public static void Low(string message)
        {
            WriteColored("[LOW] ", ConsoleColor.Cyan);
            Console.WriteLine(message);
        }
        
        public static void Info(string message)
        {
            WriteColored("[*] ", ConsoleColor.Cyan);
            Console.WriteLine(message);
        }
        
        public static void Success(string message)
        {
            WriteColored("[+] ", ConsoleColor.Green);
            Console.WriteLine(message);
        }
        
        public static void Error(string message)
        {
            WriteColored("[-] ", ConsoleColor.Red);
            Console.WriteLine(message);
        }
        
        public static void WriteColored(string text, ConsoleColor color)
        {
            Console.ForegroundColor = color;
            Console.Write(text);
            Console.ResetColor();
        }
        
        public static void WriteLineColored(string text, ConsoleColor color)
        {
            Console.ForegroundColor = color;
            Console.WriteLine(text);
            Console.ResetColor();
        }
        
        public static void PrintHeader(string title, ConsoleColor color = ConsoleColor.Cyan)
        {
            string separator = new string('═', 80);
            Console.WriteLine();
            WriteLineColored(separator, color);
            WriteLineColored($"  {title}", color);
            WriteLineColored(separator, color);
            Console.WriteLine();
        }
        
        public static void PrintSubHeader(string title)
        {
            string separator = new string('─', 76);
            Console.WriteLine();
            WriteLineColored($"  {separator}", ConsoleColor.DarkGray);
            WriteLineColored($"  {title}", ConsoleColor.White);
            WriteLineColored($"  {separator}", ConsoleColor.DarkGray);
        }
        
        public static void PrintKeyValue(string key, string value, ConsoleColor valueColor = ConsoleColor.White, int keyWidth = 20)
        {
            Console.Write($"    {key.PadRight(keyWidth)}: ");
            WriteLineColored(value, valueColor);
        }
        
        public static void PrintBox(string[] lines, ConsoleColor borderColor = ConsoleColor.DarkGray)
        {
            int maxLen = 0;
            foreach (var line in lines)
                if (line.Length > maxLen) maxLen = line.Length;
            
            maxLen += 4;
            
            WriteLineColored("    ┌" + new string('─', maxLen) + "┐", borderColor);
            foreach (var line in lines)
            {
                WriteColored("    │ ", borderColor);
                Console.Write(line.PadRight(maxLen - 2));
                WriteLineColored(" │", borderColor);
            }
            WriteLineColored("    └" + new string('─', maxLen) + "┘", borderColor);
        }
    }
}
