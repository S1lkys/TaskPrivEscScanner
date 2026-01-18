using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Principal;

namespace TaskPrivEscScanner
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.OutputEncoding = System.Text.Encoding.UTF8;
            
            var scanner = new ScheduledTaskScanner();
            
            Banner.Print();
            
            var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            bool isAdmin = principal.IsInRole(WindowsBuiltInRole.Administrator);
            
            ConsoleHelper.Info($"Current User: {identity.Name}");
            ConsoleHelper.Info($"Is Admin: {isAdmin}");
            ConsoleHelper.Info($"Scan started at: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            Console.WriteLine();
            
    
           var findings = scanner.Scan();

            if (findings.Count == 0 && EnvironmentChecks.WritablePaths.Count == 0)
            {
                ConsoleHelper.Success("No vulnerable scheduled tasks found.");
                return;
            }

            if (findings.Count > 0)
            {
         
                ConsoleHelper.Info("Checking for writable PATH directories...");
                EnvironmentChecks.CheckWritablePaths();
                
                if (EnvironmentChecks.WritablePaths.Count > 0)
                {
                    ConsoleHelper.WriteLineColored($"[!] Found {EnvironmentChecks.WritablePaths.Count} writable PATH directories!", 
                        EnvironmentChecks.HasWritableSystemPath ? ConsoleColor.Red : ConsoleColor.Yellow);
                }
                else
                {
                    ConsoleHelper.Success("No writable PATH directories found");
                }
                Console.WriteLine();

                
                var analyzer = new FindingsAnalyzer(findings);
                analyzer.Analyze();

                analyzer.PrintSeverityLegend();

                if (EnvironmentChecks.WritablePaths.Count > 0)
                {
                    EnvironmentChecks.PrintWritablePaths();
                }
                analyzer.PrintResults();
            }
            else
            {
                ConsoleHelper.Info("No vulnerable scheduled tasks found, but writable PATH directories exist.");
                ConsoleHelper.Info("Check for tasks using DLL search order (e.g., MareBackup) that may become exploitable.");
            }
            
            if (args.Contains("--export") || args.Contains("-e"))
            {
                string filename = $"task_findings_{DateTime.Now:yyyyMMdd_HHmmss}.csv";
                CsvExporter.Export(findings, filename);
                ConsoleHelper.Success($"Results exported to: {filename}");
            }
            
            // Print summary
            Console.WriteLine();
            if (EnvironmentChecks.HasWritableSystemPath)
            {
                ConsoleHelper.WriteLineColored("[!] WRITABLE SYSTEM PATH DETECTED - High risk for DLL hijacking attacks!", ConsoleColor.Red);
            }
            
            Console.WriteLine();
            ConsoleHelper.Info("Use --export or -e to export results to CSV");
        }
    }
    
    public static class Banner
    {
        public static void Print()
        {
            string banner = @"
╔═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╗
║                                                                                                                       ║
                                                                                                                     
▄▄▄▄▄▄▄▄▄                 ▄▄▄▄▄▄▄                   ▄▄▄▄▄▄▄              ▄▄▄▄▄▄▄                                     
▀▀▀███▀▀▀          ▄▄     ███▀▀███▄       ▀▀       ███▀▀▀▀▀             █████▀▀▀                                     
   ███  ▀▀█▄ ▄█▀▀▀ ██ ▄█▀ ███▄▄███▀ ████▄ ██ ██ ██ ███▄▄    ▄█▀▀▀ ▄████  ▀████▄  ▄████  ▀▀█▄ ████▄ ████▄ ▄█▀█▄ ████▄ 
   ███ ▄█▀██ ▀███▄ ████   ███▀▀▀▀   ██ ▀▀ ██ ██▄██ ███      ▀███▄ ██       ▀████ ██    ▄█▀██ ██ ██ ██ ██ ██▄█▀ ██ ▀▀ 
   ███ ▀█▄██ ▄▄▄█▀ ██ ▀█▄ ███       ██    ██▄ ▀█▀  ▀███████ ▄▄▄█▀ ▀████ ███████▀ ▀████ ▀█▄██ ██ ██ ██ ██ ▀█▄▄▄ ██    
                                                                                                                     
                                                                                                                     
║                                                                                                                       ║
║            Scheduled Task Privilege Escalation Scanner  v1.1                                                          ║
║                        https://github.com/S1lkys/TaskPrivEscScanner                                                   ║
╚═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╝
";
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine(banner);
            Console.ResetColor();
        }
    }
}
