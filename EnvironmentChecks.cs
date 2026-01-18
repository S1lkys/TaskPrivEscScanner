using System;
using System.Collections.Generic;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;

namespace TaskPrivEscScanner
{
    public class WritablePathInfo
    {
        public string Path { get; set; } = "";
        public string WritableBy { get; set; } = "";
        public bool IsSystemPath { get; set; } = false;
        public int PathIndex { get; set; } = -1;
        public bool IsBeforePowerShell { get; set; } = false;
    }
    
    public static class EnvironmentChecks
    {
        private static readonly HashSet<string> _lowPrivSids = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "S-1-1-0", "S-1-5-11", "S-1-5-32-545", "S-1-5-4",
            "WD", "AU", "BU", "IU"
        };
        
        public static List<WritablePathInfo> WritablePaths { get; private set; } = new List<WritablePathInfo>();
        public static bool HasWritableSystemPath => WritablePaths.Exists(p => p.IsSystemPath);
        public static bool HasWritablePathBeforePowerShell => WritablePaths.Exists(p => p.IsSystemPath && p.IsBeforePowerShell);
        public static int PowerShellPathIndex { get; private set; } = -1;
        
        public static void CheckWritablePaths()
        {
            WritablePaths.Clear();
            PowerShellPathIndex = -1;
            
            // Get system PATH (from Machine environment)
            string systemPath = Environment.GetEnvironmentVariable("PATH", EnvironmentVariableTarget.Machine) ?? "";
            var systemDirs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            
            // Find PowerShell path index
            string[] systemPathEntries = systemPath.Split(';');
            for (int i = 0; i < systemPathEntries.Length; i++)
            {
                string entry = Environment.ExpandEnvironmentVariables(systemPathEntries[i].Trim());
                systemDirs.Add(entry);
                
                // Check for PowerShell path
                if (entry.IndexOf("WindowsPowerShell", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    entry.IndexOf("PowerShell", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    if (PowerShellPathIndex == -1)
                        PowerShellPathIndex = i;
                }
            }
            
            // Get full PATH (Machine + User)
            string fullPath = Environment.GetEnvironmentVariable("PATH") ?? "";
            string[] pathEntries = fullPath.Split(';');
            
            for (int i = 0; i < pathEntries.Length; i++)
            {
                string trimmed = pathEntries[i].Trim();
                if (string.IsNullOrEmpty(trimmed))
                    continue;
                
                string expandedDir = Environment.ExpandEnvironmentVariables(trimmed);
                
                if (!Directory.Exists(expandedDir))
                    continue;
                
                var writableInfo = CheckDirectoryWritable(expandedDir);
                if (writableInfo != null)
                {
                    writableInfo.IsSystemPath = systemDirs.Contains(expandedDir);
                    writableInfo.PathIndex = i;
                    
                    // Check if this writable path comes before PowerShell
                    if (writableInfo.IsSystemPath && PowerShellPathIndex > 0)
                    {
                        // Find this path's index in system PATH
                        for (int j = 0; j < systemPathEntries.Length; j++)
                        {
                            string sysEntry = Environment.ExpandEnvironmentVariables(systemPathEntries[j].Trim());
                            if (sysEntry.Equals(expandedDir, StringComparison.OrdinalIgnoreCase))
                            {
                                writableInfo.IsBeforePowerShell = j < PowerShellPathIndex;
                                break;
                            }
                        }
                    }
                    
                    WritablePaths.Add(writableInfo);
                }
            }
        }
        
        private static WritablePathInfo CheckDirectoryWritable(string path)
        {
            const FileSystemRights WriteDataBit = (FileSystemRights)0x00000002;
            const FileSystemRights AppendDataBit = (FileSystemRights)0x00000004;
            
            try
            {
                var acl = Directory.GetAccessControl(path);
                
                foreach (FileSystemAccessRule rule in acl.GetAccessRules(true, true, typeof(SecurityIdentifier)))
                {
                    if (rule.AccessControlType != AccessControlType.Allow)
                        continue;
                    
                    FileSystemRights rights = rule.FileSystemRights;
                    
                    bool canWrite = (rights & WriteDataBit) != 0 ||
                                    (rights & AppendDataBit) != 0 ||
                                    (rights & FileSystemRights.FullControl) == FileSystemRights.FullControl ||
                                    (rights & FileSystemRights.Modify) == FileSystemRights.Modify;
                    
                    if (!canWrite)
                        continue;
                    
                    string sid = rule.IdentityReference.Value;
                    bool isLowPriv = _lowPrivSids.Contains(sid);
                    
                    string accountName = "";
                    if (!isLowPriv)
                    {
                        try
                        {
                            var account = (NTAccount)rule.IdentityReference.Translate(typeof(NTAccount));
                            accountName = account.Value.ToUpperInvariant();
                            
                            isLowPriv = accountName.Contains("EVERYONE") ||
                                        accountName.Contains("JEDER") ||
                                        accountName.Contains("\\USERS") ||
                                        accountName.Contains("\\BENUTZER") ||
                                        accountName.Contains("AUTHENTICATED") ||
                                        accountName.Contains("AUTHENTIFIZIERT") ||
                                        accountName.Contains("INTERACTIVE") ||
                                        accountName.Contains("INTERAKTIV");
                        }
                        catch { }
                    }
                    
                    if (isLowPriv)
                    {
                        if (string.IsNullOrEmpty(accountName))
                        {
                            try
                            {
                                var account = (NTAccount)rule.IdentityReference.Translate(typeof(NTAccount));
                                accountName = account.Value;
                            }
                            catch
                            {
                                accountName = sid;
                            }
                        }
                        
                        return new WritablePathInfo
                        {
                            Path = path,
                            WritableBy = accountName
                        };
                    }
                }
            }
            catch { }
            
            return null;
        }
        
        public static void PrintWritablePaths()
        {
            if (WritablePaths.Count == 0)
            {
                ConsoleHelper.Success("No writable PATH directories found");
                return;
            }
            
            var systemPaths = WritablePaths.FindAll(p => p.IsSystemPath);
            var userPaths = WritablePaths.FindAll(p => !p.IsSystemPath);
            
            if (systemPaths.Count > 0)
            {
                ConsoleHelper.PrintHeader("CRITICAL: WRITABLE SYSTEM PATH DIRECTORIES", ConsoleColor.Red);
                Console.WriteLine("  These directories are in the SYSTEM PATH and writable by low-privileged users.");
                Console.WriteLine("  This enables DLL hijacking for ANY process that searches PATH for DLLs.");
                Console.WriteLine("  Combined with MareBackup task, this is a direct privilege escalation vector.");
                Console.WriteLine();
                Console.WriteLine("  Reference: https://itm4n.github.io/windows-dll-hijacking-clarified/");
                Console.WriteLine();
                
                foreach (var pathInfo in systemPaths)
                {
                    ConsoleHelper.WriteColored($"    [!] ", ConsoleColor.Red);
                    Console.WriteLine(pathInfo.Path);
                    ConsoleHelper.WriteColored($"        Writable By: ", ConsoleColor.Yellow);
                    Console.WriteLine(pathInfo.WritableBy);
                }
                Console.WriteLine();
            }
            
            if (userPaths.Count > 0)
            {
                ConsoleHelper.PrintHeader("INFO: WRITABLE USER PATH DIRECTORIES", ConsoleColor.Yellow);
                Console.WriteLine("  These directories are in the USER PATH and writable.");
                Console.WriteLine("  May be useful for user-level DLL hijacking.");
                Console.WriteLine();
                
                foreach (var pathInfo in userPaths)
                {
                    ConsoleHelper.WriteColored($"    [*] ", ConsoleColor.Yellow);
                    Console.WriteLine(pathInfo.Path);
                    ConsoleHelper.WriteColored($"        Writable By: ", ConsoleColor.Gray);
                    Console.WriteLine(pathInfo.WritableBy);
                }
                Console.WriteLine();
            }
        }
    }
}
