using System;
using System.Collections.Generic;

namespace TaskPrivEscScanner
{
    public enum Severity
    {
        Info = 0,
        Low = 1,
        Medium = 2,
        High = 3,
        Critical = 4
    }
    
    public class TaskAction
    {
        // Action type
        public string ActionType { get; set; } = "Exec";  // "Exec" or "ComHandler"
        
        // Exec action fields
        public string Path { get; set; } = "";
        public string Arguments { get; set; } = "";
        public string WorkingDirectory { get; set; } = "";
        
        public bool BinaryExists { get; set; } = true;
        public bool BinaryWritable { get; set; } = false;
        public bool ParentDirWritable { get; set; } = false;
        public string WritableBy { get; set; } = "";
        
        // COM Handler action fields
        public string ComClassId { get; set; } = "";
        public string ComProgId { get; set; } = "";
        public string ComData { get; set; } = "";
        public string ComServerPath { get; set; } = "";
        public string ComServerType { get; set; } = "";
        
        public bool ComDllMissing { get; set; } = false;
        public bool ComDllWritable { get; set; } = false;
        public bool ComDllParentWritable { get; set; } = false;
        public string ComDllWritableBy { get; set; } = "";
        
        public string FullCommand => ActionType == "Exec" 
            ? (string.IsNullOrEmpty(Arguments) ? Path : $"{Path} {Arguments}")
            : $"COM: {ComClassId}";
        
        public override string ToString() => FullCommand;
    }
    
    public class TaskFinding
    {
        public string TaskPath { get; set; } = "";
        public string TaskName => System.IO.Path.GetFileName(TaskPath);
        public string TaskFolder => System.IO.Path.GetDirectoryName(TaskPath)?.Replace("\\", "/") ?? "/";
        
        public string RunAsUser { get; set; } = "";
        public bool RunsElevated { get; set; } = false;
        public bool RunsAsSystem { get; set; } = false;
        public bool RunsAsAdmin { get; set; } = false;
        
        public string TaskState { get; set; } = "";
        public string SDDL { get; set; } = "";
        
        public List<string> StartableBy { get; set; } = new List<string>();
        public List<TaskAction> Actions { get; set; } = new List<TaskAction>();
        
        public Severity Severity { get; set; } = Severity.Info;
        public List<string> Issues { get; set; } = new List<string>();
        public List<string> ExploitSteps { get; set; } = new List<string>();
        
        // MareBackup specific flags
        public bool IsMareBackupTask { get; set; } = false;
        public bool IsMareBackupWithWritablePath { get; set; } = false;
        
        public string StartCommand => $"schtasks /run /tn \"{TaskPath}\"";
        public string InfoCommand => $"schtasks /query /tn \"{TaskPath}\" /v /fo list";
        
        public string PrivilegeContext
        {
            get
            {
                var parts = new List<string>();
                if (RunsAsSystem) parts.Add("SYSTEM");
                if (RunsAsAdmin) parts.Add("Administrator");
                if (RunsElevated) parts.Add("Elevated");
                return parts.Count > 0 ? string.Join(", ", parts) : "Standard";
            }
        }
    }
    
    public static class SeverityDescriptions
    {
        public static Dictionary<Severity, SeverityInfo> Info = new Dictionary<Severity, SeverityInfo>
        {
            {
                Severity.Critical, new SeverityInfo
                {
                    Name = "CRITICAL",
                    Color = ConsoleColor.Red,
                    Description = "Immediate privilege escalation possible",
                    Explanation = "The scheduled task runs with elevated privileges (SYSTEM/Admin) and either:\n" +
                                  "  - The executed binary is missing and the parent directory is writable, OR\n" +
                                  "  - The executed binary itself is writable by low-privileged users\n\n" +
                                  "This allows an attacker to replace/create the binary with a malicious payload\n" +
                                  "that will be executed with high privileges when the task runs.",
                    Exploitation = "1. Identify the missing/writable binary path\n" +
                                   "2. Create/replace the binary with your payload (e.g., reverse shell, add user)\n" +
                                   "3. Trigger the task manually or wait for scheduled execution\n" +
                                   "4. Payload executes with SYSTEM/Admin privileges"
                }
            },
            {
                Severity.High, new SeverityInfo
                {
                    Name = "HIGH",
                    Color = ConsoleColor.Yellow,
                    Description = "SYSTEM-level task can be triggered by low-priv users",
                    Explanation = "The scheduled task runs as NT AUTHORITY\\SYSTEM and can be manually started\n" +
                                  "by unprivileged users (Everyone, Authenticated Users, Users, Interactive).\n\n" +
                                  "While the binary itself may not be directly exploitable, this could be\n" +
                                  "combined with other vulnerabilities (DLL hijacking, argument injection,\n" +
                                  "race conditions) for privilege escalation.",
                    Exploitation = "1. Analyze the executed binary for DLL hijacking opportunities\n" +
                                   "2. Check if arguments are controllable or injectable\n" +
                                   "3. Look for race conditions in file operations\n" +
                                   "4. Trigger task with: schtasks /run /tn \"<TaskPath>\"\n" +
                                   "5. Exploit secondary vulnerability during execution"
                }
            },
            {
                Severity.Medium, new SeverityInfo
                {
                    Name = "MEDIUM",
                    Color = ConsoleColor.DarkYellow,
                    Description = "Elevated task can be triggered by low-priv users",
                    Explanation = "The scheduled task runs with elevated privileges (HighestAvailable) and can\n" +
                                  "be manually started by unprivileged users.\n\n" +
                                  "Depending on the RunAs user context, this may allow elevation from standard\n" +
                                  "user to administrator level. Requires further analysis of the executed\n" +
                                  "commands and potential attack vectors.",
                    Exploitation = "1. Identify the actual privilege level when triggered\n" +
                                   "2. Analyze executed commands for injection points\n" +
                                   "3. Check for DLL search order hijacking\n" +
                                   "4. Look for writable paths in the execution chain\n" +
                                   "5. Trigger and observe behavior with Process Monitor"
                }
            },
            {
                Severity.Low, new SeverityInfo
                {
                    Name = "LOW",
                    Color = ConsoleColor.Cyan,
                    Description = "Task with permissive ACLs, limited impact",
                    Explanation = "The scheduled task has overly permissive access controls but the security\n" +
                                  "impact is limited due to the execution context or task configuration.\n\n" +
                                  "May still be useful for persistence or lateral movement scenarios.",
                    Exploitation = "1. Review task configuration for persistence opportunities\n" +
                                   "2. Check if task can be modified to run custom commands\n" +
                                   "3. Consider for maintaining access in post-exploitation"
                }
            }
        };
    }
    
    public class SeverityInfo
    {
        public string Name { get; set; } = "";
        public ConsoleColor Color { get; set; }
        public string Description { get; set; } = "";
        public string Explanation { get; set; } = "";
        public string Exploitation { get; set; } = "";
    }
}
