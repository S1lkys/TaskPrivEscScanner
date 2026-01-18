using System;
using System.Collections.Generic;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.RegularExpressions;

namespace TaskPrivEscScanner
{
    public class ScheduledTaskScanner
    {
        private readonly HashSet<string> _privilegedUsers = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "NT AUTHORITY\\SYSTEM",
            "SYSTEM",
            "S-1-5-18",
            "NT AUTHORITY\\LOCAL SERVICE",
            "LOCAL SERVICE",
            "S-1-5-19",
            "NT AUTHORITY\\NETWORK SERVICE",
            "NETWORK SERVICE",
            "S-1-5-20",
            "BUILTIN\\Administrators",
            "S-1-5-32-544"
        };
        
        private readonly Dictionary<string, string> _sidToName = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            { "S-1-1-0", "Everyone" },
            { "S-1-5-11", "Authenticated Users" },
            { "S-1-5-32-545", "BUILTIN\\Users" },
            { "S-1-5-4", "Interactive" },
            { "WD", "Everyone" },
            { "AU", "Authenticated Users" },
            { "BU", "BUILTIN\\Users" },
            { "IU", "Interactive" },
            { "S-1-5-32-544", "BUILTIN\\Administrators" },
            { "BA", "BUILTIN\\Administrators" }
        };
        
        private readonly HashSet<string> _lowPrivSids = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "S-1-1-0", "S-1-5-11", "S-1-5-32-545", "S-1-5-4",
            "WD", "AU", "BU", "IU"
        };
        
        public List<TaskFinding> Scan()
        {
            var findings = new List<TaskFinding>();
            
            try
            {
                // Use dynamic COM interop for reliability
                Type schedulerType = Type.GetTypeFromProgID("Schedule.Service");
                if (schedulerType == null)
                {
                    ConsoleHelper.Error("Task Scheduler COM object not found");
                    return findings;
                }
                
                dynamic scheduler = Activator.CreateInstance(schedulerType);
                scheduler.Connect();
                
                dynamic rootFolder = scheduler.GetFolder("\\");
                int totalTasks = 0;
                
                ScanFolder(rootFolder, findings, ref totalTasks);
                
                ConsoleHelper.Info($"Scanned {totalTasks} scheduled tasks");
                ConsoleHelper.Info($"Found {findings.Count} potentially vulnerable tasks");
            }
            catch (Exception ex)
            {
                ConsoleHelper.Error($"Failed to connect to Task Scheduler: {ex.Message}");
            }
            
            return findings;
        }
        
        private void ScanFolder(dynamic folder, List<TaskFinding> findings, ref int totalTasks)
        {
            try
            {
                // Enumerate tasks
                foreach (dynamic task in folder.GetTasks(0))
                {
                    try
                    {
                        totalTasks++;
                        var finding = AnalyzeTask(task);
                        if (finding != null)
                        {
                            findings.Add(finding);
                        }
                    }
                    catch { }
                }
                
                // Recurse into subfolders
                foreach (dynamic subfolder in folder.GetFolders(0))
                {
                    try
                    {
                        ScanFolder(subfolder, findings, ref totalTasks);
                    }
                    catch { }
                }
            }
            catch { }
        }
        
        private TaskFinding AnalyzeTask(dynamic task)
        {
            try
            {
                dynamic definition = task.Definition;
                dynamic principal = definition.Principal;
                
                string runAs = "";
                try { runAs = principal.UserId ?? ""; } catch { }
                
                int runLevel = 0;
                try { runLevel = (int)principal.RunLevel; } catch { }
                bool runsElevated = runLevel == 1; // TASK_RUNLEVEL_HIGHEST
                
                bool isPrivilegedTask = false;
                bool runsAsSystem = false;
                bool runsAsAdmin = false;
                
                // Check if runs as privileged user
                foreach (var privUser in _privilegedUsers)
                {
                    if (!string.IsNullOrEmpty(runAs) && 
                        (runAs.IndexOf(privUser, StringComparison.OrdinalIgnoreCase) >= 0 ||
                         runAs.Equals(privUser, StringComparison.OrdinalIgnoreCase)))
                    {
                        isPrivilegedTask = true;
                        
                        if (privUser.Contains("SYSTEM") || privUser == "S-1-5-18")
                            runsAsSystem = true;
                        else if (privUser.Contains("Administrator"))
                            runsAsAdmin = true;
                            
                        break;
                    }
                }
                
                if (runsElevated)
                    isPrivilegedTask = true;
                
                if (!isPrivilegedTask)
                    return null;
                
                // Get security descriptor
                string sddl;
                try
                {
                    sddl = task.GetSecurityDescriptor(0x4); // DACL_SECURITY_INFORMATION = 4
                }
                catch
                {
                    try
                    {
                        sddl = task.GetSecurityDescriptor(0xF);
                    }
                    catch
                    {
                        return null;
                    }
                }
                
                // Check if low-priv users can start (need Execute permission)
                var startableBy = new List<string>();
                
                // Parse SDDL ACEs properly
                // Format: (ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid)
                // We need: Allow ACE (A) with Execute rights for low-priv SID
                //
                // Task Scheduler rights:
                //   0x1 = Read
                //   0x2 = Write/Modify
                //   0x4 = Execute/Start  <-- This is what we need!
                //
                // Generic/Standard rights that include Execute:
                //   GA = Generic All (includes everything)
                //   GX = Generic Execute
                //   FA = File All
                //   FX = File Execute
                
                // Match ACEs: (A;;rights;;;SID)
                var acePattern = new Regex(
                    @"\(A;[^;]*;([^;]+);;;([^)]+)\)",
                    RegexOptions.IgnoreCase);
                
                foreach (Match match in acePattern.Matches(sddl))
                {
                    string rights = match.Groups[1].Value.ToUpperInvariant();
                    string aceSid = match.Groups[2].Value.ToUpperInvariant();
                    
                    // Check if this is a low-priv SID
                    bool isLowPrivSid = false;
                    string friendlyName = aceSid;
                    
                    foreach (var sid in _lowPrivSids)
                    {
                        if (aceSid == sid.ToUpperInvariant())
                        {
                            isLowPrivSid = true;
                            friendlyName = _sidToName.ContainsKey(sid) ? _sidToName[sid] : sid;
                            break;
                        }
                    }
                    
                    if (!isLowPrivSid)
                        continue;
                    
                    // Check if rights include Execute/Start capability
                    bool canStart = false;
                    
                    // Check for generic/standard rights that include execute
                    if (rights.Contains("GA") ||  // Generic All
                        rights.Contains("GX") ||  // Generic Execute
                        rights.Contains("FA") ||  // File All (full control)
                        rights.Contains("FX"))    // File Execute
                    {
                        canStart = true;
                    }
                    // Check for hex rights with Execute bit (0x4)
                    else if (rights.StartsWith("0X"))
                    {
                        try
                        {
                            uint rightsValue = Convert.ToUInt32(rights, 16);
                            // Bit 0x4 = TASK_EXECUTE (Start)
                            // Also check for full control patterns
                            if ((rightsValue & 0x4) != 0 ||           // Execute bit
                                (rightsValue & 0x1F01FF) == 0x1F01FF) // Full control
                            {
                                canStart = true;
                            }
                        }
                        catch { }
                    }
                    // Check decimal rights
                    else if (char.IsDigit(rights[0]))
                    {
                        try
                        {
                            uint rightsValue = Convert.ToUInt32(rights);
                            if ((rightsValue & 0x4) != 0 ||
                                (rightsValue & 0x1F01FF) == 0x1F01FF)
                            {
                                canStart = true;
                            }
                        }
                        catch { }
                    }
                    
                    if (canStart && !startableBy.Contains(friendlyName))
                    {
                        startableBy.Add(friendlyName);
                    }
                }
                
                if (startableBy.Count == 0)
                    return null;
                
                // Parse actions (Exec and COM Handler)
                var actions = new List<TaskAction>();
                try
                {
                    foreach (dynamic action in definition.Actions)
                    {
                        try
                        {
                            int actionType = (int)action.Type;
                            
                            if (actionType == 0) // TASK_ACTION_EXEC
                            {
                                var taskAction = new TaskAction
                                {
                                    ActionType = "Exec",
                                    Path = action.Path ?? "",
                                    Arguments = action.Arguments ?? "",
                                    WorkingDirectory = action.WorkingDirectory ?? ""
                                };
                                
                                AnalyzePath(taskAction);
                                actions.Add(taskAction);
                            }
                            else if (actionType == 5) // TASK_ACTION_COM_HANDLER
                            {
                                string classId = "";
                                string data = "";
                                try { classId = action.ClassId ?? ""; } catch { }
                                try { data = action.Data ?? ""; } catch { }
                                
                                var taskAction = new TaskAction
                                {
                                    ActionType = "ComHandler",
                                    ComClassId = classId,
                                    ComData = data
                                };
                                
                                // Try to resolve COM handler to DLL path
                                ResolveCOMHandler(taskAction);
                                actions.Add(taskAction);
                            }
                        }
                        catch { }
                    }
                }
                catch { }
                
                // Skip tasks with no actions - nothing to exploit
                if (actions.Count == 0)
                    return null;
                
                // Skip tasks that run as "invoker" with no specific privileged account
                // These run as the user who triggers them - no real privesc for low-priv users
                // Exception: Keep if there's a writable binary or COM handler (could still be useful)
                bool hasExploitableAction = actions.Exists(a => a.BinaryWritable || 
                                                                 a.ParentDirWritable ||
                                                                 a.ComDllWritable ||
                                                                 a.ComDllMissing);
                
                if (string.IsNullOrEmpty(runAs) && !runsAsSystem && !runsAsAdmin && !hasExploitableAction)
                {
                    return null;
                }
                
                // Get task state
                int stateInt = 0;
                try { stateInt = (int)task.State; } catch { }
                string state = stateInt switch
                {
                    1 => "Disabled",
                    2 => "Queued",
                    3 => "Ready",
                    4 => "Running",
                    _ => "Unknown"
                };
                
                string taskPath = "";
                try { taskPath = task.Path; } catch { }
                
                var finding = new TaskFinding
                {
                    TaskPath = taskPath,
                    RunAsUser = string.IsNullOrEmpty(runAs) ? "(Task Owner/Invoker)" : runAs,
                    RunsElevated = runsElevated,
                    RunsAsSystem = runsAsSystem,
                    RunsAsAdmin = runsAsAdmin,
                    TaskState = state,
                    SDDL = sddl,
                    StartableBy = startableBy,
                    Actions = actions
                };
                
                return finding;
            }
            catch
            {
                return null;
            }
        }
        
        private void AnalyzePath(TaskAction action)
        {
            if (string.IsNullOrEmpty(action.Path))
                return;
            
            string path = action.Path.Trim('"');
            
            // Handle environment variables
            path = Environment.ExpandEnvironmentVariables(path);
            
            try
            {
                if (File.Exists(path))
                {
                    action.BinaryExists = true;
                    
                    // Check if writable
                    try
                    {
                        var acl = File.GetAccessControl(path);
                        CheckWriteAccess(acl, action);
                    }
                    catch { }
                }
                else
                {
                    action.BinaryExists = false;
                    
                    // Check parent directory
                    string parentDir = Path.GetDirectoryName(path);
                    if (!string.IsNullOrEmpty(parentDir) && Directory.Exists(parentDir))
                    {
                        try
                        {
                            var acl = Directory.GetAccessControl(parentDir);
                            CheckWriteAccess(acl, action, isParentDir: true);
                        }
                        catch { }
                    }
                }
            }
            catch { }
        }
        
        private void CheckWriteAccess(FileSystemSecurity acl, TaskAction action, bool isParentDir = false)
        {
            // ONLY the actual write bits - NOT the composite FileSystemRights.Write constant
            // which includes ReadPermissions/Synchronize that overlap with Read!
            //
            // File write bits:
            //   WriteData      = 0x00000002  (WD in icacls)
            //   AppendData     = 0x00000004  (AD in icacls)
            //   WriteEA        = 0x00000010  (WEA in icacls)
            //   WriteAttributes= 0x00000100  (WA in icacls)
            //
            // Directory write bits:
            //   CreateFiles    = 0x00000002  (same as WriteData)
            //   CreateDirs     = 0x00000004  (same as AppendData)
            //
            // We care about WriteData and AppendData - actual file content modification
            const FileSystemRights WriteDataBit = (FileSystemRights)0x00000002;
            const FileSystemRights AppendDataBit = (FileSystemRights)0x00000004;
            
            foreach (FileSystemAccessRule rule in acl.GetAccessRules(true, true, typeof(SecurityIdentifier)))
            {
                if (rule.AccessControlType != AccessControlType.Allow)
                    continue;
                
                FileSystemRights rights = rule.FileSystemRights;
                
                // Check ONLY for actual write capability bits
                bool canWrite = (rights & WriteDataBit) != 0 ||      // Can modify file content
                                (rights & AppendDataBit) != 0 ||     // Can append to file
                                (rights & FileSystemRights.FullControl) == FileSystemRights.FullControl ||
                                (rights & FileSystemRights.Modify) == FileSystemRights.Modify;
                
                if (!canWrite)
                    continue;
                
                string sid = rule.IdentityReference.Value;
                
                // Check if it's a low-priv SID
                bool isLowPriv = _lowPrivSids.Contains(sid);
                
                // Also check by resolving to name (handles localized names)
                string accountName = "";
                if (!isLowPriv)
                {
                    try
                    {
                        var account = (NTAccount)rule.IdentityReference.Translate(typeof(NTAccount));
                        accountName = account.Value.ToUpperInvariant();
                        
                        // Check common patterns (English + German)
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
                    if (isParentDir)
                    {
                        action.ParentDirWritable = true;
                    }
                    else
                    {
                        action.BinaryWritable = true;
                    }
                    
                    // Get friendly name for output
                    if (string.IsNullOrEmpty(accountName))
                    {
                        try
                        {
                            var account = (NTAccount)rule.IdentityReference.Translate(typeof(NTAccount));
                            accountName = account.Value;
                        }
                        catch
                        {
                            accountName = _sidToName.ContainsKey(sid) ? _sidToName[sid] : sid;
                        }
                    }
                    
                    action.WritableBy = accountName;
                    return;
                }
            }
        }
        
        private void ResolveCOMHandler(TaskAction action)
        {
            if (string.IsNullOrEmpty(action.ComClassId))
                return;
            
            string clsid = action.ComClassId;
            
            // Normalize CLSID format
            if (!clsid.StartsWith("{"))
                clsid = "{" + clsid + "}";
            
            try
            {
                // Try to find InprocServer32 (DLL) or LocalServer32 (EXE) for this CLSID
                string[] registryPaths = new[]
                {
                    $@"CLSID\{clsid}\InprocServer32",
                    $@"CLSID\{clsid}\LocalServer32",
                    $@"Wow6432Node\CLSID\{clsid}\InprocServer32",
                    $@"Wow6432Node\CLSID\{clsid}\LocalServer32"
                };
                
                foreach (string regPath in registryPaths)
                {
                    try
                    {
                        using (var key = Microsoft.Win32.Registry.ClassesRoot.OpenSubKey(regPath))
                        {
                            if (key != null)
                            {
                                string serverPath = key.GetValue("")?.ToString();
                                if (!string.IsNullOrEmpty(serverPath))
                                {
                                    // Clean up the path
                                    serverPath = serverPath.Trim('"');
                                    serverPath = Environment.ExpandEnvironmentVariables(serverPath);
                                    
                                    // Remove command line arguments if present
                                    if (serverPath.Contains(" ") && !File.Exists(serverPath))
                                    {
                                        int spaceIdx = serverPath.IndexOf(' ');
                                        serverPath = serverPath.Substring(0, spaceIdx).Trim('"');
                                    }
                                    
                                    action.ComServerPath = serverPath;
                                    action.ComServerType = regPath.Contains("Inproc") ? "InprocServer32 (DLL)" : "LocalServer32 (EXE)";
                                    
                                    // Check if DLL/EXE exists and is writable
                                    AnalyzeComServerPath(action, serverPath);
                                    
                                    // Try to get ProgID for friendly name
                                    try
                                    {
                                        using (var progIdKey = Microsoft.Win32.Registry.ClassesRoot.OpenSubKey($@"CLSID\{clsid}\ProgID"))
                                        {
                                            if (progIdKey != null)
                                            {
                                                action.ComProgId = progIdKey.GetValue("")?.ToString() ?? "";
                                            }
                                        }
                                    }
                                    catch { }
                                    
                                    return;
                                }
                            }
                        }
                    }
                    catch { }
                }
                
                action.ComServerPath = "(CLSID not found in registry)";
            }
            catch { }
        }
        
        private void AnalyzeComServerPath(TaskAction action, string serverPath)
        {
            try
            {
                if (File.Exists(serverPath))
                {
                    action.ComDllMissing = false;
                    
                    // Check write permissions
                    try
                    {
                        var acl = File.GetAccessControl(serverPath);
                        CheckComServerWriteAccess(acl, action);
                    }
                    catch { }
                }
                else
                {
                    action.ComDllMissing = true;
                    
                    // Check if parent directory is writable
                    string parentDir = Path.GetDirectoryName(serverPath);
                    if (!string.IsNullOrEmpty(parentDir) && Directory.Exists(parentDir))
                    {
                        try
                        {
                            var acl = Directory.GetAccessControl(parentDir);
                            CheckComServerWriteAccess(acl, action, isParentDir: true);
                        }
                        catch { }
                    }
                }
            }
            catch { }
        }
        
        private void CheckComServerWriteAccess(FileSystemSecurity acl, TaskAction action, bool isParentDir = false)
        {
            const FileSystemRights WriteDataBit = (FileSystemRights)0x00000002;
            const FileSystemRights AppendDataBit = (FileSystemRights)0x00000004;
            
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
                    if (isParentDir)
                    {
                        action.ComDllParentWritable = true;
                    }
                    else
                    {
                        action.ComDllWritable = true;
                    }
                    
                    if (string.IsNullOrEmpty(accountName))
                    {
                        try
                        {
                            var account = (NTAccount)rule.IdentityReference.Translate(typeof(NTAccount));
                            accountName = account.Value;
                        }
                        catch
                        {
                            accountName = _sidToName.ContainsKey(sid) ? _sidToName[sid] : sid;
                        }
                    }
                    
                    action.ComDllWritableBy = accountName;
                    return;
                }
            }
        }
    }
}
