using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace TaskPrivEscScanner
{
    public static class CsvExporter
    {
        public static void Export(List<TaskFinding> findings, string filename)
        {
            var sb = new StringBuilder();
            
            // Header
            sb.AppendLine("Severity,TaskPath,TaskName,RunAs,PrivilegeLevel,State,StartableBy,ActionType,ActionPath,ActionArgs,ComClassId,ComServerPath,BinaryExists,BinaryWritable,WritableBy,Issues,StartCommand");
            
            foreach (var finding in findings.OrderByDescending(f => f.Severity))
            {
                foreach (var action in finding.Actions)
                {
                    if (action.ActionType == "Exec")
                    {
                        sb.AppendLine(string.Join(",",
                            Escape(finding.Severity.ToString()),
                            Escape(finding.TaskPath),
                            Escape(finding.TaskName),
                            Escape(finding.RunAsUser),
                            Escape(finding.PrivilegeContext),
                            Escape(finding.TaskState),
                            Escape(string.Join("; ", finding.StartableBy)),
                            "Exec",
                            Escape(action.Path),
                            Escape(action.Arguments),
                            "",
                            "",
                            action.BinaryExists.ToString(),
                            action.BinaryWritable.ToString(),
                            Escape(action.WritableBy),
                            Escape(string.Join("; ", finding.Issues)),
                            Escape(finding.StartCommand)
                        ));
                    }
                    else if (action.ActionType == "ComHandler")
                    {
                        sb.AppendLine(string.Join(",",
                            Escape(finding.Severity.ToString()),
                            Escape(finding.TaskPath),
                            Escape(finding.TaskName),
                            Escape(finding.RunAsUser),
                            Escape(finding.PrivilegeContext),
                            Escape(finding.TaskState),
                            Escape(string.Join("; ", finding.StartableBy)),
                            "ComHandler",
                            "",
                            "",
                            Escape(action.ComClassId),
                            Escape(action.ComServerPath),
                            (!action.ComDllMissing).ToString(),
                            action.ComDllWritable.ToString(),
                            Escape(action.ComDllWritableBy),
                            Escape(string.Join("; ", finding.Issues)),
                            Escape(finding.StartCommand)
                        ));
                    }
                }
                
                // If no actions, still output the finding
                if (finding.Actions.Count == 0)
                {
                    sb.AppendLine(string.Join(",",
                        Escape(finding.Severity.ToString()),
                        Escape(finding.TaskPath),
                        Escape(finding.TaskName),
                        Escape(finding.RunAsUser),
                        Escape(finding.PrivilegeContext),
                        Escape(finding.TaskState),
                        Escape(string.Join("; ", finding.StartableBy)),
                        "",
                        "",
                        "",
                        "",
                        "",
                        "",
                        "",
                        "",
                        Escape(string.Join("; ", finding.Issues)),
                        Escape(finding.StartCommand)
                    ));
                }
            }
            
            File.WriteAllText(filename, sb.ToString(), Encoding.UTF8);
        }
        
        private static string Escape(string value)
        {
            if (string.IsNullOrEmpty(value))
                return "";
            
            if (value.Contains(",") || value.Contains("\"") || value.Contains("\n") || value.Contains("\r"))
            {
                return "\"" + value.Replace("\"", "\"\"") + "\"";
            }
            
            return value;
        }
    }
}
