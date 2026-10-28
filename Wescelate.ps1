<#

.SYNOPSIS
    Windows PrivEsc Enumeration Script for my OSCP exam attempt
    and future endevours. S.H


.NOTES
    Author: Migwe101


#>


# Start of Globals

$global:ProgramBanner = @"

                                     ,--.!, 
                                  __/   -*-
                                ,d08b.  '|`
                                0088MM     
                                `9MMP'       
     _    _                    _       _       
    | |  | |                  | |     | |      
    | |  | | ___  ___  ___ ___| | __ _| |_ ___ 
    | |/\| |/ _ \/ __|/ __/ _ \ |/ _` | __/ _ \
    \  /\  /  __/\__ \ (_|  __/ | (_| | ||  __/
     \/  \/ \___||___/\___\___|_|\__,_|\__\___|


    Author: Migwe101
    Script for use in authorized systems only,
    Author is not responsible for any damage caused
    by missue


"@

$global:FilesToSearch = @(
	'C:\Users'
	'C:\inetpub'
	'C:\temp'
	'C:\xampp'
)

$global:VulnerablePrivileges = @{
	'SeImpersonatePrivilege'="It May Be vulnerable to Potato Exploits"
	'SeAssignPrimaryTokenPrivilege'="It May Be vulnerable to Potato Exploits"
	'SeBackupPrivilege'="This User Can Read any Local System File"
	'SeTcbPrivilege'="This User Can impersonate Any User"
    'SeCreateTokenPrivilege'="This Privilege is Vulenrable"
    'SeLoadDriverPrivilege'="This Privilege is Vulnerable"
    'SeDebugPrivilege'="This User can read any Process Memory"
    'SeRestorePrivilege'="This User Can Read any Local System File"
    'SeTakeOwnershipPrivilege'="User can take ownership of files or other objects"
}

$global:ContextGroups = @()

$global:ContextName = whoami

$global:AllContext = @()

$global:ServiceBinariesPath = @()

$global:ServiceBinariesName = @()

$global:CleanServicePaths = @()

# End of Globals
function PrintLineStart {
	param (
		[string]$StringToPrint
	)

	Write-Host ("=" * 20)($StringToPrint)("=" * 20)	 -ForegroundColor Blue
}

function PrintLineFinish {
	param (
		[string]$StringPrinted
	)

	Write-Host ("=" * 20)("=" * $StringPrinted.Length)("=" * 20) -ForegroundColor Blue
	}

function GetPermissionsMain {
    param(
        [Parameter(Mandatory=$false)] # Set to non-mandetory to prevent needing to rewrite previous function calls before the registry functionality was added
        [string]$Path,
        [string]$IdentityToQuery,
        [bool]$IsRegistry
    )

    if ($IsRegistry -eq $true) {
        if (!$Path) {return $false}
        $PermissionsOfObjects = try {
            get-acl $Path | foreach-object {$_.Access | where-object {$_.IdentityReference -eq $IdentityToQuery}} | select-object -Expandproperty RegistryRights
        } catch {
            Write-Error "Can't Get Permissions on Given File . ERROR 1" $Path
            return $false
        }

    } else {
        if (!$Path) {return $false}
        $acl = try {
            get-acl $Path | Select-Object Access | ForEach-Object {$_.Access | Select-Object IdentityReference,FileSystemRights}
        } catch {
            Write-Error "Can't Get Permissions on Given File . ERROR 1" $Path
            return $false
        }

        $PermissionsOfObjects = try {
            $acl | Where-Object { $_.IdentityReference -eq $IdentityToQuery } | Select-Object -ExpandProperty FileSystemRights
        } catch {
            Write-Error "Can't Get Permissions on Given File. ERROR 2" $Path
            return $false
        }
    }
    
    if ($PermissionsOfObjects) {
        return $PermissionsOfObjects
    }
    return $false
}


function GetSystemVersion {
    $results = try {systeminfo} catch {Write-Error "Could not run the 'systeminfo' command"; return}
    return $results
}

function VulnerableUserPrivileges {
    $UserPrivileges = try {whoami /priv | Select-String "^Se\w+Privilege" | ForEach-Object {($_ -split '\s+')[0]}} catch {Write-Error "Can't Run Native Commands, check PATH"; return}
    $VulnerablePrivs = $false
    foreach ($item in $UserPrivileges) {
        if ($global:VulnerablePrivileges[[string]$item]) {
            Write-Host $item "FOUND" $global:VulnerablePrivileges[[string]$item] -ForegroundColor Red
            $VulnerablePrivs = $true
        }
    }
    if (!$VulnerablePrivs) {
        Write-Output "No Vulnerable Privileges Found"
    }
}

function AlwaysInstallElevatedCheck {
    # First, a check to confirm the registry Key exists needs to be made
    $CheckInstallerKey = try {reg query HKLM\SOFTWARE\Policies\Microsoft\Windows | Select-String "Installer"} catch {Write-Error "Can't access required registry key, It probably does not exist"; return}
    if ($CheckInstallerKey) {
        # Check for correct value in LOCAL_MACHINE Key
        $CheckLocalMachineInstaller = try {reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated | Select-String 0x1} catch {Write-Error "Can't access required LOCAL_MACHINE registry key"}
        $CheckCurrentUserInstaller = try {reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated | Select-String 0x1} catch {Write-Error "Can't access required CURRENT_USER registry key"}
        if ($CheckLocalMachineInstaller -and $CheckCurrentUserInstaller) {
            Write-Host "AlwaysInstallElevated True, We Can run MSI Installers as SYSTEM" -ForegroundColor Red
            return
        }
    }
    Write-Output "AlwaysInstallElevated is False"
}

function CheckRegistryAutoRuns {
    $RegistryAutoRuns = try {reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run} catch {Write-Error "Can't Find LOCAL_MACHINE Registry Key"; return}
    # Implement unqouted service path checks
    Write-Host "Check All AutoRun Executables for vunlerable user permissions" -ForegroundColor Yellow
    Write-Output $RegistryAutoRuns | Format-Table -AutoSize
    return
}

function InterestingFileContents {
	$InterstingFiles = try { Get-ChildItem -Path $global:FilesToSearch -Include *.kdbx, *.txt, *.ini, toml-3.8.3.jar, *.log, local.txt, proof.txt, flag.txt, user.txt, root.txt, *.rsa, *.config, *.xml -File -Recurse -ErrorAction SilentlyContinue | Select-string -Pattern 'password','passwd','pwd', 'pass', 'NTLM', 'Ticket' -SimpleMatch | Select-Object Path,Line } catch {Write-Error "Error Occurred When Executing command"; return}
	Write-Output $InterstingFiles | Format-Table -AutoSize
	}


function RegistryPUTTYSessions {
    # Check If PUTTY registry key exists
    $SessionsKeyExists = try {reg query "HKCU\Software\SimonTatham\PuTTY\" | Select-String "Sessions"} catch {Write-Host "Can't Access CURRENT_USER Registry Key"; return $false}
    # If Registry key exists, get all Values
    if ($SessionsKeyExists) {
        $PUTTYSessions = try {reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | Select-String "Sessions"} catch {Write-Host "Can't Access CURRENT_USER Registry Key"; return $false}
        return $PUTTYSessions
    }
    return $false
}

function GetSavedCMDKeyCredentials {
    try {
        cmdkey /list
    } catch {
        Write-Error "Error With Native Windows Command, Check PATH"
        return $false
    }
}


function CheckStartupApps {
    # Check If we have any permissions over the directory

    $CanWriteToDir = $false
    foreach ($i in $global:AllContext) {
        $output = GetPermissionsMain "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp" $i
        if ($output -ne $false) {
            if ($output -eq "FullControl" -or $output -eq "Modify" -or $output -eq "Write") {
                $CanWriteToDir = $true
                Write-Host "Our Context can Create or Modify in the Startup Apps directory" $i "->" $output -ForegroundColor Red
            }
        }
    }

    if (!$CanWriteToDir) {
        Write-Host "Our Context Cannont Write to the StartupApps directory"
    }

    # Check If we have any permissions over any files inside the directory
    $CanWeExploit = $false
    $StartUpFiles =  Get-ChildItem "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp" | ForEach-Object {$_ | Select-Object -ExpandProperty Name}
    Write-Host $StartUpFiles
    foreach ($i in $StartUpFiles) {
        foreach ($j in $global:AllContext) {
            $output = GetPermissionsMain $i $j
            if ($output -ne $false) {
                if ($output -eq "FullControl" -or $output -eq "Modify" -or $output -eq "Write") {
                    $CanWeExploit = $true
                    Write-Host "Our Context can Create or Modify" $i "in the Startup Apps directory" $j "->" $output -ForegroundColor Red
                }
            }
        }
    }

    if (!$CanWeExploit) {
        Write-Host "We Cannont Create or Modify any files in the Startup Apps Directory"
    }
}

function InstalledApplications {
	$results = try { 
        Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | Select-Object displayname,installlocation 
    } catch {
        Write-Error "Error Occurred When Executing command"
        return
    }
    return $results
}

function CleanServicePaths {
    param(
        [string]$ServicePath
    )
    $tmp = [regex]::Match($ServicePath, '^"?(.+?\.exe)"?').Groups[0].Value
    $tmp = $tmp -replace '["'']', ''
    return $tmp
}

function IsPathVulnerable {
    param(
        [string]$Path
    )

    # Check is path is qouted

    $Qouted = $false
    if (($Path -like '"*')) {
        $Qouted = $true
    }   elseif (($Path -like "'*")) {
        $Qouted = $true
    } else {
        $Qouted = $false
    }

    # After checking if the path is qouted, We will check to see if the path contains spaces

    if ($Path -match '\s.*\.exe') {
            if (!$Qouted) {
                return $true
            } else {
                return $false
            }
    }

    return $false
}

function DisplayDefenderInfo {
    $DefenderInfo = try {
        Get-MpComputerStatus -ErrorAction Stop
    } catch {
        $DefenderInfo = $false
    }

    if (!$DefenderInfo) {
        Write-Host "Windows Defender Anti-Virus Is DISABLED" -ForegroundColor Red
        Write-Host "Windows Defender Anti-Malware Is DISABLED" -ForegroundColor Red
        Write-Host "Real Time Protection is DISABLED" -ForegroundColor Red
        Write-Host
        Write-Host "Windows Defender Signatues last updated on: N/A"
        return
    }
    if ($DefenderInfo.AntivirusEnabled) {
        Write-Host "Windows Defender Anti-Virus Is Active"
    } else {
        Write-Host "Windows Defender Anti-Virus Is DISABLED" -ForegroundColor Red
    }

    if ($DefenderInfo.AMServiceEnabled) {
        Write-Host "Windows Defender Anti-Malware Is Active"
    } else {
        Write-Host "Windows Defender Anti-Malware Is DISABLED" -ForegroundColor Red
    }

    if ($DefenderInfo.RealTimeProtectionEnabled) {
        Write-Host "Real Time Protection Is Active"
    } else {
        Write-Host "Real Time Protection is DISABLED" -ForegroundColor Red
    }

    Write-Host "Windows Defender Signatues last updated on:" $DefenderInfo.AntispywareSignatureLastUpdated
}


function AreCurrentServicePathsVulnerable {
    $VulnSrvList = @()
    $vulnerable = $false
    foreach ($i in $global:ServiceBinariesPath) {
        if (IsPathVulnerable($i)) {
                Write-Host "UNQUOTED Service Path Found:" $i -ForegroundColor Red
                $vulnerable = $true
                $VulnSrvList += $i
        }
    }

    if ($vulnerable) {
        Write-Host "A Current Service Binary Path is UNQUOTED" -ForegroundColor Red
        return $VulnSrvList
    } else {
        Write-Host "No Current Service Binary Paths are unquoted"
        return $false
    }
}

function GetPowershellHistory {
    $results = try { 
        Get-History 
    } catch {
        Write-Error "Can't Run Native Windows Command, Check PATH"
        return
    }
    return $results
}

function GetPowershellConsoleHistory {
    $HistoryPath = try {
        (Get-PSReadLineOption).HistorySavePath 
        } catch {
        Write-Error "Can't Run Native Windows Command, Check PATH"
        return
        }
    $results =  try { 
        Get-Content $HistoryPath 
    } catch {
        Write-Error "Cant Open Console History File, Does not Exist"
        return
    }
    return $results
}

function CanWeHijackPath {
    PrintLineStart("Vulnerable Unqouted Service Paths")
    $VulnerableSerivcePaths = AreCurrentServicePathsVulnerable
    $Paths2check = @()
    foreach ($i in $VulnerableSerivcePaths) {
        $array = $i -split '\\'
        $var = ""
        # Generate list of all valid Directorys in vulnerable path to attempt write access
        for ($i = 0; $i -lt ($array.Count - 1); $i++) {
            $var += ($array[$i] + "\")
            $Paths2check += $var
        }
    }
	PrintLineFinish("Vulnerable Unqouted Service Paths")
    
    # Armed with all directories is the Path, lets test our premissions
    $PrivsToHijack = @(
        "Modify"
        "Write"
        "FullControl"
    )

    <# This following function does to following:
        Stores the current privilege context of the script
        Tests every group we are apart of for permissions on the directory
        If the permissions return give us the ability to write or move a file, we print the user:privilege:path
        
        The gameplan was to create a hashtable to lookup the permissions, but some of the permissions return where
        hexadecimal masks much like linux privileges with bit values, this interfered with the array and made the values act in
        weird ways.

        Instead of looping through an array of privilege and checking them against the hash table. I compared the string of
        all the privileges to any `like` of the needed permissions
    #>
    PrintLineStart("Can We Hijack Unqouted Paths?")
    foreach ($i in $Paths2check ) {
        foreach ($f in $global:AllContext) {
            $PremissionsOnDirectory = GetPermissionsMain $i $f
            foreach ($j in $PrivsToHijack) {
                if ($PremissionsOnDirectory -like $j) {
                    Write-Host "We Can Create a File At the Path:" $i "->" $f ":" $PremissionsOnDirectory -ForegroundColor Red  "(Potential Hijackaing vector)"

                }
            }

        }
    }
    PrintLineFinish("Can We Hijack Unqouted Paths?")
}

function CanWeChangeServiceBinary {
    param(
        [string]$ServiceExecutablePath   
    )

    $PrivsToChange = @(
        "modify"
        "Write"
        "FullControl"
        "AppendData"
    )

    foreach ($i in $global:AllContext) {
        $result = GetPermissionsMain $ServiceExecutablePath $i
        foreach ($j in $PrivsToChange) {
            if ($result -ne $false){
                if ($result -like $j) {
                    Write-Host "We Can Write to the Service Binary:" $ServiceExecutablePath "->" $i ":" $result -ForegroundColor Red
                }
            }
        }
    } 
}



# Function that allows for file permissions to be tested against the authorization context of the script,
# You can also provide the Identity to test, by default it will dump permissions for the script context
# GetPermissions "C:\Users\User\test" "user"

function GetPermissions {
    param(
        [Parameter(Mandatory=$false)]
        [string]$Path,
        [string]$Identity
    )

    if (!$Path) {
        Write-Error "Need to Supply Path to Object"
        return
    } else {
        # If No identity to check given, check against all in current context
        if (!$Identity) {
            GetContextGroups
            $Identities = $global:ContextGroups
            $Identities += $global:ContextName
            foreach($i in $Identities) {
                $result = GetPermissionsMain $Path $i
                if ($result -ne $false) {
                    Write-Host "User:" $i "Has Permission ->" $result
                }
            }

        } else {
            $result = GetPermissionsMain $Path $Identity
            if ($result -ne $false) {
                    Write-Host "User:" $Identity "Has Permission ->" $result
            } else {
                Write-Host "User:" $Identity "Does Not Have Permissions on ->" $Path
            }
    }
}
}

function CheckForStoredPasswords {
    param (
        [Parameter(Mandatory=$false)]
        [string]$Mode
    )
    try {reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon"} catch {Write-Error "Can't Access LOCAL_MACHINE Registry Key"; return}
    $PUTTYSessions = RegistryPUTTYSessions
    GetSavedCMDKeyCredentials
    if ($PUTTYSessions) {
        Write-Host $PUTTYSessions -ForegroundColor Red
    } else {
        Write-Host "No PUTTY Sessions found in Registry"
    }
    if ($Mode.ToLower() -eq "all") {
        try {reg query HKLM /f password /t REG_SZ /s} catch {Write-Error "Can't Access LOCAL_MACHINE Registry Key"; return}
        try {reg query HKCU /f password /t REG_SZ /s} catch {Write-Error "Can't Access CURRENT_USER Registry Key"; return}
    }

}

function SerivceRegistryPermissions{
    # Get the ACL on the Registry Key associated with the Service Binary
    PrintLineStart("Can We modify the Service Registry Properties?")
    $PrivsForAbuse = @(
    'setvalue'
    'changepermissions'
    'takeownership'
    'writekey'
    'fullcontrol'
    )

    foreach ($i in $global:ServiceBinariesName) {
        foreach ($j in $global:AllContext) {
            $RegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\" + [string]$i
            $RegistryACL = GetPermissionsMain $RegPath $j $true
            if ($RegistryACL -ne $false){
                foreach ($k in $PrivsForAbuse) {
                    if ($RegistryACL -like $k) {
                        Write-Host $RegPath "--->" $RegistryACL ":" $j -ForegroundColor Red
                    }
                }
            }
        }
    }
    PrintLineFinish("Can We modify the Service Registry Properties?")
}


function ServicePermissions{}


<#
    The Following Functions Utilise the Above modules, They will provide the features that I want this tool to have
#>

function ServiceVulnerabilities {
    CanWeHijackPath
    PrintLineStart("Do We have interesting Permissions on Service Binaries?")
    foreach($j in $global:CleanServicePaths){
        CanWeChangeServiceBinary $j
    }
    PrintLineFinish("Do We have interesting Permissions on Service Binaries?")
    SerivceRegistryPermissions
}


function GetHistory {
    param(
        [bool]$verbose
    )

    if ($verbose){
        GetPowershellConsoleHistory
    }

    GetPowershellHistory

    # Look for other users console history
    $ConsoleHistoryDir = "\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\"
    $UserDirs = try {
        get-childitem "C:\Users" -ErrorAction Stop | select-object -ExpandProperty Name
    } catch {
        Write-Error "Can't Find Users Powershell History"
        return
    }

    # List the Powershell History for each user home directory

    foreach ($i in $UserDirs) {
        $UserPowershellHistoryPath = "C:\Users\" + $i + $ConsoleHistoryDir
        try {
            $files = Get-ChildItem $UserPowershellHistoryPath -ErrorAction Stop | select-object -ExpandProperty Name
            if ($files) {
                Write-Host "Files found in user" $i "Powershell History Directory:" $UserPowershellHistoryPath -ForegroundColor Red
                foreach($j in $files) {
                    Write-Host "`t - $j"
                }
            }
        }
        catch {
            Write-Host "Cant Find Powershell History For User:" $i
        }
    }

}


<# This Function exists to collect all the information needed to conduct vulnerability testing and store it in global variables#>
function IntializeContext{

    ## Get all Groups in the context we are running this script as
    $ContextGroups = try {
        whoami /groups /fo csv | Select-Object -Skip 2 | ConvertFrom-Csv -Header Groups | Select-Object -ExpandProperty Groups
    } catch {
        Write-Error "Can't use Native Command, Check PATH"
        return
    }

    $global:ContextGroups = $ContextGroups

    ## Get all running or non-running service binary name and path
    $results = try { Get-CimInstance -ClassName win32_service -ErrorAction Stop | Select-Object Name,State,PathName } catch {Write-Error "Error Occurred When Executing command"; return}
    $global:ServiceBinariesPath = $results.PathName
    $global:ServiceBinariesName = $results.Name



    $global:AllContext = $global:ContextGroups + $global:ContextName
    ## Create a Global with all the clean path names for further analysis for different vulnerabilities

    foreach($j in $global:ServiceBinariesPath){
        $global:CleanServicePaths += CleanServicePaths $j
    }

}


# The WescelateDefault Function, is the script functionality if no arguments have been passed with the tool

function WescelateDefault {
    IntializeContext
    $PrivEscItemsHash = @{
        "System Information" = { GetSystemVersion }
        "Vulnerable User Privileges (eg. SeImpersonate)" = { VulnerableUserPrivileges }
        "AlwaysInstallElevated Enabled?" = { AlwaysInstallElevatedCheck }
        "Contents of AutoRun Registry Key" = { CheckRegistryAutoRuns }
        "Access On System Auto Runs" = { CheckStartupApps }
        "Vulnerable Services - https://www.pentestpartners.com/security-blog/vulnerabilities-that-arent-unquoted-spaces/ " = { ServiceVulnerabilities }
        "Command Line History" = { GetHistory }
		"Current Installed Applications" = { InstalledApplications }
        "Stored Passwords" = { CheckForStoredPasswords }

	}
    Write-Host $global:ProgramBanner -ForegroundColor Green
    Write-Host "====================================================================" -ForegroundColor DarkGreen
    Write-Host
    DisplayDefenderInfo
    Write-Host
    Write-Host "...."
    Start-Sleep -Seconds 3
    foreach ($key in $PrivEscItemsHash.Keys) {
		PrintLineStart($key)
        $block = & $PrivEscItemsHash[$key]
        Write-Output $block | Format-Table -AutoSize
		PrintLineFinish($key)
		}
    Write-Host "====================================================================" -ForegroundColor DarkGreen
    
}



WescelateDefault
