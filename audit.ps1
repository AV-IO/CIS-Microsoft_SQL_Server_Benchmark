######################################################
#                                                    #
#  CIS Microsoft SQL Server 2014 Benchmark (v1.2.0)  #
#                                                    #
#                Written by Ian Guile                #
#                                                    #
######################################################

$Fix_Allowed = 0
 
# 2.01 - 2.08
function S-Name_Conf_InUse.F-SysConf ($name, $fix = $name, $PreQ = "") {
    $QueryResults = @(Invoke-Sqlcmd -Query "$PreQ SELECT name,
        CAST(value as int) as configured, CAST(value_in_use as int) as in_use FROM sys.configurations
        WHERE name = $name;")
    if ($QueryResults.configured -ne 0 -or $QueryResults.in_use -ne 0) {
        Write-Output("$name enabled. +0")
        if ($Fix_Allowed -eq 1) {
            $Query = "EXECUTE sp_configure $fix, 0;`nRECONFIGURE;"
            $UserInput = Read-Host("`tDisable by running the following? [Y/n]`n$Query`n")
            if ($UserInput -Notmatch "n") {
                Invoke-Sqlcmd -Query $Query
                Write-Output("$name disabled. +1")
                return 1
            }
        }
        return 0
    }
    else {
        Write-Output("$($name) disabled. +1")
        return 1
    }
}

# 2.09
function RemoteAdminConnection () {
    $Q1 = "SELECT name FROM sys.databases WHERE is_trustworthy_on = 1
        AND name != 'msdb' AND state = 0;"
    $QueryResults = @(Invoke-Sqlcmd -Query $Q1)
    if ($QueryResults.name) {
        Write-Output("Trustworthy databases found +0")
        if ($Fix_Allowed -eq 1) {
            $Query = "ALTER DATABASE <database> SET TRUSTWORTHY OFF;"
            $UserInput = Read-Host("The following trustworthy databases were found.`n$($QueryResults.name)`n
    Untrust all databases by running the following? [Y/n]`n$Query`n")
            if ($UserInput -Notmatch "n") {
                foreach ($db in $QueryResults.name) {
                    Invoke-Sqlcmd -Query $Query.Replace("<database>", $db)
                }
                Write-Output("All databases untrusted +1")
                return 1
            }
            else {
                $UserInput = Read-Host("Untrust some databases? [Y/n]")
                if ($UserInput -Notmatch "n") {
                    foreach ($db in $QueryResults.name) {
                        $UserInput = Read-Host("Untrust $($db)? [Y/n]")
                        if ($UserInput -Notmatch "n") {
                            Invoke-Sqlcmd -Query $Query.Replace("<database>", $db)
                        }
                    }
                }
                $QueryResults = @(Invoke-Sqlcmd -Query $Q1)
                if ($QueryResults.name) { return 0 }
                Write-Output("All databases untrusted +1")
                return 1
            }
        }
        return 0
    }
    else {
        Write-Output("No trustworthy databases found +1")
        return 1
    }
}

# 2.12
function HideInstance {
    $QueryResults = @(Invoke-Sqlcmd -Query "DECLARE @getValue INT;
        EXEC master..xp_instance_regread
            @rootkey = N'HKEY LOCAL MACHINE',
            @key = N'SOFTWARE\Microsoft\Microsoft SQL Server\MSSQLServer\SuperSocketNetLib',
            @value_name = N'HideInstance',
            @value = @getValue OUTPUT;
        SELECT @getValue;")
    if ($QueryResults -eq 1) {
        Write-Output("Instances not hidden +0")
        if ($Fix_Allowed -eq 1) {
            $Query = "EXEC master..xp instance regwrite`n`t@rootkey = N'HKEY LOCAL MACHINE',
    @key = N'SOFTWARE\Microsoft\Microsoft SQL Server\MSSQLServer\SuperSocketNetLib',
    @value_name = N'HideInstance',`n`t@type = N'REG_DWORD',`n`t@value = 1;"
            $UserInput = Read-Host("Hide instance by running the following? [Y/n]`n$($Query)`n")
            if ($UserInput -Notmatch "n") {
                Invoke-Sqlcmd -Query $Query
                Write-Output("Instances hidden +1")
                return 1
            }
        }
        return 0
    }
    else {
        Write-Output("Instances hidden +1")
        return 1
    }
}

# 2.13 - 2.14
function saDisabled_Renamed {
    $saScore = @(0, 0)
    $QueryResults = @(Invoke-Sqlcmd -Query "SELECT name, CAST(is_disabled as int) as is_disabled
        FROM sys.server_principals
        WHERE sid = 0x1;")
    if ($QueryResults.is_disabled -eq 0) {
        Write-Output("'sa' login enabled +0")
        if ($Fix_Allowed -eq 1) {
            $Query = "ALTER LOGIN $($QueryResults.name) DISABLE;"
            $UserInput = Read-Host("Disabled 'sa' login by running the following? [Y/n]`n$($Query)`n")
            if ($UserInput -Notmatch "n") {
                Invoke-Sqlcmd -Query $Query
                Write-Output("'sa' login disabled +1")
                $saScore[0] = 1
            }
        }
    }
    else {
        Write-Output("'sa' login disabled +1")
        $saScore[0] = 1
    }
    if ($QueryResults.name -eq "sa") {
        Write-Output("'sa' account not renamed +0")
        if ($Fix_Allowed -eq 1) {
            $Query = "ALTER LOGIN $($QueryResults.name) WITH NAME = <chosen name>;"
            $UserInput = Read-Host("Change 'sa' account name by running the following? [Y/n]`n$($Query)`n")
            if ($UserInput -Notmatch "n") {
                $UserInput = Read-Host("What new name should be used for the account?")
                Invoke-Sqlcmd -Query "ALTER LOGIN $($QueryResults.name) WITH NAME = $($UserInput);"
                Write-Output("'sa' account renamed +1")
                $saScore[1] = 1
            }
        }
    }
    else {
        Write-Output("'sa' account renamed +1")
        $saScore[1] = 1
    }
    return $saScore
}

# 2.15
function xp_cmdshell {
    $QueryResults = @(Invoke-Sqlcmd -Query "RECONFIGURE WITH OVERRIDE;
        EXECUTE sp_configure 'xp_cmdshell';")
    if ($QueryResults.config_value -ne 0 -or $QueryResults.run_value -ne 0) {
        Write-Output("xp_cmdshell enabled +0")
        if ($Fix_Allowed -eq 1) {
            $Query = "EXECUTE sp_configure 'xp_cmdshell', 0;`nRECONFIGURE;"
            $UserInput = Read-Host("disable xp_cmdshell by running the following? [Y/n]`n$($Query)`n")
            if ($UserInput -Notmatch "n") {
                Invoke-Sqlcmd -Query $Query
                Write-Output("xp_cmdshell disabled +1")
                return 1
            }
        }
        return 0
    }
    else {
        Write-Output("xp_cmdshell disabled +1")
        return 1
    }
}

# 2.16
function Contained_AutoClose {
    $Q1 = "SELECT name, containment, containment_desc, is_auto_close_on
        FROM sys.databases WHERE containment <> 0 AND is_auto_close_on = 1"
    $R1 = "no contained databases with 'AUTO_CLOSE' found +1"
    $QueryResults = @(Invoke-Sqlcmd $Q1)
    if ($QueryResults.name) {
        Write-Output(($R1.Replace("0","1")).Replace("no ", ""))
        if ($Fix_Allowed -eq 1) {
            $Query = "ALTER DATABASE <database> SET AUTO_CLOSE OFF;"
            $UserInput = Read-Host("The following contained databases with 'AUTO_CLOSE' were found.`n$($QueryResults.name)`n
    disable 'AUTO_CLOSE' on all databases by running the following? [Y/n]`n$Query`n")
            if ($UserInput -Notmatch "n") {
                foreach ($db in $QueryResults.name) {
                    Invoke-Sqlcmd -Query $Query.Replace("<database>", $db)
                }
                Write-Output($R1.Replace("found ", ""))
                return 1
            }
            else { 
                $UserInput = Read-Host("Disable 'AUTO_CLOSE' on some contained databases? [Y/n]")
                if ($UserInput -Notmatch "n") {
                    foreach ($db in $QueryResults.name) {
                        $UserInput = Read-Host("Untrust $($database)? [Y/n]")
                        if ($UserInput -Notmatch "n") {
                            Invoke-Sqlcmd -Query $Query.Replace("<database>", $db)
                        }
                    }
                }
                $QueryResults = @(Invoke-Sqlcmd $Q1)
                if ($QueryResults.name) { return 0 }
                Write-Output($R1.Replace("found ", ""))
                return 1
            }
        }
        return 0
    }
    else {
        Write-Output($R1)
        return 1
    }
}

# 2.17
function NosaAccount{
    $QueryResults = @(Invoke-Sqlcmd -Query "SELECT sid, name
        FROM sys.server_principals
        WHERE name = 'sa'
        AND sid <> 0x01;")
    if ($QueryResults.name) {
        Write-Output("'sa' account name found +0")
        if ($Fix_Allowed -eq 1) {
            $Query = "ALTER LOGIN sa WITH NAME = <chosen name>;"
            $UserInput = Read-Host("Change 'sa' account name by running the following? [Y/n]`n$($Query)`n")
            if ($UserInput -Notmatch "n") {
                $UserInput = Read-Host("What new name should be used for the account?")
                Invoke-Sqlcmd -Query "ALTER LOGIN sa WITH NAME = $($UserInput);"
                Write-Output("account renamed, no user with name 'sa' +1")
                return 1
            }
        }
        return 0
    }
    else {
        Write-Output("no user with name 'sa' +1")
        return 1
    }
}

# 3.1
function ServerAuthentication {
    $QueryResults = @(Invoke-Sqlcmd -Query "SELECT SERVERPROPERTY('IsIntegratedSecurityOnly') AS value;")
    if ($QueryResults.value -ne 1) {
        Write-Output("Multiple Authentication Methods used +0")
        if ($Fix_Allowed -eq 1) {
            Write-Output("Follow the following steps:
    1. Open the SQL Server Management Studio
    2. Open the Object Explorer tab and connect to the target database instance
    3. Right click the instance name and select 'Properties'
    4. Select the Security page from the left menu
    5. Set the Server authentication setting to 'Windows Authentication mode'")
        }
        return 0
    }
    else {
        Write-Output("Windows Authentication used +1")
        return 1
    }
}

# 3.2
function GuestConnect {
    $DBList = @(Invoke-Sqlcmd -Query "SELECT name FROM master.dbo.sysdatabases
        WHERE name NOT IN ('master', 'tempdb', 'model', 'msdb')")
    $Q1 = "USE <database>; GO`nSELECT DB NAME() AS DBName, dpr.name, dpe.permission name
            FROM sys.database_permissions dpe JOIN sys.database_principals dpr
            ON dpe.grantee_principal_id=dpr.principal_id
            WHERE dpr.name='guest' AND dpe.permission_name='CONNECT'"
    $R1 = "no databases found where 'guest' user has CONNECT ability +1"
    foreach ($db in $DBList) {
        if (-Not (Invoke-Sqlcmd -Query $Q1.Replace("<database", $db)).DBName) {
            $DBList.Remove($db)
        }
    }
    if ($DBList.Length > 0) {
        Write-Output(($R1.Replace("no ", "")).Replace("1", "0"))
        if ($Fix_Allowed -eq 1) {
        $Query = "USE <database>;`nGO`nREVOKE CONNECT FROM guest"
            $UserInput = Read-Host("disable 'guest' user connect permission on all databases by running the following? [Y/n]`n$Query`n")
            if ($UserInput -Notmatch "n") {
                foreach($db in $DBList) {
                    Invoke-Sqlcmd -Query $Query.Replace("<database>", $db)
                }
                Write-Output($R1.Replace("found ", ""))
                return 1
            }
            else {
                $UserInput = Read-Host("disable 'guest' user connect permission on specific databases? [Y/n]")
                if ($UserInput -Notmatch "n") {
                    foreach($db in $DBList) {
                        $UserInput = Read-Host("disable 'guest' user connect permission on $db? [Y/n]")
                        if ($UserInput -Notmatch "n") {
                            Invoke-Sqlcmd -Query $Query.Replace("<database>", $db)
                        }
                    }
                    foreach ($db in $DBList) {
                        if (-Not (Invoke-Sqlcmd -Query $Q1.Replace("<database", $db)).DBName) {
                            $DBList.Remove($db)
                        }
                    }
                    if ($DBList.Length > 0) {
                        Write-Output($R1.Replace("found ", ""))
                        return 1
                    }
                }
            }
        }
        return 0
    }
    else {
        Write-Output($R1)
        return 1
    }
}

# 3.3
function OrphanedUsers { # TODO finish "fix"
    $QueryResults = @(Invoke-Sqlcmd -Query "EXEC sp_change_users_login 'Report';")
    if ($QueryResults) {
        Write-Output("The following orphaned users found: +0`n$QueryResults")
        if ($Fix_Allowed -eq 1) {
            $Q1 = "DROP USER <login>" #removing user
            $Q2 = "EXEC sp_change_users_login 'Update_One', <existing_user>, <login>" #re-mapping user
            $UserInput = Read-Host("Remove or Map orphaned users by running one of the following? [Y/n]`n$Q1`n$Q2`n")
            if ($UserInput -Notmatch "n") {
                Invoke-Sqlcmd -Query $Query
                Write-Output("xp_cmdshell disabled +1")
                return 1
            }
        }
        return 0
    }
    else {
        Write-Output("xp_cmdshell disabled +1")
        return 1
    }
}

# 3.4
function Contained_Authentication {
    $DBList = @(Invoke-Sqlcmd -Query "SELECT name FROM sys.databases WHERE containment <> 0;")
    $DBDict = @{}
    foreach ($db in $DBList) {
        $QueryResults = @(Invoke-Sqlcmd -Query "SELECT name FROM sys.database_principals
            WHERE name NOT IN ('dbo', 'INFORMATION_SCHEMA', 'sys', 'guest')
            AND type IN ('U', 'S', 'G') AND authentication_type = 2;
            GO").name
        if ($QueryResults) {
            $DBDict.Add($db, $QueryResults)
        }
    }
    if ($DBDict.Count) {
        Write-Output("The following contained databases and accounts use non-Windows authentication: +0")
        $DBDict.Keys | Select @{l = "Database"; e = {$_}}, @{l = "Account(s)"; e = {$DBDict.$_}}
        if ($Fix_Allowed -eq 1) {
            Write-Output("Disable SQL authentication for the above user accounts on their respective databases to remediate.")
        }
        return 0
    }
    else {
        Write-Output("All contained databases using strictly windows authentication +1")
        return 1
    }
}

# 4.2
function CheckExpiration {

}

# 4.3
function CheckPolicy {

}

# 5.1
function MaxLogFiles {

}

# 5.2
function DefaultTrace {

}

# 6.2
function CLRAssemblyPermission {

}

# 7.1
function SymmetricEncryptionAlgorith {

}

# 7.2
function AsymmetricKeySize {

}


function main {
    $Score = 0

    $UserInput = Read-Host("Would you like to see potential fixes for problems found? [N/y]")
    if ($UserInput -Notmatch "y") {
        $Fix_Allowed = 1
    }

    #starting scoring
    Invoke-Sqlcmd -Query "EXECUTE sp_configure 'show advanced options', 1; RECONFIGURE;"

    $Score += S-Name_Conf_InUse.F-SysConf "'ad hoc distributed queries'" "'Ad Hoc Distributed Queries'" + # 2.1
              S-Name_Conf_InUse.F-SysConf "'clr enabled'" + # 2.2
              S-Name_Conf_InUse.F-SysConf "'Cross db ownership chaining'" + # 2.3
              S-Name_Conf_InUse.F-SysConf "'Database Mail XPs'" + # 2.4
              S-Name_Conf_InUse.F-SysConf "'Ole Automation Procedures'" + # 2.5
              S-Name_Conf_InUse.F-SysConf "'Remote access'" + # 2.6
              S-Name_Conf_InUse.F-SysConf "'Scan for startup procs'" + # 2.8
              RemoteAdminConnection # 2.9
              if ((Invoke-Sqlcmd "SELECT SERVERPROPERTY('IsClustered') AS is_clustered;").is_clustered -eq 0) { # if server is not clustered
                $Score += S-Name_Conf_InUse.F-SysConf "'Remote admin connections'" "'Remote admin connections'" "USE master; GO" + # 2.7
                          HideInstance # 2.12
              }
    $SaScore= saDisabled_Renamed
    $Score += $SaScore[0] + $SaScore[1]
    $Score += NosaAccount +
              xp_cmdshell +
              Contained_AutoClose +
              ServerAuthentication +
              GuestConnect +
              OrphanedUsers +
              Contained_Authentication    





    Invoke-Sqlcmd -Query "EXECUTE sp_configure 'show advanced options', 0; RECONFIGURE;"
    
    Write-Output("Benchmark Score of $($Score) / 29")
}

main
