<#
.SYNOPSIS
Query remote computer for vulnerable log4j files and output results to CSV

.DESCRIPTION
This script recurses through a list of computers / servers to find any files containing log4j

.LINK
https://logging.apache.org/log4j/2.x/security.html
https://github.com/zwelch12/powershell-log4j-scan


Check for CVE-2021-45046 (2.0-beta9 through 2.12.1 and 2.13.0 through 2.15.0)
    Mitigation - remove the JndiLookup class from the classpath or upgrade to 2.16.0 (Java 8) or 2.12.2 (Java 7)

Check for CVE-2021-44228 (all versions from 2.0-beta9 through 2.12.1 and 2.13.0 through 2.14.1)
    Mitigation - remove the JndiLookup class from the classpath or upgrade to 2.16.0 (Java 8) or 2.12.2 (Java 7)

Check for CVE-2021-4104 (untrusted deserialization flaw affecting Log4j version 1.2 - Fix is to upgrade to 2.17.0)

Check for CVE-2021-45105 (DoS vulnerability affecting versions 2.0-beta9 to 2.16.0)

.NOTES

#>


Write-Host -ForegroundColor DarkYellow "`nThis script will check the file system for any vulnerable log4j files."

# Display the current location
Write-Host "Current location: "(Get-Location)"`n"

# Get the path of the server list
$computerlist = Get-Content (Read-Host "Please enter path or name of file" )

# Write the server list to stout
Write-Host "`nPopulated list of server names below.`n`n"$computerlist

# Get the administrator credentials
$credential = Get-Credential -Message "Please enter administrator credentials for PSRemoting to work."

# The results of foreach is stored in invoke results for later output to CSV
$invokeresults = foreach ($computer in $computerlist){

        # Invokes command on remote computer.  Script block below searches through file system for log4j files.
        Invoke-Command -Computer $computer -Credential $credential -ScriptBlock { 
     
        # Create object for later excel file export.
        $computers_obj = $null
        $computers_obj = @()
        
        # Find any log4j vulnerable files
        Write-Host "Checking file system. Please wait..."
        
        # no native command to exclude a C:\Windows in Get-ChildItem but we'll get er done
        $root = (Get-ChildItem -Directory -Path "$env:SystemDrive\" | Where-Object {$_.Name -ne "Windows"})
        $recurse = Get-ChildItem -Path $root.'FullName' -Recurse -Include "log4j-core*","log4j-1*" -Exclude "log4j-core-2.17.0"  -File -ErrorAction SilentlyContinue
        
        # If recurse does not find any log4j files, it is not vulnerable
            if ($recurse -eq $null)
            
            {
            
                Write-Host -ForegroundColor Green "`n$env:COMPUTERNAME This computer does not have any log4j vulnerabilities."
                $details = 
                @{                     
                ComputerName = $env:COMPUTERNAME
                Vulnerable = "NO"
                }
            
                $computers_obj += New-Object PSObject -Property $details
                return $computers_obj
            
                
            }
            
            else
            
            {
            
                 Write-Host -ForegroundColor Red "`n$env:COMPUTERNAME Has vulnerable versions of log4j found.`n"
            
                 # we already filter out 2.17 in gci but we will make sure it's filtered out again anyway
                 $log4j_file = $recurse | Where-Object {$_.'Name' -notlike 'log4j-core-2.17*'}
                 $log4j_file.'Name'
            
                 # just in case there is more than one log4j file, write the results.
                 foreach ($item in $log4j_file)
                 {
            
            
                    $details = 
                    @{                     
                    ComputerName = $env:COMPUTERNAME
                    Path = "$($item.FullName)"
                    Vulnerable = "YES"
                    }
            
                    $computers_obj += New-Object PSObject -Property $details
                    return $computers_obj
            
                 }
            
                                
            
            # end else
            }
        
        # end invoke command
        }




    # end for loop
    }


    # Check to see if we want to export results to CSV.
    $prompt2 = Read-Host "Do you wish to export script findings to DESKTOP?  ENTER to EXPORT."

    if($prompt2 -eq "")

        {
            
            # We use select object here to ensure columes in CSV are in correct order
            $invokeresults | Select-Object ComputerName,Vulnerable,RunspaceId,Path | Export-Csv "$env:USERPROFILE\Desktop\log4j-local-scanresults.csv" -NoTypeInformation
        
        }

