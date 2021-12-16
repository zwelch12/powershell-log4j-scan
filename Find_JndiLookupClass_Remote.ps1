# https://logging.apache.org/log4j/2.x/security.html

# Check for CVE-2021-45046 (2.0-beta9 through 2.12.1 and 2.13.0 through 2.15.0)
# Mitigation - remove the JndiLookup class from the classpath or upgrade to 2.16.0 (Java 8) or 2.12.2 (Java 7)

# Check for CVE-2021-44228 (all versions from 2.0-beta9 through 2.12.1 and 2.13.0 through 2.14.1)
# Mitigation - remove the JndiLookup class from the classpath or upgrade to 2.16.0 (Java 8) or 2.12.2 (Java 7)

#Non-domain joined computers PS Remote

$path = Get-Location
Write-Host "Current location: $path`n"

$computerlist_path = Read-Host "Please enter path or name of file" 

$computerlist = Get-Content $computerlist_path

Write-Host "`nPopulated list of server names below.`n"
$computerlist
pause

# load in export function
function export(){
$prompt3 = Read-Host "Do you wish to export script findings? (Results exported to desktop) ENTER to EXPORT."
if($prompt3 -eq ""){

$invokeresults | Select-Object ComputerName,Vulnerable,RunspaceId,Path | Export-Csv "$env:USERPROFILE\Desktop\log4j-local-scanresults.csv" -NoTypeInformation
        }
}

$creds = Get-Credential

$invokeresults = foreach ($computer in $computerlist){


Invoke-Command -Computer $computer -Credential $creds -ScriptBlock { 

#load in the .NET assemblies
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem

# Just in case the zip file is not cleaned from previous runtime.
#$zip.Dispose()
#$stream.Close()
#$stream.Dispose()

Write-Host -ForegroundColor DarkYellow "`nThis script will check the file system for any vulnerable log4j files.`nOPTIONALLY, this script can delete JndiLookup.Class"
$prompt1 = Read-Host "Press ENTER to run this script on $($env:COMPUTERNAME)"


if ($prompt1 -eq ""){

# Find any log4j vulnerable files
Write-Host "Checking file system. Please wait..."
$recurse = Get-Childitem –Path 'C:\' -Include *log4j-core-* -Exclude *log4j-core-2.16* -File -Recurse -ErrorAction SilentlyContinue

# Create object for later excel file export.
$computers_obj = $null
$computers_obj = @()

# If recurse does not find any log4j files, it is not vulnerable
if ($recurse -eq $null){

    Write-Host -ForegroundColor Green "`n$Computername This computer does not have any log4j vulnerabilities."
    $details = @{                     
    ComputerName = $env:COMPUTERNAME
    Vulnerable = "NO"
    }
    $computers_obj += New-Object PSObject -Property $details
    return $computers_obj
    
}

# If recurse DOES return log4j files, run through .ZIP routine to check for JndiLookup.Class
elseif($recurse -ne $null){


    Write-Host -ForegroundColor Green "`n$Computername This computer is potientially vulnerable to log4j. Checking for JndiLookup.Class"
    sleep 5


ForEach ($log4j_file in $recurse){

$stream = New-Object IO.FileStream($log4j_file, [IO.FileMode]::Open)
$mode   = [System.IO.Compression.ZipArchiveMode]::Update
$zip    = New-Object IO.Compression.ZipArchive($stream, $mode)


$jndilookup_bool = ($zip.Entries | Where-Object {$_.Name -contains "JndiLookup.class"}) 

        if ($jndilookup_bool) {

        ForEach-Object { 

                Write-Host -ForegroundColor Red "Found JndiLookup.class in $($log4j_file.FullName)"
                
               
                Write-Host "Do you wish to delete the JndiLookup.class file?"
                $prompt2 = Read-Host "NOTE: PLEASE STOP ASSOCIATED PROGRAM, THEN START AFTER DELETION. `n Enter Y/N to delete"
                
                if ($prompt2 -eq "Y" -or $prompt2 -eq "y"){

                #$jndilookup_bool.Delete(); Write-Host "Deleted JndiLookup.Class file!"

                $details = @{                     
                ComputerName = $env:COMPUTERNAME
                Path = "$($log4j_file.FullName)"
                Vulnerable = "NO (mitigated)"
                }
                $computers_obj += New-Object PSObject -Property $details
                return $computers_obj

                }
                else{

                $details = @{                     
                ComputerName = $env:COMPUTERNAME
                Path = "$($log4j_file.FullName)"
                Vulnerable = "YES"
                }
                $computers_obj += New-Object PSObject -Property $details
                return $computers_obj


                }
                
             }

        }
         else{

          $details = @{                     
          ComputerName = $env:COMPUTERNAME
          Path = $($log4j_file.FullName)
          Vulnerable = "NO"
          }
          $computers_obj += New-Object PSObject -Property $details

          Write-Host -ForegroundColor Green "NO JndiLookup.class located in $($log4j_file.FullName)"

            

    }

    

# Clean up opened .JAR files
$zip.Dispose()
$stream.Close()
$stream.Dispose()

}

#export


}

}

# end script block
}


}


export
Write-Host -ForegroundColor Red "`n`tExported results to $($env:USERPROFILE)\Desktop`n`n"



pause
