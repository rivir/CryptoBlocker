##CRYPTO BLOCKER TO ALL SERVERS in $servers array

#SETUP ON SERVERS
#PSv3 and REMOTE PS
# $psversiontable
#get-service winrm
#Enable-PSRemoting –force
#firewall rule remote FSRM

$servers = @{SERVERNAME='DRIVELETTER'; SERVER2='D'}


$fileGroupName = "1-PreventCrypto"
$fileTemplateName = "1-PreventCrypto"
$fileScreenName = "1-PreventCrypto"
$eventConfFilename = "\\servername\cryptoblocker-eventnotify.txt"
$mailConfFilename = "\\servername\cryptoblocker-mailnotify.txt"


$webClient = New-Object System.Net.WebClient
$jsonStr = $webClient.DownloadString("https://fsrm.experiant.ca/api/v1/get")
$monitoredExtensions = @(ConvertFrom-Json20($jsonStr) | % { $_.filters })
       
        ######**********remove unwanted filters v5
$Exclusions = @('*.stn','*.one')
$monitoredExtensions = $monitoredExtensions | Where-Object { $Exclusions -notcontains $_ }
        ######**********remove unwanted filters v5

function Deploy-CryptoBlock
{
    [CmdletBinding()]
    param 
    (
        [Parameter(Position=0,
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true)]
        [Alias('hostname')]
        [Alias('cn')]
        [hashtable]$ComputerName = $env:COMPUTERNAME,
        
        [Parameter(Position=1,
                   Mandatory=$false)]
        [Alias('runas')]
        [System.Management.Automation.Credential()]$Credential =
        [System.Management.Automation.PSCredential]::Empty
        
    )
    
    BEGIN
    {
       

    }
    
    PROCESS
    {
        foreach ($computer in $ComputerName.Keys|Sort)
        {
            try
            {

                    # Split the $monitoredExtensions array into fileGroups of less than 4kb to allow processing by filescrn.exe
                    $fileGroups = New-CBArraySplit $monitoredExtensions
                    ForEach ($group in $fileGroups) {
                        $group | Add-Member -MemberType NoteProperty -Name fileGroupName -Value "$FileGroupName$($group.index)"
                    }

                    Write-Host "***" -foregroundcolor "magenta"
                     Write-Host $computer -foregroundcolor "magenta"
                      Write-Host "***" -foregroundcolor "magenta"
                    # Perform these steps for each of the 4KB limit split fileGroups
                    ForEach ($group in $fileGroups) {
                        Write-Host "Adding/replacing File Group [$($group.fileGroupName)] with monitored file.." ##Too much text## [$($group.array -Join ",")].."
                         &filescrn.exe filegroup Delete "/Filegroup:$($group.fileGroupName)" /Quiet /remote:$computer
                         &filescrn.exe Filegroup Add "/Filegroup:$($group.fileGroupName)" "/Members:$($group.array -Join '|')" /remote:$computer
                        
                    }
                    ##FALSE POSITIVE, EXEMPTIONS##
                    &filescrn.exe Filegroup Modify "/Filegroup:$($group.fileGroupName)" "/NonMembers:*CrystalReports*" /remote:$computer
                    
                    Write-Host "Adding/replacing File Screen Template [$fileTemplateName] with Event Notification [$eventConfFilename] and Command Notification [$cmdConfFilename].."
                    &filescrn.exe Template Delete /Template:$fileTemplateName /Quiet  /remote:$computer
                    # Build the argument list with all required fileGroups
                    $screenArgs = 'Template','Add',"/Template:$fileTemplateName"
                    ForEach ($group in $fileGroups) {
                        $screenArgs += "/Add-Filegroup:$($group.fileGroupName)"
                    }

                    &filescrn.exe $screenArgs /remote:$computer
                    Write-Host "Adding/replacing File Screens.."
                    $drivesContainingShares = $ComputerName.$computer+":\"
                    $drivesContainingShares | % {
                        Write-Host "`tAdding/replacing File Screen for [$_] with Source Template [$fileTemplateName].."
                        &filescrn.exe Screen Delete "/Path:$_" /Quiet /remote:$computer         
                        &filescrn.exe Screen Add "/Path:$_" "/SourceTemplate:$fileTemplateName" "/type:active" "/add-notification:m,$mailConfFilename" "/add-notification:e,$eventConfFilename" /remote:$computer
              }
            }
            catch 
            {
                # Check for common DCOM errors and display "friendly" output
                switch ($_)
                {
                    { $_.Exception.ErrorCode -eq 0x800706ba } `
                        { $err = 'Unavailable (Host Offline or Firewall)'; 
                            break; }
                    { $_.CategoryInfo.Reason -eq 'UnauthorizedAccessException' } `
                        { $err = 'Access denied (Check User Permissions)'; 
                            break; }
                    default { $err = $_.Exception.Message }
                }
                Write-Warning "$computer - $err" -foregroundcolor "red"
            } 
        }
    }
    
    END {}
}


Deploy-CryptoBlock -cn $servers -Verbose

################################ Functions ################################

function ConvertFrom-Json20([Object] $obj)
{
    Add-Type -AssemblyName System.Web.Extensions
    $serializer = New-Object System.Web.Script.Serialization.JavaScriptSerializer
    return ,$serializer.DeserializeObject($obj)
}

Function New-CBArraySplit {

    param(
        $extArr,
        $depth = 1
    )

    $extArr = $extArr | Sort-Object -Unique
    # Concatenate the input array
    $conStr = $extArr -join ','
    $outArr = @()

    # If the input string breaks the 4Kb limit
    If ($conStr.Length -gt 4096) {
        # Pull the first 4096 characters and split on comma
        $conArr = $conStr.SubString(0,4096).Split(',')
        # Find index of the last guaranteed complete item of the split array in the input array
        $endIndex = [array]::IndexOf($extArr,$conArr[-2])
        # Build shorter array up to that indexNumber and add to output array
        $shortArr = $extArr[0..$endIndex]
        $outArr += [psobject] @{
            index = $depth
            array = $shortArr
        }

        # Then call this function again to split further
        $newArr = $extArr[($endindex + 1)..($extArr.Count -1)]
        $outArr += New-CBArraySplit $newArr -depth ($depth + 1)
        
        return $outArr
    }
    # If the concat string is less than 4096 characters already, just return the input array
    Else {
        return [psobject] @{
            index = $depth
            array = $extArr
        }  
    }
}

################################ Functions ################################


