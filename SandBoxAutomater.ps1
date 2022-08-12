<#
.SYNOPSIS
  Send files to Vision One SandBox
.DESCRIPTION
  Script for Trend Micro Vision One Sandbox Analytics
  Sending single file or files in directory into Sandbox Analytics (Zipping files into 1 archive)
  Retriving Status of the Scan submission

  This script is not developed or associated with Trend Micro, all runs is on your own responsibility.

  TODO: Move functions into modules etc
.PARAMETER Action
    ScanFile - Submitting single file to Sandbox.
    ScanDirectory - Submitting all supported files within the directory(Input: ScanDirectoryPath). The files will be zipped and sent to sandbox as 1 file
    GetAnalytics - Getting information about existing submission 
.PARAMETER ScanFilePath
    Provides Absolute path to file you want to send into sandbox
.PARAMETER ScanDirectoryPath
    Provides Absolute path to directory
.PARAMETER ScanningID
    Put in the scanningID you have recieved from submission in this script or from Vision One console.
    This Input is associated with Action: GetAnalytics
.PARAMETER WaitScanResult
    Waiting for the Sandbox Submission to be done.
.OUTPUTS
   Outputs to the logfile is: %ProgramData%\TrendMicroVisionOneSandBoxScanner\Log.txt
.NOTES
  Version:        0.1
  Author:         Soren Isager
  Creation Date:  21 May 2022
  Purpose/Change: Initial script development
  Github Link: https://github.com/sorenisager/TrendMicro-VisionOne-Sandbox-File-Folder-Checker
  License: MIT (No guarantee)
.LINK
 https://github.com/sorenisager/TrendMicro-VisionOne-Sandbox-File-Folder-Checker
.EXAMPLE
  Scan single file:
  SandBoxAutomater.ps1 -Action "ScanFile" -ScanFilePath "C:\Users\Soere\OneDrive\Skrivebord\putty.exe" -WaitScanResult
  SandBoxAutomater.ps1 -Action "ScanFile" -ScanFilePath "C:\Users\Soere\OneDrive\Skrivebord\putty.exe"
.EXAMPLE
  Scan files within directory (Zip as 1 file):
  SandBoxAutomater.ps1 -Action "ScanDirectory" -ScanDirectoryPath "C:\Users\Soere\Downloads\test" -WaitScanResult
  SandBoxAutomater.ps1 -Action "ScanDirectory" -ScanDirectoryPath "C:\Users\Soere\Downloads\test"
.EXAMPLE
  Get status of existing Sandbox Submission:
  SandBoxAutomater.ps1 -Action "GetAnalytics" -ScanningID "xxx-xxx-xxx-xxx-xxx"
  SandBoxAutomater.ps1 -Action "GetAnalytics" -ScanningID "xxx-xxx-xxx-xxx-xxx" -WaitScanResult
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, HelpMessage = "Action: ScanFile, ScanDirectory or GetAnalytics")] [ValidateSet("ScanFile", "ScanDirectory", "GetAnalytics")] [string] $Action,
    [Parameter(Mandatory = $false, HelpMessage = "The file path for the file you want to send to sandbox")] [string] $ScanFilePath,
    [Parameter(Mandatory = $false, HelpMessage = "The Folder/Directory path containing all the files you want to sandbox")] [string] $ScanDirectoryPath,
    [Parameter(Mandatory = $false, HelpMessage = "Provide the ScanningID if you already have done scanning.")] [string] $ScanningID,
    [Parameter(Mandatory = $false, HelpMessage = "Apply -WaitScanResult if you want to request data to sandbox and wait to it is finish")] [Switch] $WaitScanResult
)

#Requires -Version 7.0
#---------------------------------------------------------[Initialisations]--------------------------------------------------------

#Set Error Action to Silently Continue
$ErrorActionPreference = "SilentlyContinue"

$global:RunningUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$RunnerVersion = "0.1"



#----------------------------------------------------------[Declarations]----------------------------------------------------------

$GlobalConfiguration = "https://github.com/sorenisager/VisionOne-Sandbox-Powershell-Automater/blob/main/Webconfig.json"
$DefaultWorkingDirectory = "$($env:ProgramData)\TrendMicroVisionOneSandBoxScanner"
$ConfigurationFile = "$($DefaultWorkingDirectory)\ConfigurationFile.json"
$global:DefaultLogFile = "$($DefaultWorkingDirectory)\Log.txt"


#-----------------------------------------------------------[Functions]------------------------------------------------------------

function New-LogData {
    param (
        [Parameter(Mandatory = $true)]  [string] $LogMessage,
        [Parameter(Mandatory = $false)]  [switch] $WriteHost
    )

    ## Write to file
    Add-Content -Value "$(Get-date -Format "dd-MM-yyyy HH:mm:ss") : $($LogMessage)" -LiteralPath $global:DefaultLogFile

    # If switch is set
    if ($WriteHost) {
        write-host $LogMessage
    }
    
}

function Confirm-VisionOneConnection {
    param (
        [Parameter(Mandatory = $true)]  [string] $VisionOneToken,
        [Parameter(Mandatory = $true)]  [string] $VisionOneUrl
    )

    # Generate headers
    $Headers = @{
        'Authorization' = "Bearer $($VisionOneToken)"
    }


    try {
        New-LogData -LogMessage "Testing connection to: $($VisionOneUrl)" -WriteHost
        Invoke-RestMethod -Uri $VisionOneUrl -Headers $Headers -Method "GET"
    }
    catch {
        New-LogData -LogMessage "Could not connect to Vision One, verify your token + vision one region and try again!"
        throw "Could not connect to Vision One, verify your token + vision one region and try again!"
    }
    

    #Get Response
    try {
        New-LogData -LogMessage "Sucessfully establish connection to Vision One" -WriteHost
    }
    catch {
        New-LogData -LogMessage "Unable to establish connection to Vision One: $($VisionOneUrl)"
        throw "Unable to establish connection to Vision One: $($VisionOneUrl)"
    }
   
}

function Initialize-VisionOneSandboxAutomater {
    param (
        [Parameter(Mandatory = $true)]  [string] $GlobalConfiguration,
        [Parameter(Mandatory = $true)]  [string] $RunnerVersion,
        [Parameter(Mandatory = $true)]  [string] $DefaultWorkingDirectory,
        [Parameter(Mandatory = $true)]  [string] $ConfigurationFile
    )

    # Get Global Github Configuration File
    write-host "No configuration found...."
    write-host "Fetching online configuration "

    try {
        $GlobalConfigurationResponse = Invoke-RestMethod -Method "GET" -Uri $GlobalConfiguration
    }
    catch {
        throw "Could not retrieve online configuration schema :( - try again later... ($($GlobalConfiguration))"
    }
    

    # Get VisionOne Token
    ## TODO: Add the VisionOne Token from param instead
    $VisionOneToken = Read-Host -Prompt "Please insert VisionOne Token:" -MaskInput

    # Verify VisionOneToken
    if (!($VisionOneToken)) {
        throw "No Vision One token was entered!"
    }

    # Get VisionOne URL
    ## TODO: Remove Regions here, add it as param
    $Region = (($GlobalConfigurationResponse.$RunnerVersion.VisionOneAPI.Regions).PSObject.Properties | Select-Object Name, Value | Out-gridview -PassThru -Title "Select Region").Name

    # Verify VisionOneToken
    if (!($Region)) {
        throw "No Vision Region was selected!"
    }
        
    # Get VisionOne URL
    ## TODO: Remove Vision One URL here, add it as param
    $APIVersion = (($GlobalConfigurationResponse.$RunnerVersion.VisionOneAPI.APIVersion).PSObject.Properties | Select-Object Name | Out-gridview -PassThru -Title "Select API version").Name

    # Verify APIVersion
    if (!($APIVersion)) {
        write-host "No Vision One APIVersion was selected!"
        throw "No Vision One APIVersion was selected!"
    }

    # Test Connection
    Confirm-VisionOneConnection `
        -VisionOneToken $VisionOneToken `
        -VisionOneUrl "$($GlobalConfigurationResponse.$RunnerVersion.VisionOneAPI.Regions.$Region)$($GlobalConfigurationResponse.$RunnerVersion.VisionOneAPI.APIVersion.$APIVersion.GetDailyReserve)"
    
        
    # Verify WorkingDirectory is created - if not create it
    if (!(Test-Path -Path $DefaultWorkingDirectory)) {
        # Create Script Directory
        New-LogData -LogMessage "Creating Directory: $($DefaultWorkingDirectory)" -WriteHost
        New-Item -ItemType Directory -Path $DefaultWorkingDirectory | Out-Null
    }

    # Convert VisionOneToken to SecureString
    New-LogData -LogMessage "Encrypting the Vision One API key." -WriteHost
    $VisionOneSecureToken = $VisionOneToken | ConvertTo-SecureString -AsPlainText -Force | ConvertFrom-SecureString

    New-LogData -LogMessage "Creating configuration.." -WriteHost
    # Make Configuration Settings
    ## TODO: Get schema from the repo instead of making it static here...
    @{
        "VisionOneAPI"          = @{
            "VisionOneToken"                = $VisionOneSecureToken
            "VisionOneAPIBaseUrl"           = $GlobalConfigurationResponse.$RunnerVersion.VisionOneAPI.Regions.$Region
            "VisionOneAPISubmitFileUrlPath" = $GlobalConfigurationResponse.$RunnerVersion.VisionOneAPI.APIVersion.$APIVersion.SubmitFileToSandbox
            "VisionOneAPIGetStatusUrlPath"  = $GlobalConfigurationResponse.$RunnerVersion.VisionOneAPI.APIVersion.$APIVersion.GetAnalysisResults
        }
        "ScanningConfiguration" = @{
            "ScanIntervalSeconds"             = $GlobalConfigurationResponse.$RunnerVersion.DefaultConfiguration.ScanIntervalSeconds
            "ScanMaxFileSizeMB"               = $GlobalConfigurationResponse.$RunnerVersion.DefaultConfiguration.ScanMaxFileSizeMB
            "ScanResultWaitIterations"        = $GlobalConfigurationResponse.$RunnerVersion.DefaultConfiguration.ScanResultWaitIterations
            "ScanResultWaitSleepTimerSeconds" = $GlobalConfigurationResponse.$RunnerVersion.DefaultConfiguration.ScanResultWaitSleepTimerSeconds
            "ScanningPaths"                   = @()
            "AllowedExtensions"               = $GlobalConfigurationResponse.$RunnerVersion.DefaultConfiguration.AllowedExtensions
        }
        "SystemConfiguration"   = @{
            "ConfigurationCreatedBy"  = $global:RunningUser
            "ConfigurationCreated"    = (Get-Date -Format "dd-MM-yyyy")
            "DefaultWorkingDirectory" = $DefaultWorkingDirectory
            "VisionOneScannerVersion" = $RunnerVersion
        }
    } | ConvertTo-Json | Out-File $ConfigurationFile # Save configuration to the configuration file based on Json
    New-LogData -LogMessage "Saved configuration sucessfully.." -WriteHost
    
    
}


function Get-VisionOneConfiguration {
    param (
        [Parameter(Mandatory = $true)]  [string]  $ConfigurationFile
    )

    try {

        if (Test-Path -Path $ConfigurationFile) {
            # ConfigurationFile is found - Return
            write-host "Loading Configuration..." -NoNewline
            $Configuration = Get-Content -LiteralPath $ConfigurationFile | ConvertFrom-Json
            write-host " Done" -ForegroundColor Green

            Return $Configuration
        }
        else {
            return $false
        }
    }
    catch {
        throw $Error[0]
    }
    
    
}

function Get-EncryptedValue {
    param (
        [Parameter(Mandatory = $true)]  [string]  $SecureStringValue
    )

    try {

        # DecryptPassword
        $PlainPassword = $SecureStringValue | ConvertTo-SecureString
        $Ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToCoTaskMemUnicode($PlainPassword)
        $UnsecureSecureValue = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($Ptr)
        [System.Runtime.InteropServices.Marshal]::ZeroFreeCoTaskMemUnicode($Ptr)
        
        return $UnsecureSecureValue
    }
    catch {
        New-LogData -LogMessage $Error[0]
        write-error $Error[0]
    }
}

function New-SandboxFile {
    param (
        [Parameter(Mandatory = $true)]  [PSCustomObject]  $Configuration,
        [Parameter(Mandatory = $true)]  [string]  $ScanFilePath
    )

    

    try {
        # 1. Check if file exists
        if (Test-Path -Path $ScanFilePath) {
            
            # Variables
            $APIURI = "$($Configuration.VisionOneAPI.VisionOneAPIBaseUrl)$($Configuration.VisionOneAPI.VisionOneAPISubmitFileUrlPath)"
            $UnsecureVisionOneToken = Get-EncryptedValue -SecureStringValue $Configuration.VisionOneAPI.VisionOneToken


        
            # 2. Generate Headers
            $Headers = @{
                'Authorization' = "Bearer $($UnsecureVisionOneToken)"
            }

            $Body = @{
                "file"             = Get-Item -Path $ScanFilePath
                "documentPassword" = ""
                "archivePassword"  = ""
            }
            

            #Send to Sandbox
            write-host "Sending: $($ScanFilePath) to Analysis" -NoNewline
            $Response = Invoke-RestMethod -Uri $APIURI -Headers $Headers -Method "POST" -form $Body
            write-host " Done" -ForegroundColor green

            # Add log entry
            New-LogData -LogMessage "New submission created - ID: $($Response.id)"
            
            
            $SandboxCorrelationID = $Response.id
            write-host " SCANNING ID: $($SandboxCorrelationID)" -ForegroundColor RED


            # If Wait on response is enabled, Call Function
            if ($WaitScanResult) {
                Get-AnalyticsStatus -Configuration $Configuration -ScanningID $SandboxCorrelationID
            }

            
        }

    }
    catch {
        New-LogData -LogMessage $Error[0]
        write-host $Error[0]
    }
    
}

function CheckFile {
    param (
        [Parameter(Mandatory = $true)]  [string]  $ScanFilePath
    )

    # Get File
    $FileObject = Get-Item -Path $ScanFilePath

    # Check if file exists
    if ($FileObject) {

        # Check if file extension is supported
        if ($Configuration.ScanningConfiguration.AllowedExtensions -contains $FileObject.Extension) {
                    
            # File is supported, Check size MAX 60 MB
            if (($FileObject.Length / 1MB) -gt $Configuration.ScanningConfiguration.ScanMaxFileSizeMB) {
                
                # File size is not supported
                New-LogData -LogMessage "File size is too big"
                throw "File size is too big"
            }
        }
        else {
            New-LogData -LogMessage "File extension is not supported"
            throw "File extension is not supported"
        }
    }
    else
    {
        New-LogData -LogMessage "Could not find file requested!"
        throw "Could not find file requested!"
    }
}

function Get-AnalyticsStatus {
    param (
        [Parameter(Mandatory = $true)]  [PSCustomObject]  $Configuration,
        [Parameter(Mandatory = $true)]  [string]  $ScanningID
    )

    # Variables
    $APIURI = "$($Configuration.VisionOneAPI.VisionOneAPIBaseUrl)$($Configuration.VisionOneAPI.VisionOneAPIGetStatusUrlPath)/$($ScanningID)"
    $UnsecureVisionOneToken = Get-EncryptedValue -SecureStringValue $Configuration.VisionOneAPI.VisionOneToken



    # 2. Generate Headers
    $Headers = @{
        'Authorization' = "Bearer $($UnsecureVisionOneToken)"
    }

    # Check if we need to wait for the result
    if ($WaitScanResult) {

        # Get Status
        $SandboxAnalyticsDone = $false
        $i = 0
        do {
            write-host "Getting status from Vision One... $(Get-Date)" -ForegroundColor Green
            
            # Check if we need to wait until the scan result
            try {
                $AnalyticsResponse = Invoke-RestMethod -Uri $APIURI -Headers $Headers -Method "Get"
               
                # Response is good
                write-host "Sandbox Submission is done..:"
                New-LogData -LogMessage "Submission done ID: $($ScanningID) --> $($AnalyticsResponse | Out-String)"
                
                # Exit
                $SandboxAnalyticsDone = $true
                return $AnalyticsResponse
            }
            catch {
                # Still waiting to be done...
                Start-Sleep -Seconds $Configuration.ScanningConfiguration.ScanResultWaitSleepTimerSeconds

                $i++

                if ($i -ge $Configuration.ScanningConfiguration.ScanResultWaitIterations) {
                    throw "Operation timed out, taking longer that it should.. Go into the Vision One portal and see status of the scanningid: $($ScanningID)"
                }
            }

        }
        until($SandboxAnalyticsDone -eq $true)

    }
    else {
        # Get Status
        $Response = Invoke-RestMethod -Uri $APIURI -Headers $Headers -Method "Get"


        if ($Response.riskLevel) {
            # Response is good
            New-LogData -LogMessage "Sandbox Submission is done..:" -WriteHost
            return $Response
        }
        else {
            # Response is not good yet
            New-LogData -LogMessage "Sandbox Submission is either not found or not finish." -WriteHost
            return $false
        }
    }    
}

#-----------------------------------------------------------[Execution]------------------------------------------------------------


try {
    # 1. Load Configuration
    $Configuration = Get-VisionOneConfiguration -ConfigurationFile $ConfigurationFile

    # No Configuration Exists, Gather the global configuration
    if (!($Configuration)) {

        # Initialize VisionOne Sandbox Automater (Setup)
        Initialize-VisionOneSandboxAutomater `
            -GlobalConfiguration $GlobalConfiguration `
            -RunnerVersion $RunnerVersion `
            -DefaultWorkingDirectory $DefaultWorkingDirectory `
            -ConfigurationFile $ConfigurationFile `
            -ErrorAction SilentlyContinue


        # Stop execution
        New-LogData -LogMessage "Initial Configuration Successfully Done.. Please run command again!" -WriteHost
        Exit 200
    }
  
    # 2. Check Action
    switch ($Action) {
        "ScanFile" {
            
            # Check if ScanFile Path is set
            if (!($ScanFilePath)) {
                $ScanFilePath = Read-Host "Please enter full path of file:"
            }

            try {
                # Check File
                CheckFile -ScanFilePath $ScanFilePath

                # Start Scan of file
                New-SandboxFile -Configuration $Configuration -ScanFilePath $ScanFilePath
            }
            catch {
                write-host "File: $($File.FullName) not supported: $($Error[0])" -ForegroundColor Yellow
            }

        }
        "ScanDirectory" {
            
            # Variables
            $FilesToArchive = @()
            $FailedFilesToArchive = @()
            $ScanCorrelationID = [guid]::NewGuid().Guid
            $ArchiveFullPath = "$($Configuration.SystemConfiguration.DefaultWorkingDirectory)/$($ScanCorrelationID).zip"

            # Check if Scan directory Path is set
            if (!($ScanDirectoryPath)) {
                $ScanDirectoryPath = Read-Host "Please enter full path of directory"
            }

            # Get Files in Directory
            $FilesToScan = Get-ChildItem -LiteralPath $ScanDirectoryPath -Recurse


            # Foreach File 
            foreach ($File in $FilesToScan) {

                # Check File
                try {
                    # Check file extension & size
                    CheckFile -ScanFilePath $File.FullName

                    # File is supported
                    New-LogData -LogMessage "File: $($File.FullName) Is supported and added to the archive" -WriteHost

                    # File is supported, add to list of files needed to be in archived file
                    $FilesToArchive += $File.FullName
                }
                catch {
                    # Files was not supported
                    write-host "File: $($File.FullName) not supported: $($Error[0])" -ForegroundColor Yellow

                    # Add to Array
                    $FailedFilesToArchive += $File.FullName
                }

            }

            # If there is any files sucessfully checked, add those to Archive
            if ($FilesToArchive.Length -gt 0) {

                try {
                    # Create Archive with all the files
                    Get-ChildItem -LiteralPath $FilesToArchive | Compress-Archive -DestinationPath $ArchiveFullPath

                    # Send file to sandbox
                    New-SandboxFile -Configuration $Configuration -ScanFilePath $ArchiveFullPath
                }
                catch {
                    write-host "Unable to send archived file to sandbox: $($ArchiveFullPath): $($Error[0])" -ForegroundColor Red
                }
                
            }
            else {
                write-host "No file in the directory is supported or found..." -ForegroundColor Red
            }
                

        }
        "GetAnalytics" {

            # Check if Scanning id is provided
            if (!($ScanningID)) {
                $ScanningID = Read-Host "Please enter Scan ID"
            }

            # Check if we need to wait until the scan result
            Get-AnalyticsStatus -Configuration $Configuration -ScanningID $ScanningID
        }
        Default {
            New-LogData -LogMessage "No option selected"
            throw "No option selected"
        }
    }

}
catch {
    Write-Warning $Error[0]
}


