# Trend Micro Vision One Sandbox Automater

This script enables you to automated send files to Trend Micro Vision One Sandbox, to dethermine if file(s) contains bad code.

Everytime the script runs, it checks the local configuration file. If the configuration file does not exist it will require you to insert Vision One token, Which Region your Vision One instance is located and which version of the API you want to use.

You can either select a single file or a directory. If you choose directory it will zip all files within the directory and send only 1 file to Vision One Sandbox.

## Setup
First time you run the script it will detect if configuration file exist. If no configuration file exist it will get the schema from the github and add configurationfile.

The configuration file will contain encrypted Vision One token, Scan configuration and file extension support.

## Examples
> The use of : -WaitScanResult will query the Vision One API every 10 seconds for response on the submission.
### Scan single file:
- SandBoxAutomater.ps1 -Action "ScanFile" -ScanFilePath "C:\temp\file.exe" -WaitScanResult
- SandBoxAutomater.ps1 -Action "ScanFile" -ScanFilePath "C:\temp\file.exe
### Scan files within directory (Zip as 1 file):
- SandBoxAutomater.ps1 -Action "ScanDirectory" -ScanDirectoryPath "C:\temp" -WaitScanResult
- SandBoxAutomater.ps1 -Action "ScanDirectory" -ScanDirectoryPath "C:\temp"
### Get status of existing Sandbox Submission:
- SandBoxAutomater.ps1 -Action "GetAnalytics" -ScanningID "xxx-xxx-xxx-xxx-xxx"
- SandBoxAutomater.ps1 -Action "GetAnalytics" -ScanningID "xxx-xxx-xxx-xxx-xxx" -WaitScanResult

## Security
The Vision One Token is encrypted in user-context which means you have to run the script as the same user as when the configuration file was created.

## Configuration File
```json
{
  "VisionOneAPI": {
    "VisionOneAPIGetStatusUrlPath": "/beta/xdr/sandbox/analysisResults",
    "VisionOneAPISubmitFileUrlPath": "/beta/xdr/sandbox/files/analyze",
    "VisionOneAPIBaseUrl": "https://api.xdr.trendmicro.com",
    "VisionOneToken": ""
  },
  "ScanningConfiguration": {
    "ScanResultWaitSleepTimerSeconds": 10,
    "AllowedExtensions": [
      ".exe",
      ".pdf"
    ],
    "ScanIntervalSeconds": 60,
    "ScanResultWaitIterations": 120,
    "ScanningPaths": [],
    "ScanMaxFileSizeMB": 60
  },
  "SystemConfiguration": {
    "VisionOneScannerVersion": "0.1",
    "ConfigurationCreated": "04-08-2022",
    "DefaultWorkingDirectory": "C:\\ProgramData\\TrendMicroVisionOneSandBoxScanner",
    "ConfigurationCreatedBy": "ISAGERPC\\Soere"
  }
}

```


## Usage & License
***This script is not associated and developed by Trend Micro.***

MIT license

## TODOs
- Split functions into modules
- Move some local properties in configuration file into cloud
- Move Configuration File to User-Directory, as the token is encrypted in user-context. If running VDI/Terminal Server todays solution will be difficult to run as the configuration file is located same path globally. (You could in fact change it in the script)
- Support response actions
  - Removing file on origin location
  - Move files into directories after scan completed
- Notifications
