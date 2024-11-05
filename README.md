```
     ___ ______ _     _          ___  ___            _ _             
    / _ \|  _  \ |   (_)         |  \/  |           (_) |            
   / /_\ \ | | | |    ___   _____| .  . | ___  _ __  _| |_ ___  _ __ 
   |  _  | | | | |   | \ \ / / _ \ |\/| |/ _ \| '_ \| | __/ _ \| '__|
   | | | | |/ /| |___| |\ V /  __/ |  | | (_) | | | | | || (_) | |   
   \_| |_/___/ \_____/_| \_/ \___\_|  |_/\___/|_| |_|_|\__\___/|_|   
                                                                                                
```

Tool for monitor Active Directory changes in real time without getting all objects.
It use replication metadata and Update Sequence Number (USN) to filter current properties of objects.
  
Forked from https://github.com/DrunkF0x/ADSpider   

## How to use
### Prerequisites
PowerShell module for Active Directory  
https://learn.microsoft.com/en-us/powershell/module/activedirectory/?view=windowsserver2022-ps  
### Domain computer
Just run module in powershell session from domain user. For better performance use domain controller FQDN instead of IP address.
```powershell
Import-Module .\ADLiveMonitor.ps1
Invoke-ADLiveMonitor
```
### Non-domain computer
Start powershell session with domain user with runas. Check that domain controller accessible. For better performance use domain controller FQDN instead of IP address.
```powershell
## From cmd or powershell
runas /netonly /u:TargetDomain.com\MyUser powershell

## From powershell
Import-module .\ADLiveMonitor.ps1
Invoke-ADLiveMonitor -DC DC01.TargetDomain.com
```

## Interesting links
https://premglitz.wordpress.com/2013/03/20/how-the-active-directory-replication-model-works/
https://learn.microsoft.com/en-us/archive/technet-wiki/51185.active-directory-replication-metadata  
https://learn.microsoft.com/en-us/windows/win32/adschema/a-systemflags   
https://learn.microsoft.com/en-us/windows/win32/ad/linked-attributes     
