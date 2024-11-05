Function Invoke-ADLiveMonitor {
    #requires -Modules ActiveDirectory
    <#
        .SYNOPSIS
        ADLiveMonitor monitor any replicated changes in Microsoft Active Direcotry, catching all changes performed on any objects.

        .DESCRIPTION
        ADLiveMonitor use USN to monitor any replicated changes in Microsoft Active Direcotry, catching all changes performed on any objects.

        .PARAMETER DC
        Domain Controller FQDN.

        .PARAMETER ExcludeLastLogonTimestamp
        Exclude lastLogonTimestamp events from output.

        .PARAMETER DumpAllObjects
        Dump all Active Directory objects before start. In case of changes It will show you all previous values. But in large domains use it on your own risk (time and resource consuming).

        .PARAMETER Output
        Create XML file with all output.

        .PARAMETER ExcludeObjectGUID
        Exclude Active Directory object with specific GUID.

        .PARAMETER Sleep
        Time interval between requests for USN number. By default - 30 seconds.

        .PARAMETER USN
        Specify started USN.
    #>
    Param(
        [CmdletBinding()]
        [String]$DC,

        [PSCredential]$Credentials,

        [Switch]$ExcludelastLogonTimestamp,

        [Switch]$DumpAllObjects,

        [String]$Output,

        [Array]$ExcludeObjectGUID,

        [Int]$Sleep = 30,

        [Int]$USN
    )

    #region Functions
    Function Convert-UAC {
        Param(
            [int]$UAC
        )

        $UACPropertyFlags = @('SCRIPT', 'ACCOUNTDISABLE', 'RESERVED', 'HOMEDIR_REQUIRED', 'LOCKOUT', 'PASSWD_NOTREQD', 'PASSWD_CANT_CHANGE', 'ENCRYPTED_TEXT_PWD_ALLOWED', 'TEMP_DUPLICATE_ACCOUNT', 'NORMAL_ACCOUNT', 'RESERVED', 'INTERDOMAIN_TRUST_ACCOUNT', 'WORKSTATION_TRUST_ACCOUNT', 'SERVER_TRUST_ACCOUNT', 'RESERVED', 'RESERVED', 'DONT_EXPIRE_PASSWORD', 'MNS_LOGON_ACCOUNT', 'SMARTCARD_REQUIRED', 'TRUSTED_FOR_DELEGATION', 'NOT_DELEGATED', 'USE_DES_KEY_ONLY', 'DONT_REQ_PREAUTH', 'PASSWORD_EXPIRED', 'TRUSTED_TO_AUTH_FOR_DELEGATION', 'RESERVED', 'PARTIAL_SECRETS_ACCOUNT', 'RESERVED', 'RESERVED', 'RESERVED', 'RESERVED', 'RESERVED')
        return (0..($UACPropertyFlags.Length) | where-object {$UAC -bAnd [math]::Pow(2,$_)} | foreach-object {$UACPropertyFlags[$_]}) -join ' | '
    }
    Function Write-LogEntry {
        <#
            .SYNOPSIS
            Write formated entry in the PowerShell Host and a file.
    
            .DESCRIPTION
            Function to write message within the PowerShell Host and persist it into a select file.
    
            .PARAMETER Info
            Message to write as basic information.
            It will be displayed as Verbose in the PowerShell Host.
    
            .PARAMETER Warning
            Message to write as a warning information.
            It will be displayed as Warning in the PowerShell Host.
    
            .PARAMETER Debugging
            Message to write as a debugging information.
            It will be displayed as Debug in the PowerShell Host
    
            .PARAMETER ErrorMessage
            Message to write as error information.
            It will be de displayed as an Error message in the PowerShell Host.
    
            .PARAMETER Success
            Message to write as a success information.
            It will be displayed in grenn as a successfull message in the PowerShell Host.
    
            .PARAMETER ErrorRecord
            Used to complete the ErrorMessage parameter with the Error Object that may have been generated.
            This information will be displayed in the persistance file.
    
            .PARAMETER LogFile
            Specify the file to write messages in.
    
            .EXAMPLE
            Write-LogEntry -Info 'Test log entry' -LogFile 'C:\Logs\TestLogFile.log'
            
            Will output in Write-Verbose and in specified log file the specified Info string.
    
            .EXAMPLE
            Write-LogEntry -Warning 'Test log entry' -LogFile 'C:\Logs\TestLogFile.log'
            
            Will output in Write-Warning and in specified log file the specified Info string.
    
            .EXAMPLE
            Write-LogEntry -Debugging 'Test log entry' -LogFile 'C:\Logs\TestLogFile.log'
            
            Will output in Write-Debug and in specified log file the specified Info string.
    
            .EXAMPLE
            Write-LogEntry -ErrorMessage 'Test log entry' -ErrorRecord Value -LogFile 'C:\Logs\TestLogFile.log'
            
            Will output using Write-Host (sadly) with a red foreground and in specified log file the specified Info string.
    
            .EXAMPLE
            Write-LogEntry -Success 'Test log entry' -LogFile 'C:\Logs\TestLogFile.log'
            
            Will output using Write-Host (sadly) with a green foreground and in specified log file the specified Info string.
    
            .NOTES
            Author: Thomas Prud'homme (Blog: https://blog.prudhomme.wtf Tw: @Prudhomme_WTF).
    
            .LINK
            https://github.com/PrudhommeWTF/Stuffs/blob/master/Write-LogEntry/Write-LogEntry.md
    
            .INPUTS
            System.String
    
            .OUTPUTS
            System.IO.File
        #>
        [CmdletBinding(
            DefaultParameterSetName = 'Info', 
            SupportsShouldProcess   = $true, 
            ConfirmImpact           = 'Medium',
            HelpUri                 = 'https://github.com/PrudhommeWTF/Stuffs/blob/master/Write-LogEntry/Write-LogEntry.md'
        )]
        Param(
            [Parameter(
                Mandatory                       = $true, 
                ValueFromPipelineByPropertyName = $true,
                ParameterSetName                = 'Info'
            )]
            [ValidateNotNullOrEmpty()]
            [Alias('Message')]
            [String]$Info,
     
            [Parameter(
                Mandatory                       = $true, 
                ValueFromPipelineByPropertyName = $true,
                ParameterSetName                = 'Warning'
            )]
            [ValidateNotNullOrEmpty()]
            [String]$Warning,
     
            [Parameter(
                Mandatory                       = $true, 
                ValueFromPipelineByPropertyName = $true,
                ParameterSetName                = 'Debugging'
            )]
            [ValidateNotNullOrEmpty()]
            [String]$Debugging,
     
            [Parameter(
                Mandatory                       = $true, 
                ValueFromPipelineByPropertyName = $true,
                ParameterSetName                = 'ErrorMessage'
            )]
            [ValidateNotNullOrEmpty()]
            [String]$ErrorMessage,
     
            [Parameter(
                Mandatory                       = $true, 
                ValueFromPipelineByPropertyName = $true,
                ParameterSetName                = 'Success'
            )]
            [ValidateNotNullOrEmpty()]
            [String]$Success,
     
            [Parameter( 
                ValueFromPipeline               = $true,
                ValueFromPipelineByPropertyName = $true, 
                ValueFromRemainingArguments     = $false, 
                ParameterSetName                = 'ErrorMessage'
            )]
            [ValidateNotNullOrEmpty()]
            [Alias('Record')]
            [Management.Automation.ErrorRecord]$ErrorRecord,
     
            [Parameter(
                Mandatory = $true,
                ValueFromPipelineByPropertyName = $true, 
                ParameterSetName                = 'Info'
            )]
            [Parameter(
                Mandatory = $true,
                ValueFromPipelineByPropertyName = $true, 
                ParameterSetName                = 'Warning'
            )]
            [Parameter(
                Mandatory = $true,
                ValueFromPipelineByPropertyName = $true, 
                ParameterSetName                = 'Debugging'
            )]
            [Parameter(
                Mandatory = $true,
                ValueFromPipelineByPropertyName = $true, 
                ParameterSetName                = 'Success'
            )]
            [Parameter(
                Mandatory = $true,
                ValueFromPipelineByPropertyName = $true, 
                ParameterSetName                = 'ErrorMessage'
            )]
            [Alias('File', 'Location')]
            [String]$LogFile
        )
        if (!(Test-Path -Path $LogFile)) {
             try {
                $null = New-Item -Path $LogFile -ItemType File -Force
             }
             catch {
                Write-Error -Message 'Error creating log file'
                break
             }
        }
        
        try {
            $Mutex = [Threading.Mutex]::OpenExisting('Global\AZEOMutex')
        }
        catch {
            $Mutex = New-Object -TypeName 'Threading.Mutex' -ArgumentList $false, 'Global\AZEOMutex'
        }
        
        switch ($PSBoundParameters.Keys) {
             'ErrorMessage' {
                Write-Host -Object "ERROR: [$([DateTime]::Now)] $ErrorMessage" -ForegroundColor Red
    
                $null = $Mutex.WaitOne()
     
                Add-Content -Path $LogFile -Value "$([DateTime]::Now) [ERROR]: $ErrorMessage"
     
                if ($PSBoundParameters.ContainsKey('ErrorRecord')) {
                    $Message = '{0} ({1}: {2}:{3} char:{4})' -f $ErrorRecord.Exception.Message,
                                                                $ErrorRecord.FullyQualifiedErrorId,
                                                                $ErrorRecord.InvocationInfo.ScriptName,
                                                                $ErrorRecord.InvocationInfo.ScriptLineNumber,
                                                                $ErrorRecord.InvocationInfo.OffsetInLine
     
                    Add-Content -Path $LogFile -Value "$([DateTime]::Now) [ERROR]: $Message"
                }
     
                $null = $Mutex.ReleaseMutex()
                Continue
             }
             'Info' {
                $VerbosePreference = 'Continue'
                Write-Verbose -Message "[$([DateTime]::Now)] $Info"
    
                $null = $Mutex.WaitOne()
     
                Add-Content -Path $LogFile -Value "$([DateTime]::Now) [INFO]: $Info"
                    
                $null = $Mutex.ReleaseMutex()
                Continue
             }
             'Debugging' {
                Write-Debug -Message "$Debugging"
     
                $null = $Mutex.WaitOne()
                    
                Add-Content -Path $LogFile -Value "$([DateTime]::Now) [DEBUG]: $Debugging"
                    
                $null = $Mutex.ReleaseMutex()
                Continue
             }
             'Warning' {
                Write-Warning -Message "[$([DateTime]::Now)] $Warning"
     
                $null = $Mutex.WaitOne()
                    
                Add-Content -Path $LogFile -Value "$([DateTime]::Now) [WARNING]: $Warning"
                    
                $null = $Mutex.ReleaseMutex()
                Continue
             }
             'Success' {
                Write-Host -Object "SUCCESS: [$([DateTime]::Now)] $Success" -ForegroundColor Green
     
                $null = $Mutex.WaitOne()
                    
                Add-Content -Path $LogFile -Value "$([DateTime]::Now) [SUCCESS]: $Success"
                    
                $null = $Mutex.ReleaseMutex()
                Continue
             }
        }
    }
    #endregion Functions

    #region Init
    $LogFile = "{0}\Logs\{1:yyyyMMdd}.log" -f $PSScriptRoot, [DateTime]::Now

    #Collected data storage
    $USNDataWH = @()
    $CliXmlDataWH = @()

    #Default Parameters Values
    $PSDefaultParameterValues = @{
        'Write-LogEntry:LogFile' = $LogFile
    }
    #endregion Init

    Write-LogEntry -Info 'ADLiveMonitor v0.1'

    #Import module ActiveDirectory, if it does not import yet
    if (!(Get-Module | Where-Object {$_.Name -eq 'ActiveDirectory'})) {
        try {
            Import-Module -Name 'ActiveDirectory'
            Write-LogEntry -Success 'Loaded ActiveDirectory module'
        }
        catch {
            Write-LogEntry -ErrorMessage 'Failed loading ActiveDirectory module.' -ErrorRecord $_
            Exit
        }
    }

    #Domain Controller
    if ($DC) {
        Write-LogEntry -Info 'DC has been specified in parameters, resolving IPAddress.'
        try {
            $DCIp = (Resolve-DnsName -Name $DC).IPAddress
            Write-LogEntry -Success 'Specified DC name has been resolved successfully.'
            Write-LogEntry -Info "Ensuring $DC is a Domain Controller."
            try {
                Get-ADDomainController -Identity $DC -Server $DC
                Write-LogEntry -Success 'Specified DC is a Domain Controller'
            }
            catch {
                $Message = 'Specified DC is not a Domain Controller'
                Write-LogEntry -ErrorMessage $Message -ErrorRecord $_
                throw $_
            }
        }
        catch {
            Exit
        }
    } else {
        Write-LogEntry -Info 'DC has nt been specified in parameters, getting the closest DC using ActiveDirectory module.'
        try {
            $ClosestDC = Get-ADDomainController
            Write-LogEntry -Success 'Fetched the closest DC using ActiveDirectory module.'
        }
        catch {
            Write-LogEntry -ErrorMessage 'Failed loading the closest DC using ActiveDirectory module.' -ErrorRecord $_
            Exit
        }
        $DC   = $ClosestDC.HostName
        $DCIp = $ClosestDC.IPv4Address
    }

    $ADModule101 = @{
        Server = $DC
    }
    $ADRepl101 = @{
        Target = $DC
        EnumerationServer = $DCIp
    }

    if ($Credentials) {
        $ADModule101.Add('Credential', $Credentials)
        $ADRepl101.Add('Credential', $Credentials)
    }

    <#
        If we need, we dump all objects with all properties. 
        This is very loud, high network use and time consuming.
        But this this the sacrifice you are willing to make...
    #>
    $DumpedAD = $null
    if ($DumpAllObjects) {
        Write-LogEntry -Info 'Dumping all Active Directory objects... This can take a lot of time.'
        try {
            $DumpedAD = Get-ADObject -Filter * -Properties * @ADModule101
            Write-LogEntry -Success 'Dumped all Active Directory objects.'
        }
        catch {
            Write-LogEntry -ErrorMessage 'Failed dumping all Active Directory objects.' -ErrorRecord $_
            Exit
        }
    }

    #Domain DistinguishedName
    $DomainDN = (Get-ADDomain @ADModule101).DistinguishedName

    #Get first DC usn value
    if ($USN) {
        $DCOldUSN = $USN
    } else {
        Write-LogEntry -Info 'No USN specified, fetching USN from domain.'
        try {
            $DCInvID = (Get-ADDomainController -Identity $DC @ADModule101).InvocationID.Guid
            $DCStartReplUTDV = Get-ADReplicationUpToDatenessVectorTable @ADRepl101 | Where-Object -FilterScript {$_.PartnerInvocationId.Guid -eq $DCInvID}   
            Write-LogEntry -Success 'Fetched USN from domain.'  
        }
        catch {
            Write-LogEntry -ErrorMessage 'Failed fetching USN from domain.' -ErrorRecord $_
            Exit
        }
        $DCOldUSN = $DCStartReplUTDV.USNFilter
    }
    
    Write-LogEntry -Info 'ADLiveMonitor on ActiveDirectory WebSerices'

    if ($Output) {
        Write-LogEntry -Info "Output will be saved in $Output"
    }
    
    #Main loop
    for (;;) {
        Start-Sleep -Seconds $Sleep
        $DCReplUTDV = Get-ADReplicationUpToDatenessVectorTable @ADRepl101 | Where-Object -FilterScript {$_.PartnerInvocationId.Guid -eq $DCInvID}
        
        #If new USN value greater than old, than we got some changes
        if ($DCReplUTDV.USNFilter -gt $DCOldUSN) {
            #Save new USN value
            $DCChangedUSN = $DCReplUTDV.USNFilter

            #Get all objects from current DC, where ChangeUSN value greater than new USN
            $ChangedObjects = Get-ADObject -LDAPFilter "(&(objectClass=*)(usnchanged>=$DCOldUSN))" -IncludeDeletedObjects @ADModule101
            Write-LogEntry -Debugging 'Gotted changed objects'
            
            foreach ($Object in $ChangedObjects) {
                #Check if object in ExcludeObject, If object in Exclude list, just ignore it :)
                if ($ExcludeObjectGUID -contains $Object.ObjectGUID.Guid) {
                    continue
                } else {
                    $Props = Get-ADReplicationAttributeMetadata -Object $Object.ObjectGUID.Guid -IncludeDeletedObjects -ShowAllLinkedValues @ADModule101
                
                    $ChangedProps = $Props | Where-Object {$_.LocalChangeUsn -gt $DCOldUSN} | Select-Object -Property Object, AttributeName, AttributeValue, LastOriginatingChangeTime, LocalChangeUsn, Version
                    
                    #Working with single property
                    foreach ($Prop in $ChangedProps) {
                        #Adding new property for explanation about changes
                        $Prop | Add-Member -MemberType NoteProperty -Name Explanation -Value $Null
    
                        #Adding new property for ObjectGUID
                        $Prop | Add-Member -MemberType NoteProperty -Name ObjectGUID -Value $Object.ObjectGUID.Guid
    
                        #Add some human readable information
                        switch ($Prop.AttributeName) {
                            #Convert number of userAccountControl to human format
                            'userAccountControl' {
                                $Prop.Explanation = Convert-UAC $Prop.AttributeValue
                            }
                            #Add or delete member from group
                            'member' {
                                if ($Prop.Version%2 -eq 1) {
                                    $Prop.Explanation = 'Added to group'
                                } else {
                                    $Prop.Explanation = 'Deleted from group'
                                }
                            }
                            #Convert Date & Time to human format
                            {($_ -eq 'lastLogonTimestamp') -or ($_ -eq 'pwdlastset') -or ($_ -eq 'lockoutTime') -or ($_ -eq 'ms-Mcs-AdmPwdExpirationTime')} {
                                $Prop.Explanation = [DateTime]::FromFileTime($Prop.AttributeValue)
                            }
                            #Expires Account convert to human readable format
                            {($_ -eq 'accountExpires')} {
                                if (($Prop.AttributeValue -eq 0) -or ($Prop.AttributeValue -gt [DateTime]::MaxValue.Ticks)) {
                                    $Prop.Explanation = 'Never Expired'
                                } else {
                                    $AEDate = [datetime]$Prop.AttributeValue
                                    $Prop.Explanation = $AEDate.AddYears(1600).ToLocalTime()
                                }
                            }
                        }
                    }
    
                    #Exclude lastLogonTimestamp events
                    if ($ExcludelastLogonTimestamp) {
                        $ChangedProps = $ChangedProps | Where-Object {$_.AttributeName -ne 'lastLogonTimestamp'}
                    }
    
                    #Checking for changes 
                    #Colorize output (for PowerShell 5.1)
                    $Escape = [char]27; # escape character
                    $Red = $Escape + '[31m'
                    $Green = $Escape + '[32m'
                    $Yellow = $Escape + '[33m'
                    $Reset = $Escape + '[0m'
    
                    #Output variable
                    $OutputData = @()
    
                    foreach ($HistoryProp in $ChangedProps) {
                        #Expressions for new value
                        $AttrNew = $HistoryProp.AttributeValue
    
                        $OutputData += $HistoryProp | Select-Object -Property Object, AttributeName, @{
                            Label = 'AttributeValue'
                            Expression = {$Green + $AttrNew + $Reset}
                        }, LastOriginatingChangeTime, LocalChangeUsn, Version, Explanation, ObjectGUID
    
                        if ($HistoryProp.AttributeName -eq 'member') {
                            continue
                        }
    
                        $OldRecords = $null
                        $RecentChange = $null
                        
                        $OldRecords = $USNDataWH | Where-Object -FilterScript {$_.ObjectGUID -eq $HistoryProp.ObjectGUID -and $_.Attributename -eq $HistoryProp.Attributename}
    
                        Write-Debug -Message 'Got old records from USNDataWH'
    
                        #If no old values but we dump all AD before - we search this value in dump
                        if (!$OldRecords -AND $DumpedAD) {
                            $DumpedObject = $DumpedAD | Where-Object -FilterScript {$_.ObjectGUID.GUID -eq $HistoryProp.ObjectGUID}
                            $DumpExplanation = '-'
                            $ValueFromDump = $DumpedObject.($HistoryProp.AttributeName)
                            switch ($HistoryProp.AttributeName) {
                                #Convert number of userAccountControl to human format
                                'userAccountControl' {
                                    $DumpExplanation = Convert-UAC $ValueFromDump
                                }
                                #Convert date & time to human format
                                {($_ -eq 'lastLogonTimestamp') -or ($_ -eq 'pwdlastset') -or ($_ -eq 'lockoutTime') -or ($_ -eq 'ms-Mcs-AdmPwdExpirationTime')} {
                                    $DumpExplanation = [DateTime]::FromFileTime($ValueFromDump)
                                }
                                #Expires Account convert to human readable format
                                {($_ -eq 'accountExpires')} {
                                    if (($HistoryProp.AttributeName -eq 0) -or ($HistoryProp.AttributeName -gt [DateTime]::MaxValue.Ticks)) {
                                        $DumpExplanation = 'Never Expired'
                                    } else {
                                        $AEDate = [DateTime]$ValueFromDump
                                        $DumpExplanation = $AEDate.AddYears(1600).ToLocalTime()
                                    }
                                }
                            }
    
                            $OutputData += $DumpedObject | Select-Object -Property @{
                                Name = 'Object'
                                Expression = {$_.DistinguishedName}
                            }, @{
                                Name = 'AttributeName'
                                Expression = {$HistoryProp.AttributeName}
                            }, @{
                                Name = 'AttributeValue'
                                Expression = {$Red + $ValueFromDump + $Reset}
                            }, @{
                                Name = 'LastOriginatingChangeTime'
                                Expression = {'-'}
                            }, @{
                                Name = 'LocalChangeUsn'
                                Expression = {'-'}
                            }, @{
                                Name = 'Version'
                                Expression = {'-'}
                            }, @{
                                Name = 'Explanation'
                                Expression = {$DumpExplanation}
                            }, @{
                                Name = 'ObjectGUID'
                                Expression = {$_.ObjectGUID.GUID}
                            }
                            continue
                        }
    
                        #If no old values - we continue foreach with next property
                        if (!$OldRecords) {
                            continue
                        }
    
                        #If we have old values, we get previous version (by USN) and place it in output, Expressions for old value
                        $RecentChange = ($OldRecords | Sort-Object -Property LocalChangeUsn -Descending)[0]
                        $AttrOld = $RecentChange.AttributeValue
    
                        #$Exp_Old = {$("{0}$AttrOld{1}" -f $Yellow, $Reset)}
                        Write-Debug -Message 'Before OutputData write (history, no DampedAD)'
                        
                        #$OutputData += $RecentChange | Select-Object Object,AttributeName,@{n="AttributeValue";e=$Exp_old},LastOriginatingChangeTime,LocalChangeUsn,Version,Explanation,ObjectGUID
                        $OutputData += $RecentChange | Select-Object -Property Object, AttributeName, @{
                            Name = 'AttributeValue'
                            Expression = {$Yellow + $AttrOld + $Reset}
                        }, LastOriginatingChangeTime, LocalChangeUsn, Version, Explanation, ObjectGUID
                    }
    
                    #Collecting History
                    $USNDataWH += $ChangedProps
                    if ($Output) {
                        $CliXmlDataWH += $OutputData
                        $CliXmlDataWH | Export-Clixml -Depth 5 -Path $Output -Force
                    }
    
                    #Output
                    Write-Debug -Message 'Gotted all data. Output will be next'
                    $OutputData | Format-Table -Property @{
                        Label = 'Object'
                        Expression = {$_.Object.TrimEnd($DomainDN)}
                    }, AttributeName, AttributeValue, LastOriginatingChangeTime, LocalChangeUsn, Version, Explanation, ObjectGUID -Wrap    
                }
            }

            $DCOldUSN = $DCChangedUSN
            $DCChangedUSN = $null
        }
    }
}