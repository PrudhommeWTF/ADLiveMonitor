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
    #endregion Functions

    #Import module ActiveDirectory, if it does not import yet
    if (!(Get-Module | Where-Object {$_.Name -eq 'ActiveDirectory'})) {
        Import-Module -Name 'ActiveDirectory'
    }

    Write-Host -Object @'
     ___ ______ _     _          ___  ___            _ _             
    / _ \|  _  \ |   (_)         |  \/  |           (_) |            
   / /_\ \ | | | |    ___   _____| .  . | ___  _ __  _| |_ ___  _ __ 
   |  _  | | | | |   | \ \ / / _ \ |\/| |/ _ \| '_ \| | __/ _ \| '__|
   | | | | |/ /| |___| |\ V /  __/ |  | | (_) | | | | | || (_) | |   
   \_| |_/___/ \_____/_| \_/ \___\_|  |_/\___/|_| |_|_|\__\___/|_|   
                                                                                                
'@

    #Collected data storage
    $USNDataWH = @()
    $CliXmlDataWH = @()

    #Domain Controller
    if ($DC) {
        $DCIp = (Resolve-DnsName -Name $DC).IPAddress
    } else {
        $ClosestDC = Get-ADDomainController
        $DC   = $ClosestDC.HostName
        $DCIp = $ClosestDC.IPv4Address
    }

    <#
        If we need, we dump all objects with all properties. 
        This is very loud, high network use and time consuming.
        But this this the sacrifice you are willing to make...
    #>
    $DumpedAD = $null
    if ($DumpAllObjects) {
        Write-Host -Object 'Dumping all Active Directory objects... This can take a lot of time.'
        $DumpedAD = Get-ADObject -Filter * -Properties * -Server $DC
        Write-Host -Object 'Done!'
    }

    #Get first DC usn value
    if ($USN) {
        $DCOldUSN = $USN
    } else {
        if ($Credentials) {
            $DCInvID = (Get-ADDomainController $DC -Server $DC -Credential $Credentials).InvocationID.Guid
            $DCStartReplUTDV = Get-ADReplicationUpToDatenessVectorTable -Target $DC -EnumerationServer $DCIp -Credential $Credentials | where-object -FilterScript {$_.PartnerInvocationId.Guid -eq $DCInvID}
        } else {
            $DomainDN = (Get-ADDomain -Server $DC).DistinguishedName
            $DCInvID = (Get-ADDomainController $DC -Server $DC).InvocationID.Guid
            $DCStartReplUTDV = Get-ADReplicationUpToDatenessVectorTable -Target $DC -EnumerationServer $DCIp | where-object -FilterScript {$_.PartnerInvocationId.Guid -eq $DCInvID}   
        }
        $DCOldUSN = $DCStartReplUTDV.USNFilter
    }
    
    'Spider on AD Web now...'

    if ($Output) {
        "Output will be save in $Output"
    }
    
    #Main loop
    :main for (;;) {
        Start-Sleep -Seconds $Sleep
        if ($Credentials) {
            $DCReplUTDV = Get-ADReplicationUpToDatenessVectorTable -Target $DC -EnumerationServer $DCIp -Credential $Credentials | where-object -FilterScript {$_.PartnerInvocationId.Guid -eq $DCInvID}
        } else {
            $DCReplUTDV = Get-ADReplicationUpToDatenessVectorTable -Target $DC -EnumerationServer $DCIp | where-object -FilterScript {$_.PartnerInvocationId.Guid -eq $DCInvID}
        }
        
        #If new USN value greater than old, than we got some changes
        if ($DCReplUTDV.USNFilter -gt $DCOldUSN) {
            #Save new USN value
            $DCChangedUSN = $DCReplUTDV.USNFilter

            #Get all objects from current DC, where ChangeUSN value greater than new USN
            if ($Credentials) {
                $ChangedObjects = Get-ADObject -LDAPFilter "(&(objectClass=*)(usnchanged>=$DCOldUSN))" -Server $DC -Credential $Credentials -IncludeDeletedObjects
            } else {
                $ChangedObjects = Get-ADObject -LDAPFilter "(&(objectClass=*)(usnchanged>=$DCOldUSN))" -Server $DC -IncludeDeletedObjects
                Write-Debug 'Gotted changed objects'
            }
            
            :changed_objects foreach ($Object in $ChangedObjects) {
                #Check if object in ExcludeObject, If object in Exclude list, just ignore it :)
                if ($ExcludeObjectGUID -contains $Object.ObjectGUID.Guid) {
                    continue changed_objects
                }
                if ($Credentials) {            
                    $Props = Get-ADReplicationAttributeMetadata -Object $Object.DistinguishedName -Server $DC -Credential $Credentials -IncludeDeletedObjects -ShowAllLinkedValues
                } else {
                    $Props = Get-ADReplicationAttributeMetadata -Object $Object.ObjectGUID.Guid -Server $DC -IncludeDeletedObjects -ShowAllLinkedValues
                }
                $ChangedProps = $Props | Where-Object {$_.LocalChangeUsn -gt $DCOldUSN} | Select-Object -Property Object, AttributeName, AttributeValue, LastOriginatingChangeTime, LocalChangeUsn, Version
                
                #Working with single property
                :props foreach ($Prop in $ChangedProps) {
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

                :history foreach ($HistoryProp in $ChangedProps) {
                    #Expressions for new value
                    $AttrNew = $HistoryProp.AttributeValue

                    $OutputData += $HistoryProp | Select-Object -Property Object, AttributeName, @{
                        Label = 'AttributeValue'
                        Expression = {$Green + $AttrNew + $Reset}
                    }, LastOriginatingChangeTime, LocalChangeUsn, Version, Explanation, ObjectGUID

                    if ($HistoryProp.AttributeName -eq 'member') {
                        continue history
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
                        continue history
                    }

                    #If no old values - we continue foreach with next property
                    if (!$OldRecords) {
                        continue history
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
                Width = [int](($Host.UI.RawUI.WindowSize.Width - 77)/4)
            }, @{
                Label = 'AttributeName'
                Expression = {$_.AttributeName}
                Width = [int](($Host.UI.RawUI.WindowSize.Width - 77)/5)
            }, @{
                Label = 'AttributeValue'
                Expression = {$_.AttributeValue}
                Width = [int](($Host.UI.RawUI.WindowSize.Width - 77)/4)
            }, @{
                Label = 'LastOriginChangeTime'
                Expression = {$_.LastOriginatingChangeTime}
                Width = 20
            }, @{
                Label = 'LocalChangeUsn'
                Expression = {$_.LocalChangeUsn}
                Width = 14
            }, @{
                Label = 'Version'
                Expression = {$_.Version}
                Width = 7
            }, @{
                Label = 'Explanation'
                Expression = {$_.Explanation}
                Width = [int](($Host.UI.RawUI.WindowSize.Width - 77)/5)
            }, @{
                Label = 'ObjectGUID'
                Expression = {$_.ObjectGUID}
                Width = 36
            } -Wrap
        }

        $DCOldUSN = $DCChangedUSN
        $DCChangedUSN = $null
        }
    }
}