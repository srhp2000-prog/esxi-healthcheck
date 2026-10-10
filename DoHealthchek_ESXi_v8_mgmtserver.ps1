#Edit with latest supported versions
#$Supporteversionv7 = "7.0.3"
#$Supportedbuildv7 = "23307199"
$Supporteversionv8 = "8.0.3"
$Supportedbuildv8 = "25595708"

#vCenters to check
cd C:\Util
$vCenters = [string[]]@(Get-Content .\mgmt-vCenter_1.txt |
    ForEach-Object { $_.Trim() } |
    Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
if ($vCenters.Count -eq 0) {
    throw "mgmt-vCenter_1.txt inneholder ingen gyldige vCenter-servernavn."
}

#Folder for reports
$exportpath ='C:\Reports'

#*************************************************************************************************************************************
#Looping throug selected vCenters

$credentials = Get-Credential
Write-Host "Antall vCenter-servere i listen: $($vCenters.Count)"

foreach ($vCenterEntry in $vCenters){
$vCenterServer = ([string]$vCenterEntry).Trim()
if ([string]::IsNullOrWhiteSpace($vCenterServer)) {
    Write-Warning "Tom vCenter-verdi ble hoppet over; Connect-VIServer blir ikke kalt."
    continue
}

Write-Host ("Kobler til vCenter: [{0}]" -f $vCenterServer)
$connectParameters = @{
    Server = $vCenterServer
    Credential = $credentials
    ErrorAction = 'Stop'
}

try {
    $viServer = Connect-VIServer @connectParameters
} catch {
    Write-Warning "Kunne ikke koble til vCenter $vCenterServer. Hopper til neste vCenter. Feil: $($_.Exception.Message)"
    continue
}

Write-Host "Connected to vCenter: $vCenterServer"

#*************************************************************************************************************************************
#Select hosts

#Get hosts from list
#$esxihostslist = Get-Content .\Servers-vspap010.txt

#Get all hosts from connected vCenter
$esxihosts = Get-VMHost -Server $viServer | Where-Object {$_.ConnectionState -eq "connected"}
Write-Host "Antall ESXi-hosts funnet i ${vCenterServer}: $($esxihosts.Count)"

#*************************************************************************************************************************************
#Collect settings

$ESXiHostResultTotal = ""
$ESXiHostResultTotal =@()

foreach ($esxihost in $esxihosts){
	$ESXi = $esxihost.name

$accountlockouttime = Get-VMHost -Name $ESXi | Get-AdvancedSetting Security.AccountUnlockTime
if ($accountlockouttime.value -eq "900") {$accountlockouttimeResult = "OK"} else {$accountlockouttimeResult = "Deviation"}
$accountlockouttimeResult

$AccountLockoutFailures = Get-VMHost -Name $ESXi | Get-AdvancedSetting Security.AccountLockFailures
if ($AccountLockoutFailures.value -le "5") {$AccountLockoutFailuresResult = "OK"} else {$AccountLockoutFailuresResult = "Deviation"}
$AccountLockoutFailures.value

$accountpwhistory = Get-VMHost -Name $ESXi | Get-AdvancedSetting Security.PasswordHistory
if ($accountpwhistory.value -in 1..5) {$accountpwhistoryResult = "OK"} else {$accountpwhistoryResult = "Deviation"}
$accountpwhistory.value

$pwMaxDays = Get-VMHost -Name $ESXi | Get-AdvancedSetting Security.PasswordMaxDays
if ($pwMaxDays.value -eq "99999") {$pwMaxDaysResult = "OK"} else {$pwMaxDaysResult = "Deviation"}
$pwMaxDays.value

$pwpolicies = Get-VMHost -Name $ESXi | Get-AdvancedSetting Security.PasswordQualityControl
if ($pwpolicies.value -eq "retry=3 min=disabled,15,15,15,15 max=64 similar=deny passphrase=3") {$pwpoliciesResult = "OK"} else {$pwpoliciesResult = "Deviation"}
$pwpolicies.value
$pwpoliciesResult
#Default: retry=3 min=disabled,disabled,disabled,7,7
#Recomended: "retry=3 min=disabled,15,15,15,15 max=64 similar=deny passphrase=3"
#Remidiation: Get-VMHost -Name $ESXi | Get-AdvancedSetting Security.PasswordQualityControl | Set-AdvancedSetting -Value "retry=3 min=disabled,15,15,15,15 max=64 similar=deny passphrase=3"


$welcomemessage = Get-VMHost -Name $ESXi | Get-AdvancedSetting Annotations.WelcomeMessage
if ($welcomemessage.value -eq "") {$welcomemessageResult = "OK"} else  {$welcomemessageResult = "Deviation"}
$welcomemessage.value
$welcomemessageResult
#Default= ""
#Change: Get-VMHost -Name $ESXi | Get-AdvancedSetting Annotations.WelcomeMessage | Set-AdvancedSetting -Value "Authorized users only. Actual or attempted unauthorized use of this system is prohibited and may result in criminal, civil, security, or administrative proceedings and/or penalties. Use of this information system indicates consent to monitoring and recording, without notice or permission. Users have no expectation of privacy in any use of this system. Any information stored on, or transiting this system, or obtained by monitoring and/or recording, may be disclosed to law enforcement and/or used in accordance with Federal law, State statute, and organization policy. If you are not an authorized user of this system, exit the system at this time."

$cpuHyperthreadWarning = Get-VMHost -Name $ESXi | Get-AdvancedSetting UserVars.SuppressHyperthreadWarning
if ($cpuHyperthreadWarning.value -eq "0") {$cpuHyperthreadWarningResult = "OK"} else {$cpuHyperthreadWarningResult = "Deviation"}
$cpuHyperthreadWarning.value
$cpuHyperthreadWarningResult

$dcuitimeout = Get-VMHost -Name $ESXi | Get-AdvancedSetting UserVars.DcuiTimeOut
if ($dcuitimeout.value -eq "600") {$dcuitimeoutResult = "OK"} else {$dcuitimeoutResult = "Deviation"}
$dcuitimeout.value
$dcuitimeoutResult

$disablecim1 = Get-VMHostService -VMHost $ESXi | Where-Object {$_.Key -eq 'sfcbd-watchdog' -and $_.Running -eq 'True'}
$disablecim2 = Get-VMHostService -VMHost $ESXi | Where-Object {$_.Key -eq 'sfcbd-watchdog' -and $_.Policy -eq 'On'}
if (-not $disablecim1) {$cimRunningResult = "OK"} else {$cimRunningResult = "Deviation"}
if (-not $disablecim2) {$cimPolicyResult = "OK"} else {$cimPolicyResult = "Deviation"}
$disablecim1.running
$disablecim2.policy
$cimRunningResult
$cimPolicyResult
#Remidiation
#Get-VMHostService -VMHost $ESXi | where {$_.Key -eq 'sfcbd-watchdog'} | Set-VMHostService -Policy Off
#Get-VMHostService -VMHost $ESXi | where {$_.Key -eq 'sfcbd-watchdog'} | Stop-VMHostService

$disablemob = Get-VMHost -Name $ESXi | Get-AdvancedSetting Config.HostAgent.plugins.solo.enableMob
if ($disablemob.value -eq "False") {$disablemobResult = "OK"} else {$disablemobResult = "Deviation"}
if ($disablemob.value -eq $false) {$disablemobResult = "OK"} else {$disablemobResult = "Deviation"}
$disablemob.value
$disablemobResult

$disableslp1 = Get-VMHostService -VMHost $ESXi | Where-Object {$_.Key -eq 'slpd' -and $_.Running -eq 'True'}
$disableslp2 = Get-VMHostService -VMHost $ESXi | Where-Object {$_.Key -eq 'slpd' -and $_.Policy -eq 'On'}
if (-not $disableslp1) {$slpRunningResult = "OK"} else {$slpRunningResult = "Deviation"}
if (-not $disableslp2) {$slpPolicyResult = "OK"} else {$slpPolicyResult = "Deviation"}
$disableslp1
$disableslp2
$slpPolicyResult
$slpRunningResult

$disablesnmp1 = Get-VMHostService -VMHost $ESXi | Where-Object {$_.Key -eq 'snmpd' -and $_.Running -eq 'True'}
$disablesnmp2 = Get-VMHostService -VMHost $ESXi | Where-Object {$_.Key -eq 'snmpd' -and $_.Policy -eq 'On'}
if (-not $disablesnmp1) {$snmpRunningResult = "OK"} else {$snmpRunningResult = "Deviation"}
if (-not $disablesnmp2) {$snmpPolicyResult = "OK"} else {$snmpPolicyResult = "Deviation"}
$disablesnmp1.running
$disablesnmp2.policy
$snmpRunningResult
$snmpPolicyResult

$disablessh1 = Get-VMHostService -VMHost $ESXi | Where-Object {$_.Key -eq 'TSM-SSH' -and $_.Running -eq 'True'}
$disablessh2 = Get-VMHostService -VMHost $ESXi | Where-Object {$_.Key -eq 'TSM-SSH' -and $_.Policy -eq 'On'}
if (-not $disablessh1) {$sshRunningResult = "OK"} else {$sshRunningResult = "Deviation"}
if (-not $disablessh2) {$sshPolicyResult = "OK"} else {$sshPolicyResult = "Deviation"}
$disablessh1.running
$disablessh2.policy
$sshRunningResult
$sshPolicyResult

$etcissue = Get-VMHost -Name $ESXi | Get-AdvancedSetting Config.Etc.Issue
if ($etcissue.value -eq "") {$etcissueResult = "OK"} else  {$etcissueResult = "Deviation"}
$etcissue.value
$etcissueResult
#Remidiation: Get-VMHost -Name $ESXi | Get-AdvancedSetting Config.Etc.Issue | Set-AdvancedSetting -Value "Authorized users only. Actual or attempted unauthorized use of this system is prohibited and may result in criminal, civil, security, or administrative proceedings and/or penalties. Use of this information system indicates consent to monitoring and recording, without notice or permission. Users have no expectation of privacy in any use of this system. Any information stored on, or transiting this system, or obtained by monitoring and/or recording, may be disclosed to law enforcement and/or used in accordance with Federal law, State statute, and organization policy. If you are not an authorized user of this system, exit the system at this time."

$ESXcli = Get-EsxCli -VMHost $ESXi -V2
$firewallrestrictaccessRules = $ESXcli.network.firewall.ruleset.list.Invoke()
$firewallrestrictaccessIPs = $ESXcli.network.firewall.ruleset.allowedip.list.Invoke()
$firewallrestrictaccessRules
$firewallrestrictaccessIPs

#Remidiation example
##"$ESXcli = Get-EsxCli -VMHost $ESXi -V2
# Disable firewall temporarily so we don't lose connectivity
##$arguments = $ESXcli.network.firewall.set.CreateArgs()
##$arguments.enabled = $false
##$ESXcli.network.firewall.set.Invoke($arguments)

# Unset the ""allow all"" flag
##$arguments = $ESXcli.network.firewall.ruleset.set.CreateArgs()
##$arguments.allowedall = $false
##$arguments.rulesetid = ""sshServer""
##$ESXcli.network.firewall.ruleset.set.Invoke($arguments)

# Add an IP range that will be allowed
##$arguments = $ESXcli.network.firewall.ruleset.allowedip.add.CreateArgs()
##$arguments.ipaddress = ""192.168.0.0/16""
##$arguments.rulesetid = ""sshServer""
##$ESXcli.network.firewall.ruleset.allowedip.add.Invoke($arguments)

# Enable the firewall
##$arguments = $ESXcli.network.firewall.set.CreateArgs()
##$arguments.enabled = $true
##$ESXcli.network.firewall.set.Invoke($arguments)"

$hostclientsessiontimeout = Get-VMHost -Name $ESXi | Get-AdvancedSetting UserVars.HostClientSessionTimeout
if ($hostclientsessiontimeout.value -eq "900") {$hostclientsessiontimeoutResult = "OK"} else {$hostclientsessiontimeoutResult = "Deviation"}
$hostclientsessiontimeout.value
$hostclientsessiontimeoutResult


#Result ok if there is no ISCS. may need to be modified if there is
$iscsimutualchap = Get-VMHost -Name $ESXi | Get-VMHostHba | Where {$_.Type -eq "Iscsi"} | Select VMHost, Device, ChapType, @{N="CHAPName";E={$_.AuthenticationProperties.ChapName}}
if (-not $iscsimutualchap) {$iscsimutualchapResult = "OK"} else {$iscsimutualchapResult = "Deviation"}
$iscsimutualchap.device
$iscsimutualchapResult

#Lockdown not in use
$lockdowndcuiaccess = Get-VMHost -Name $ESXi | Get-AdvancedSetting DCUI.Access
if ($lockdowndcuiaccess.value -eq "root") {$lockdowndcuiaccessResult = "OK"} else {$lockdowndcuiaccessResult = "Deviation"}
$lockdowndcuiaccess.value
$lockdowndcuiaccessResult

#Lockdown not in use
$lockdownexceptionusers = (Get-View (Get-VMHost -Name $ESXi | Get-View).ConfigManager.HostAccessManager).QueryLockdownExceptions()
if (-not $lockdownexceptionusers) {$lockdownexceptionusersResult = "OK"} else {$lockdowndcuiaccessResult = "Deviation"}
if (-not $lockdownexceptionusers) {$lockdownexceptionusers = "None"}
$lockdownexceptionusers
$lockdownexceptionusersResult

$lockdownmode = (Get-View (Get-VMHost -Name $ESXi | Get-View).ConfigManager.HostAccessManager).LockdownMode
if ($lockdownmode -eq "lockdownDisabled") {$lockdownmodeResult = "OK"} else {$lockdownmodeResult = "Deviation"}
$lockdownmode
$lockdownmodeResult

$logslevel = Get-VMHost -Name $ESXi | Get-AdvancedSetting Config.HostAgent.log.level
if ($logslevel.value -eq "info") {$logslevelResult = "OK"} else {$logslevelResult = "Deviation"}
$logslevel.value
$logslevelResult

#Maybe this needs to be changed
$logspersistent = Get-VMHost -Name $ESXi | Get-AdvancedSetting Syslog.global.logDir
if ($logspersistent.value -eq "[] /scratch/log") {$logspersistentResult = "OK"} else {$logspersistentResult = "Deviation"}
$logspersistent.value
$logspersistentResult

$logsremote = Get-VMHost -Name $ESXi | Get-AdvancedSetting Syslog.global.logHost
if ($logsremote.value -like "udp://*") {$logsremoteResult = "OK"} else {$logsremoteResult = "Deviation"}
$logsremote.value
$logsremoteResult

$networkbpdu = Get-VMHost -Name $ESXi | Get-AdvancedSetting Net.BlockGuestBPDU
if ($networkbpdu.value -eq "1") {$networkbpduResult = "OK"} else {$networkbpduResult = "Deviation"}
$networkbpdu.value
$networkbpduResult

$networkdvfilter = Get-VMHost -Name $ESXi | Get-AdvancedSetting Net.DVFilterBindIpAddress
if (-not $networkdvfilter.value) {$networkdvfilterResult = "OK"} else {$networkdvfilterResult = "Deviation"}
$networkdvfilter.value
$networkdvfilterResult

#Get Network security Policy Stanndard Swithch and PortGroups
$NetSecPolicyvSwitch = Get-VMHost -Name $ESXi | Get-VirtualSwitch | Get-SecurityPolicy
$NetSecPolicyPG = Get-VMHost -Name $ESXi | Get-VirtualPortGroup | Get-SecurityPolicy

#Forged Transmits vSwitch
if ($NetSecPolicyvSwitch.ForgedTransmits -Like "*True*") {$NetSecPolicyvSwitchFTResult = "Deviation"} else {$NetSecPolicyvSwitchFTResult = "OK"}
$NetSecPolicyvSwitch.ForgedTransmits
$NetSecPolicyvSwitchFTResult

#Forged Transmits PortGroup
if ($NetSecPolicyPG.ForgedTransmits -Like "*True*") {$NetSecPolicyPGFTResult = "Deviation"} else {$NetSecPolicyPGFTResult = "OK"}
$NetSecPolicyPG.ForgedTransmits
$NetSecPolicyPGFTResult

#Remidiation for Forged transmits on Standard Switch and PortGroups (2 above) (Not tested)
#Get-VMHost -Name $ESXi | Get-VirtualSwitch | Get-SecurityPolicy | Set-SecurityPolicy -ForgedTransmits $false 
#Get-VMHost -Name $ESXi | Get-VirtualPortGroup | Get-SecurityPolicy | Set-SecurityPolicy -ForgedTransmitsInherited $true

#Mac Changes vSwitch
if ($NetSecPolicyvSwitch.MacChanges -Like "*True*") {$NetSecPolicyvSwitchMacResult = "Deviation"} else {$NetSecPolicyvSwitchMacResult = "OK"}
$NetSecPolicyvSwitch.MacChanges
$NetSecPolicyvSwitchMacResult

#Mac Changes PortGroup
if ($NetSecPolicyPG.MacChanges -Like "*True*") {$NetSecPolicyPGMacResult = "Deviation"} else {$NetSecPolicyPGMacResult = "OK"}
$NetSecPolicyPG.MacChanges
$NetSecPolicyPGMacResult

#Remidiation Mac Changes standard Switch and Port groups (Not Tested)
#Get-VMHost -Name $ESXi | Get-VirtualSwitch | Get-SecurityPolicy | Set-SecurityPolicy -MacChanges $false
#Get-VMHost -Name $ESXi | Get-VirtualPortGroup | Get-SecurityPolicy | Set-SecurityPolicy -MacChangesInherited $true

#AllowPromiscuous vSwitch
if ($NetSecPolicyvSwitch.AllowPromiscuous -Like "*True*") {$NetSecPolicyvSwitchAllowProResult = "Deviation"} else {$NetSecPolicyvSwitchAllowProResult = "OK"}
$NetSecPolicyvSwitch.AllowPromiscuous
$NetSecPolicyvSwitchAllowProResult

#AllowPromiscuous PortGroup
if ($NetSecPolicyPG.AllowPromiscuous -Like "*True*") {$NetSecPolicyPGAllowProResult = "Deviation"} else {$NetSecPolicyPGAllowProResult = "OK"}
$NetSecPolicyPG.AllowPromiscuous
$NetSecPolicyPGAllowProResult

#AllowPromiscuous Remidiation for Standard Switch and Port Groups  (Not Tested)
#Get-VMHost -Name $ESXi | Get-VirtualSwitch | Get-SecurityPolicy | Set-SecurityPolicy -AllowPromiscuous $false
#Get-VMHost -Name $ESXi | Get-VirtualPortGroup | Get-SecurityPolicy | Set-SecurityPolicy -AllowPromiscuousInherited $true

$shelldisableRunnning = Get-VMHostService -VMHost $ESXi | Where-Object {$_.Key -eq 'TSM' -and $_.Running -eq 'True'}
if (-not $shelldisableRunnning) {$shelldisableRunnningResult = "OK"} else {$shelldisableRunnningResult = "Deviation"}
$shelldisablePolicy = Get-VMHostService -VMHost $ESXi | Where-Object {$_.Key -eq 'TSM'}
if ($shelldisablePolicy.policy -eq "off") {$shelldisablePolicyResult = "OK"} else {$shelldisablePolicyResult = "Deviation"}
#$shelldisablePolicy = Get-VMHostService -VMHost $ESXi | Where-Object {$_.Key -eq 'TSM' -and $_.Policy -eq 'On'}
#if (-not $shelldisablePolicy) {$shelldisablePolicyResult = "OK"} else {$shelldisablePolicyResult = "Deviation"}
$shelldisableRunnning
$shelldisableRunnningResult
$shelldisablePolicy.policy
$shelldisablePolicyResult

$shellinteractivetimeout = Get-VMHost -Name $ESXi | Get-AdvancedSetting UserVars.ESXiShellInteractiveTimeOut
if ($shellinteractivetimeout.value -eq "900") {$shellinteractivetimeoutResult = "OK"} else {$shellinteractivetimeoutResult = "Deviation"}
$shellinteractivetimeout.value
$shellinteractivetimeoutResult

#Remidiation shellinteractivetimeout
#Get-VMHost -Name $ESXi | Get-AdvancedSetting UserVars.ESXiShellInteractiveTimeOut | Set-AdvancedSetting -Value 900

$shelltimeout = Get-VMHost -Name $ESXi | Get-AdvancedSetting UserVars.ESXiShellTimeOut
if ($shelltimeout.value -eq "900") {$shelltimeoutResult = "OK"} else {$shelltimeoutResult = "Deviation"}
$shelltimeout.value
$shelltimeoutResult

$shellwarning = Get-VMHost -Name $ESXi | Get-AdvancedSetting UserVars.SuppressShellWarning
if ($shellwarning.value -eq "0") {$shellwarningResult = "OK"} else {$shellwarningResult = "Deviation"}
$shellwarning.value
$shellwarningResult

#Moved to the start of the Script
#$Supporteversionv7 = "7.0.3"
#$Supportedbuildv7 = "22348816"
#$Supporteversionv8 = "8.0.2"
#$Supportedbuildv8 = "22380479"

$supported = Get-VMHost -Name $ESXi | Select-Object Name,Version,Build
if (($supported.version -eq $Supporteversionv7) -or ($supported.version -eq $Supporteversionv8)) {$supportedversionResult = "OK"} else {$supportedversionResult = "Deviation"}
if (($supported.build -eq $Supportedbuildv7) -or ($supported.build -eq $Supportedbuildv8)) {$supportedbuildResult = "OK"} else {$supportedbuildResult = "Deviation"}
$supported.version
$supportedversionResult
$supported.build
$supportedbuildResult

$timeServerstocheck ='0.ntp.cosng.net','1.ntp.cosng.net','2.ntp.cosng.net','3.ntp.cosng.net'
$timeServers =  Get-VMHostNtpServer -VMHost $ESXi
if (($timeServers.Split(':@')[0] -eq $timeServerstocheck.Split(':@')[0]) -and ($timeServers.Split(':@')[1] -eq $timeServerstocheck.Split(':@')[1]) -and ($timeServers.Split(':@')[2] -eq $timeServerstocheck.Split(':@')[2]) -and ($timeServers.Split(':@')[3] -eq $timeServerstocheck.Split(':@')[3])) {$timeServersResult = "OK"} else {$timeServersResult = "Deviation"}
#if ($timeServers.Split(':@')[1] -eq $timeServerstocheck.Split(':@')[1]) -and ($timeServers.Split(':@')[2] -eq $timeServerstocheck.Split(':@')[2]) -and ($timeServers.Split(':@')[3] -eq $timeServerstocheck.Split(':@')[3]) -and ($timeServers.Split(':@')[4] -eq $timeServerstocheck.Split(':@')[4]) {$timeServersResult = "OK"} else {$timeServersResult = "Deviation"}
$timeServers
$timeServersResult

#Sjekke om NTP servicen kjører og står til riktig startup
$timeServicestatus = Get-VMHostService -VMHost $ESXi | Where-Object {$_.Key -eq 'ntpd' -and $_.Running -eq 'True'}
if ($timeServicestatus.policy -eq "on") {$timeServicestatusResult = "OK"} else {$timeServicestatusResult = "Deviation"}
$timeServicestatus.policy
$timeServicestatusResult

$tlsprotocolsDisabled = Get-VMHost -Name $ESXi | Get-AdvancedSetting UserVars.ESXiVPsDisabledProtocols
if ($tlsprotocolsDisabled.value -eq "sslv3,tlsv1,tlsv1.1") {$tlsprotocolsDisabledResult = "OK"} else {$tlsprotocolsDisabledResult = "Deviation"}
$tlsprotocolsDisabled.value
$tlsprotocolsDisabledResult

$transparentpagesharing = Get-VMHost -Name $ESXi | Get-AdvancedSetting Mem.ShareForceSalting
if ($transparentpagesharing.value -eq "2") {$transparentpagesharingResult = "OK"} else {$transparentpagesharingResult = "Deviation"}
$transparentpagesharing.value
$transparentpagesharingResult

#esxi-8.updates Already checked above (Seach up for $supported.build)

$vibacceptanceleveldesired = "VMwareCertified"
#Default: 
#$vibacceptanceleveldesired = "PartnerSupported"

$vibacceptancelevel = (Get-EsxCli -VMHost $ESXi -V2).software.acceptance.get.Invoke()
if ($vibacceptancelevel -eq $vibacceptanceleveldesired) {$vibacceptancelevelResult = "OK"} else {$vibacceptancelevelResult = "Deviation"}
$vibacceptancelevel
$vibacceptancelevelResult

#Remidiate vib acceptance level
#$ESXcli = Get-EsxCli -VMHost $ESXi -V2
#$arguments = $esxcli.software.acceptance.set.CreateArgs()
#$arguments.level = ""VMwareCertified"" # VMwareCertified, VMwareAccepted, PartnerSupported, CommunitySupported
#$esxcli.software.acceptance.set.Invoke($arguments)"

$vibtrustedbinaries = Get-VMHost -Name $ESXi | Get-AdvancedSetting VMkernel.Boot.execInstalledOnly
if ($vibtrustedbinaries.value -eq "True") {$vibtrustedbinariesResult = "OK"} else {$vibtrustedbinariesResult = "Deviation"}
$vibtrustedbinaries.value
$vibtrustedbinariesResult

#Remidiate vib trusted binaries
#Get-VMHost -Name $ESXi | Get-AdvancedSetting VMkernel.Boot.execInstalledOnly | Set-AdvancedSetting -Value True

#$vmkmanagement = Get-VMHostNetworkAdapter -VMHost $ESXi -VMKernel | Select VMHost,Name,IP,ManagementTrafficEnabled
$vmkmanagement = Get-VMHostNetworkAdapter -VMHost $ESXi -VMKernel |where {$_.ManagementTrafficEnabled -eq "True"}
if ($vmkmanagement.count -eq "1") {$vmkmanagementnumberResult = "OK"} else {$vmkmanagementnumberResult = "Deviation"}
$vmkmanagement.ip
$vmkmanagement.count
$vmkmanagementnumberResult


#************************************************************************************************************************
#Export results

    $ESXiHostResult = [pscustomobject]@{
        Hostname = $ESXi
        vCenterName = $vCenterServer
        Accountlockouttime = $accountlockouttime.value
        'Accountlockouttime-Result' = $accountlockouttimeResult
        AccountLockoutFailures = $AccountLockoutFailures.value
        'AccountLockoutFailures-Result' = $AccountLockoutFailuresResult
        Accountpwhistory = $accountpwhistory.value
        'Accountpwhistory-Result' = $accountpwhistoryResult
        pwMaxDays = $pwMaxDays.value
        'pwMaxDays-Result' = $pwMaxDaysResult
        pwpolicies = $pwpolicies.value
        'pwpolicies-Result' = $pwpoliciesResult
        Welcomemessage = $welcomemessage.value
        'Welcomemessage-Result' = $welcomemessageResult
        cpuHyperthreadWarning = $cpuHyperthreadWarning.value
        'cpuHyperthreadWarning-Result' = $cpuHyperthreadWarningResult
        dcuitimeout = $dcuitimeout.value
        'dcuitimeout-Result' = $dcuitimeoutResult
        'Cim-Running' = $disablecim1.running
        'cim-Running-Result' = $cimRunningResult
        'Cim-Policy' = $disablecim2.policy
        'Cim-Policy-Result' = $cimPolicyResult
        'mob-enabled' = $disablemob.value
        'disablemob-Result' = $disablemobResult
        'slp-Running' = $disableslp1.running
        'slp-Running-Result' = $slpRunningResult
        'slp-Policy' = $disableslp2.policy
        'slp-Policy-Result' = $slpPolicyResult
        'snmp-Running' = $disablesnmp1.running
        'snmp-Running-Result' = $snmpRunningResult
        'snmp-Policy' = $disablesnmp2.policy
        'snmp-Policy-Result' = $snmpPolicyResult
        'ssh-Running' = $disablessh1.running
        'ssh-Running-Result' = $sshRunningResult
        'ssh-Policy' = $disablessh2.policy
        'ssh-Policy-Result' = $sshPolicyResult
        'etc-issue' = $etcissue.value
        'etc-issue-Result' = $etcissueResult
        HostClientSessionTimeout = $hostclientsessiontimeout.value
        'HostClientSessionTimeout-Result' = $hostclientsessiontimeoutResult
        'iscsi-mutualchap' = $iscsimutualchap.device
        'iscsi-mutualchap-Result' = $iscsimutualchapResult
        'Lockdown-dcui-Access' = $lockdowndcuiaccess.value
        'Lockdown-dcui-Access-Result' = $lockdowndcuiaccessResult
        'Lockdown-ExceptionUsers' = $lockdownexceptionusers
        'Lockdown-exceptionusers-Result' = $lockdownexceptionusersResult
        'Lockdown-Mode' = $lockdownmode
        'Lockdow-Mode-Result' = $lockdownmodeResult
        Logslevel = $logslevel.value
        'Logslevel-Result' = $logslevelResult
        'Logspersistent-value' = $logspersistent.value
        'Logspersistent-Result' = $logspersistentResult
        'Logsremote-value' = $logsremote.value
        'Logsremote-Result' = $logsremoteResult
        'Network-bpdu-value' = $networkbpdu.value
        'Network-bpdu-Result' = $networkbpduResult
        'Networkdvfilter-value' = $networkdvfilter.value
        'Networkdvfilter-Result' = $networkdvfilterResult
        StdSwitchForgedTrasmits = $NetSecPolicyvSwitch.ForgedTransmits
        'StdSwitchForgedTrasmits-Result' = $NetSecPolicyvSwitchFTResult
        PortGroupForgedTrasmits = $NetSecPolicyPG.ForgedTransmits
        'PortGroupForgedTrasmits-Result' = $NetSecPolicyPGFTResult
        StdSwitchMacChanges = $NetSecPolicyvSwitch.MacChanges
        'StdSwitchMacChanges-Result' = $NetSecPolicyvSwitchMacResult
        PortGroupMacChanges = $NetSecPolicyPG.MacChanges
        'PortGroupMacChanges-Result' = $NetSecPolicyPGMacResult
        StdSwitchAllowPromiscuous = $NetSecPolicyvSwitch.AllowPromiscuous
        'StdSwitchAllowPromiscuous-Result' = $NetSecPolicyvSwitchAllowProResult
        PortGroupAllowPromiscuous = $NetSecPolicyPG.AllowPromiscuous
        'PortGroupAllowPromiscuous-Result' = $NetSecPolicyPGAllowProResult
        ShellRunninng = $shelldisableRunnning
        'ShellRunninng-Result' = $shelldisableRunnningResult
        ShellPolicy = $shelldisablePolicy.policy
        'ShellPolicy-Result' = $shelldisablePolicyResult
        ShellInteractiveTimeout = $shellinteractivetimeout.value
        'ShellInteractiveTimeout-Result' = $shellinteractivetimeoutResult
        ShellTimeout = $shelltimeout.value
        'ShellTimeout-Result' = $shelltimeoutResult
        ShellWarning = $shellwarning.value
        'ShellWarning-Result' = $shellwarningResult
        'ESXi-Version' = $supported.version
        'SupportedVersion-Result' = $supportedversionResult
        'ESXi-Build' = $supported.build
        'SupportedBuild-Result' = $supportedbuildResult
        NtpTimeServers = $timeServers
        'TimeServers-Result' = $timeServersResult
        TimeServicePolicy = $timeServicestatus.policy
        'TimeServicePolicy-Result' = $timeServicestatusResult
        TLSProtocolsDisabled = $tlsprotocolsDisabled.value
        'TLSProtocolsDisabled-Result' = $tlsprotocolsDisabledResult
        TransparentPageSharingValue = $transparentpagesharing.value
        'TransparentPageSharing-Result' = $transparentpagesharingResult
        VibAcceptanceLevel = $vibacceptancelevel
        'vibAcceptanceLevel-Result' = $vibacceptancelevelResult
        VibTrustedBinariesValue = $vibtrustedbinaries.value
        'VibTrustedBinariesValue-Result' = $vibtrustedbinariesResult
        vmkManagement = if ($vmkmanagement) { $vmkmanagement.ip } else { $null }
        'vmkManagement-Number' = if ($vmkmanagement) { $vmkmanagement.count } else { 0 }
        'vmkManagement-Number-Result' = $vmkmanagementnumberResult
    }

    $ESXiHostResultTotal += $ESXiHostResult
}

if ($ESXiHostResultTotal.Count -gt 0) {
    $ESXiHostResultTotal | Format-Table -AutoSize
    Write-Output "Antall hostresultater: $($ESXiHostResultTotal.Count)"
} else {
    Write-Warning "Ingen hostresultater ble generert for $vCenterServer. Sjekk at Get-VMHost returnerer data og at PowerCLI er koblet til vCenter."
}

#Export options
# Use semicolon as delimiter because Excel on Norwegian/European locale expects ';' for CSV files.
$exportpathvcenter = $exportpath + "\HealtCheck-ESXi-servers-" + $vCenterServer + ".csv"
$ESXiHostResultTotal | Export-Csv $exportpathvcenter -NoTypeInformation -Append -Encoding UTF8 -Delimiter ';'
#$ESXiHostResultTotal | Export-Csv .\HealtCheck-ESXi-servers-vspap021.txt -NoTypeInformation -Append -Encoding UTF8 -Delimiter ';'
#$ESXiHostResultTotal | Export-Csv .\HealtCheck-ESXi-servers-milton.txt -NoTypeInformation -Append -Encoding UTF8 -Delimiter ';'
if ($viServer) {
    try {
        Disconnect-VIServer -Server $viServer -Confirm:$false -ErrorAction Stop
    } catch {
        Write-Warning "Kunne ikke koble fra vCenter ${vCenterServer}: $($_.Exception.Message)"
    }
}
#Pause
}
