<#
.SYNOPSIS
Configures Checkmarx Engine and/or Manager for SSL communication between 
CxManager and CxEngine

.DESCRIPTION
For CxEngine, registers the latest Server Authentication certificate with the
Checkmarx Engine.

For CxManager, configures the Checkmarx services for SSL communication with Engines. 

.NOTES

.VERSION
V1 - 23 Feb 2018 - Initial version

.AUTHOR
Randy Geyer (randy@checkmarx.com)

#>
[CmdletBinding()]
Param(
    
    [Parameter(Mandatory = $False)]
    [int]
    $sslPort = 443
   
)


function Setup-CxSSL([int]$port)
{

    $WCF_BINDINGS_XPATH = "/configuration/*/bindings/basicHttpBinding/binding"

    ConfigureEngine($port)
    ' '
    ConfigureManager

    'Done.'

}

function ConfigureEngine([int]$port)
{
    $ENGINE_KEY_NAME = 'HKLM:\SOFTWARE\Checkmarx\Installation\Checkmarx Engine Server'
    $ENGINE_CONFIG_FILE = 'CxSourceAnalyzerEngine.WinService.exe.config'

    # Lookup CxEngine install location via registry
    $cxEnginePath = Get-ItemPropertyValue -Path $ENGINE_KEY_NAME -Name 'Path' -ErrorAction SilentlyContinue

    'Processing CxEngine...'
    if (!$cxEnginePath) 
    {
        '...engine not found.'
        return
    }

    '...component found: path=' + $cxEnginePath
    $cxEngineConfigPath = $cxEnginePath + $ENGINE_CONFIG_FILE
    $cxEngineDir = Get-Item -Path $cxEnginePath -ErrorAction SilentlyContinue
    if (!$cxEngineDir )
    {
        '...engine directory not found.'
        return
    }

    ConfigureCert($sslPort)

    BackupConfig($cxEngineConfigPath)

    "...loading engine bindings, path='" + $cxEngineConfigPath + "' xpath='" + $WCF_BINDINGS_XPATH + "'"
    [Xml]$xml = Get-Content $cxEngineConfigPath
    $bindingNode = Select-Xml -xml $xml -XPath $WCF_BINDINGS_XPATH
    '...binding=' + $bindingNode
    $securityNode = $bindingNode.Node.SelectSingleNode('security')
    '...security=' + $securityNode.OuterXml
    if (!$securityNode)
    {
        '...adding <security/> node'
        $securityNode = $xml.CreateElement('security')
        $bindingNode.Node.AppendChild($securityNode)  | Out-Null
    }
    '...setting <security mode="Transport" />'
    $securityNode.SetAttribute("mode", "Transport")

    $SERVICES_MEX_XPATH = "/configuration/*/services/service/endpoint[@address='mex']"
    $mexNode = $xml.SelectSingleNode($SERVICES_MEX_XPATH)
    '...mexNode=' + $mexNode.OuterXml
    if (!$mexNode) 
    {
        'ERROR: <endpoint address="mex" not found!'
        return
    }
    '...setting <endpoint address="mex" binding="mexHttpsBinding"...'
    $mexNode.SetAttribute("binding", "mexHttpsBinding")

    $HOST_XPATH = "/configuration/*/services/service/host/baseAddresses/add"
    $hostNode = $xml.SelectSingleNode($HOST_XPATH)
    '...hostNode=' + $hostNode.OuterXml
    if (!$hostNode) 
    {
        'ERROR: <baseAddresses><add>... not found!'
        return
    }
    [string]$hostAddress = $hostNode.SelectSingleNode("@baseAddress").Value
    '...host=' + $hostAddress
    $hostAddress = $hostAddress.Replace("http:", "https:").Replace(":80",":"+$port).Replace("localhost",[System.Net.Dns]::GetHostByName(($env:computerName)).HostName)
    '...setting baseAddress="' + $hostAddress + '"'
    $hostNode.SetAttribute("baseAddress", $hostAddress)

    $SERVICE_METADATA_XPATH = "/configuration/*/behaviors/serviceBehaviors/behavior/serviceMetadata"
    $serviceNode = $xml.SelectSingleNode($SERVICE_METADATA_XPATH)
    '...serviceNode=' + $serviceNode.OuterXml
    if (!$serviceNode) 
    {
        'ERROR: <serviceMetadata> not found!'
        return
    }
    '...setting <serviceMetadata httpsGetEnabled="true"...'
    $serviceNode.SetAttribute("httpsGetEnabled", "true")
    $serviceNode.RemoveAttribute("httpGetEnabled")

    "...saving: '" + $cxEngineConfigPath + "'"
    $xml.Save($cxEngineConfigPath)

}


function ConfigureManager()
{
    $SYS_MANAGER_KEY_NAME = 'HKLM:\SOFTWARE\Checkmarx\Installation\Checkmarx System Manager'
    $SYS_MANAGER_CONFIG_FILE = 'CxSystemManagerService.exe.config'

    $JOBS_MANAGER_KEY_NAME = 'HKLM:\SOFTWARE\Checkmarx\Installation\Checkmarx Jobs Manager'
    $JOBS_MANAGER_CONFIG_FILE = 'CxJobsManagerWinService.exe.config'

    $SCAN_MANAGER_KEY_NAME = 'HKLM:\SOFTWARE\Checkmarx\Installation\Checkmarx Scans Manager'
    $SCAN_MANAGER_CONFIG_FILE = 'CxScansManagerWinService.exe.config'

    # Lookup CxManager install location via registry
    $cxSysManagerPath = LookupComponentInRegistry($SYS_MANAGER_KEY_NAME)

    'Processing Cx SystemManager...'
    if (!$cxSysManagerPath) 
    {
        '...manager not found.'
        return
    }

    '...component found: path=' + $cxSysManagerPath

    ConfigureTransportSecurity($cxSysManagerPath + 'bin\' + $SYS_MANAGER_CONFIG_FILE)
    
    $cxJobsMgr = LookupComponentInRegistry($JOBS_MANAGER_KEY_NAME)
    if ($cxJobsMgr) 
    { 
        ConfigureTransportSecurity($cxJobsMgr + 'bin\' + $JOBS_MANAGER_CONFIG_FILE)
    }
    $cxScansMgr = LookupComponentInRegistry($SCAN_MANAGER_KEY_NAME)
    if ($cxScansMgr) 
    { 
        ConfigureTransportSecurity($cxScansMgr + 'bin\' + $SCAN_MANAGER_CONFIG_FILE)
    }
}

function LookupComponentInRegistry([string] $regexPath)
{
    #returns the component path if found in registry, otherwise null
    return Get-ItemPropertyValue -Path $regexPath -Name 'Path' -ErrorAction SilentlyContinue
}

function ConfigureTransportSecurity([string]$configPath)
{
    '...configuring CxManager service: ' + $configPath

    BackupConfig($configPath)
    
    # configure security mode='Transport'
    $WCF_SECURITY_XPATH = "/configuration/*/bindings/basicHttpBinding/binding/security"

    "...loading security, path='" + $configPath + "' xpath='" + $WCF_SECURITY_XPATH + "'"
    [Xml]$xml = Get-Content $configPath
    $securityNode = Select-Xml -xml $xml -XPath $WCF_SECURITY_XPATH
    '...security=' + $securityNode.Node.OuterXml
    if (!$securityNode)
    {
        'ERROR: <transport> not found! config="' + $configPath + '"'
        return
    }
    '...setting <security mode="Transport" />'
    $securityNode.Node.SetAttribute("mode", "Transport")

    "...saving: '" + $configPath + "'"
    $xml.Save($configPath)
}

function ConfigureCert([int]$port)
{
    '...configuring cert...'

    '...retrieving cert'
    $cert = Get-ChildItem -path cert:\LocalMachine\My | where-object { ($_.EnhancedKeyUsageList -like “*Server Authentication*”) -and ($_.Subject -like "*$hostname*") } | Sort NotAfter -Descending | Select -First 1
    '...cert: ' + $cert.Thumbprint + ' ; ' + $cert.Subject
    if (!$cert)
    {
        throw 'ERROR: no proper cert found!'
    }

    #register cert with Windows
    #$appid = [guid]::NewGuid().ToString("B")
    $appid = "{00112233-4455-6677-8899-AABBCCDDEEFF}"
    $ipport = "0.0.0.0:" + $port

    #RJG: will fail if cert already bound
    #Add-NetIPHttpsCertBinding -IpPort $ipport -CertificateHash $cert.Thumbprint -ApplicationId $appid -CertificateStoreName "my" -NullEncryption $false

    # delete sslcert if it exists
    $netsh = [string]::Format('"netsh.exe http delete sslcert ipport={0}"', $ipport)
    '...netsh: ' + $netsh
    $netshOut = cmd.exe /c $netsh 2>$1
    '...deleting existing sslcert binding: ' + $netshOut

    # register sslcert
    $netsh = [string]::Format('"netsh.exe http add sslcert ipport={0} certhash={1} appid={2}"', $ipport, $cert.Thumbprint, $appid)
    '...netsh: ' + $netsh
    $netshOut = cmd.exe /c $netsh 2>$1
    '...registering new sslcert binding: ' + $netshOut

}

function BackupConfig ([String]$configPath)
{
    "...backing up config: '" + $configPath
    
    $timestamp = Get-Date -Format o | foreach {$_ -replace ":", ""}
    $timestamp = $timestamp.Replace("-","")
    $configFileName = [System.IO.Path]::GetFileNameWithoutExtension($configPath)
    $configCopyName = $configFileName + '-' + $timestamp + '.config'
    "...copying to: " + $configCopyName

    $configDir = [System.IO.Path]::GetDirectoryName($configPath)
    $configCopyPath = [System.IO.Path]::Combine($configDir, $configCopyName)

    Copy-Item $configPath -Destination $configCopyPath
}

'sslPort=' + $sslPort
Setup-CxSSL($sslPort)
