#requires -version 2

<#
    Get-AdaptWMIRegProxy.ps1 - Standalone Function
    Based on PowerView by Will Schroeder (@harmj0y)
    Original function: Get-AdaptWMIRegProxy
    
    Clean version - no PSReflect/Win32 signatures
#>

# --- Main Function: Get-AdaptWMIRegProxy ---
function Get-AdaptWMIRegProxy {
<#
.SYNOPSIS

Enumerates the proxy server and WPAD conents for the current user.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: None  

.DESCRIPTION

Enumerates the proxy server and WPAD specification for the current user
on the local machine (default), or a machine specified with -ComputerName.
It does this by enumerating settings from
HKU:SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings.

.PARAMETER ComputerName

Specifies the system to enumerate proxy settings on. Defaults to the local host.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connecting to the remote system.

.EXAMPLE

Get-AdaptWMIRegProxy

ComputerName           ProxyServer            AutoConfigURL         Wpad
------------           -----------            -------------         ----
WINDOWS1               http://primary.test...

.EXAMPLE

$Cred = Get-Credential "TESTLAB\administrator"
Get-AdaptWMIRegProxy -Credential $Cred -ComputerName primary.testlab.local

ComputerName            ProxyServer            AutoConfigURL         Wpad
------------            -----------            -------------         ----
windows1.testlab.local  primary.testlab.local

.INPUTS

String

Accepts one or more computer name specification strings  on the pipeline (netbios or FQDN).

.OUTPUTS

PowerView.ProxySettings

Outputs custom PSObjects with the ComputerName, ProxyServer, AutoConfigURL, and WPAD contents.
#>

    [OutputType('PowerView.ProxySettings')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $ComputerName = $Env:COMPUTERNAME,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        ForEach ($Computer in $ComputerName) {
            try {
                $WmiArguments = @{
                    'List' = $True
                    'Class' = 'StdRegProv'
                    'Namespace' = 'root\default'
                    'Computername' = $Computer
                    'ErrorAction' = 'Stop'
                }
                if ($PSBoundParameters['Credential']) { $WmiArguments['Credential'] = $Credential }

                $RegProvider = Get-WmiObject @WmiArguments
                $Key = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings'

                # HKEY_CURRENT_USER
                $HKCU = 2147483649
                $ProxyServer = $RegProvider.GetStringValue($HKCU, $Key, 'ProxyServer').sValue
                $AutoConfigURL = $RegProvider.GetStringValue($HKCU, $Key, 'AutoConfigURL').sValue

                $Wpad = ''
                if ($AutoConfigURL -and ($AutoConfigURL -ne '')) {
                    try {
                        $Wpad = (New-Object Net.WebClient).DownloadString($AutoConfigURL)
                    }
                    catch {
                        Write-Warning "[Get-AdaptWMIRegProxy] Error connecting to AutoConfigURL : $AutoConfigURL"
                    }
                }

                if ($ProxyServer -or $AutoConfigUrl) {
                    $Out = New-Object PSObject
                    $Out | Add-Member Noteproperty 'ComputerName' $Computer
                    $Out | Add-Member Noteproperty 'ProxyServer' $ProxyServer
                    $Out | Add-Member Noteproperty 'AutoConfigURL' $AutoConfigURL
                    $Out | Add-Member Noteproperty 'Wpad' $Wpad
                    $Out.PSObject.TypeNames.Insert(0, 'PowerView.ProxySettings')
                    $Out
                }
                else {
                    Write-Warning "[Get-AdaptWMIRegProxy] No proxy settings found for $ComputerName"
                }
            }
            catch {
                Write-Warning "[Get-AdaptWMIRegProxy] Error enumerating proxy settings for $ComputerName : $_"
            }
        }
    }
}
