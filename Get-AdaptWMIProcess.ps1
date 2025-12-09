#requires -version 2

<#
    Get-AdaptWMIProcess.ps1 - Standalone Function
    Based on PowerView by Will Schroeder (@harmj0y)
    Original function: Get-AdaptWMIProcess
    
    Clean version - no PSReflect/Win32 signatures
#>

# --- Main Function: Get-AdaptWMIProcess ---
function Get-AdaptWMIProcess {
<#
.SYNOPSIS

Returns a list of processes and their owners on the local or remote machine.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: None  

.DESCRIPTION

Uses Get-WMIObject to enumerate all Win32_process instances on the local or remote machine,
including the owners of the particular process.

.PARAMETER ComputerName

Specifies the hostname to query for cached RDP connections (also accepts IP addresses).
Defaults to 'localhost'.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the remote system.

.EXAMPLE

Get-AdaptWMIProcess -ComputerName WINDOWS1

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-AdaptWMIProcess -ComputerName PRIMARY.testlab.local -Credential $Cred

.OUTPUTS

PowerView.UserProcess

A PSCustomObject containing the remote process information.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.UserProcess')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $ComputerName = 'localhost',

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        ForEach ($Computer in $ComputerName) {
            try {
                $WmiArguments = @{
                    'ComputerName' = $ComputerName
                    'Class' = 'Win32_process'
                }
                if ($PSBoundParameters['Credential']) { $WmiArguments['Credential'] = $Credential }
                Get-WMIobject @WmiArguments | ForEach-Object {
                    $Owner = $_.getowner();
                    $Process = New-Object PSObject
                    $Process | Add-Member Noteproperty 'ComputerName' $Computer
                    $Process | Add-Member Noteproperty 'ProcessName' $_.ProcessName
                    $Process | Add-Member Noteproperty 'ProcessID' $_.ProcessID
                    $Process | Add-Member Noteproperty 'Domain' $Owner.Domain
                    $Process | Add-Member Noteproperty 'User' $Owner.User
                    $Process.PSObject.TypeNames.Insert(0, 'PowerView.UserProcess')
                    $Process
                }
            }
            catch {
                Write-Verbose "[Get-AdaptWMIProcess] Error enumerating remote processes on '$Computer', access likely denied: $_"
            }
        }
    }
}
