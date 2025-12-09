#requires -version 2

<#
    Get-AdaptPathAcl.ps1 - Standalone Function
    Based on PowerView by Will Schroeder (@harmj0y)
    Original function: Get-AdaptPathAcl
    
    Clean version - no PSReflect/Win32 signatures
    Note: -Credential parameter removed (requires Win32)
#>

# --- Convert-ADName ---
function Convert-ADName {
<#
.SYNOPSIS

Converts Active Directory object names between a variety of formats.

Author: Bill Stewart, Pasquale Lantella  
Modifications: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: None  

.DESCRIPTION

This function is heavily based on Bill Stewart's code and Pasquale Lantella's code (in LINK)
and translates Active Directory names between various formats using the NameTranslate COM object.

.PARAMETER Identity

Specifies the Active Directory object name to translate, of the following form:

    DN                short for 'distinguished name'; e.g., 'CN=Phineas Flynn,OU=Engineers,DC=fabrikam,DC=com'
    Canonical         canonical name; e.g., 'fabrikam.com/Engineers/Phineas Flynn'
    NT4               domain\username; e.g., 'fabrikam\pflynn'
    Display           display name, e.g. 'pflynn'
    DomainSimple      simple domain name format, e.g. 'pflynn@fabrikam.com'
    EnterpriseSimple  simple enterprise name format, e.g. 'pflynn@fabrikam.com'
    GUID              GUID; e.g., '{95ee9fff-3436-11d1-b2b0-d15ae3ac8436}'
    UPN               user principal name; e.g., 'pflynn@fabrikam.com'
    CanonicalEx       extended canonical name format
    SPN               service principal name format; e.g. 'HTTP/kairomac.contoso.com'
    SID               Security Identifier; e.g., 'S-1-5-21-12986231-600641547-709122288-57999'

.PARAMETER OutputType

Specifies the output name type you want to convert to, which must be one of the following:

    DN                short for 'distinguished name'; e.g., 'CN=Phineas Flynn,OU=Engineers,DC=fabrikam,DC=com'
    Canonical         canonical name; e.g., 'fabrikam.com/Engineers/Phineas Flynn'
    NT4               domain\username; e.g., 'fabrikam\pflynn'
    Display           display name, e.g. 'pflynn'
    DomainSimple      simple domain name format, e.g. 'pflynn@fabrikam.com'
    EnterpriseSimple  simple enterprise name format, e.g. 'pflynn@fabrikam.com'
    GUID              GUID; e.g., '{95ee9fff-3436-11d1-b2b0-d15ae3ac8436}'
    UPN               user principal name; e.g., 'pflynn@fabrikam.com'
    CanonicalEx       extended canonical name format, e.g. 'fabrikam.com/Users/Phineas Flynn'
    SPN               service principal name format; e.g. 'HTTP/kairomac.contoso.com'

.PARAMETER Domain

Specifies the domain to use for the translation, defaults to the current domain.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to for the translation.

.PARAMETER Credential

Specifies an alternate credential to use for the translation.

.EXAMPLE

Convert-ADName -Identity "TESTLAB\harmj0y"

harmj0y@testlab.local

.EXAMPLE

"TESTLAB\krbtgt", "CN=Administrator,CN=Users,DC=testlab,DC=local" | Convert-ADName -OutputType Canonical

testlab.local/Users/krbtgt
testlab.local/Users/Administrator

.EXAMPLE

Convert-ADName -OutputType dn -Identity 'TESTLAB\harmj0y' -Server PRIMARY.testlab.local

CN=harmj0y,CN=Users,DC=testlab,DC=local

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm', $SecPassword)
'S-1-5-21-890171859-3433809279-3366196753-1108' | Convert-ADNAme -Credential $Cred

TESTLAB\harmj0y

.INPUTS

String

Accepts one or more objects name strings on the pipeline.

.OUTPUTS

String

Outputs a string representing the converted name.

.LINK

http://windowsitpro.com/active-directory/translating-active-directory-object-names-between-formats
https://gallery.technet.microsoft.com/scriptcenter/Translating-Active-5c80dd67
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [OutputType([String])]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('Name', 'ObjectName')]
        [String[]]
        $Identity,

        [String]
        [ValidateSet('DN', 'Canonical', 'NT4', 'Display', 'DomainSimple', 'EnterpriseSimple', 'GUID', 'Unknown', 'UPN', 'CanonicalEx', 'SPN')]
        $OutputType,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $NameTypes = @{
            'DN'                =   1  # CN=Phineas Flynn,OU=Engineers,DC=fabrikam,DC=com
            'Canonical'         =   2  # fabrikam.com/Engineers/Phineas Flynn
            'NT4'               =   3  # fabrikam\pflynn
            'Display'           =   4  # pflynn
            'DomainSimple'      =   5  # pflynn@fabrikam.com
            'EnterpriseSimple'  =   6  # pflynn@fabrikam.com
            'GUID'              =   7  # {95ee9fff-3436-11d1-b2b0-d15ae3ac8436}
            'Unknown'           =   8  # unknown type - let the server do translation
            'UPN'               =   9  # pflynn@fabrikam.com
            'CanonicalEx'       =   10 # fabrikam.com/Users/Phineas Flynn
            'SPN'               =   11 # HTTP/kairomac.contoso.com
            'SID'               =   12 # S-1-5-21-12986231-600641547-709122288-57999
        }

        # accessor functions from Bill Stewart to simplify calls to NameTranslate
        function Invoke-Method([__ComObject] $Object, [String] $Method, $Parameters) {
            $Output = $Null
            $Output = $Object.GetType().InvokeMember($Method, 'InvokeMethod', $NULL, $Object, $Parameters)
            Write-Output $Output
        }

        function Get-Property([__ComObject] $Object, [String] $Property) {
            $Object.GetType().InvokeMember($Property, 'GetProperty', $NULL, $Object, $NULL)
        }

        function Set-Property([__ComObject] $Object, [String] $Property, $Parameters) {
            [Void] $Object.GetType().InvokeMember($Property, 'SetProperty', $NULL, $Object, $Parameters)
        }

        # https://msdn.microsoft.com/en-us/library/aa772266%28v=vs.85%29.aspx
        if ($PSBoundParameters['Server']) {
            $ADSInitType = 2
            $InitName = $Server
        }
        elseif ($PSBoundParameters['Domain']) {
            $ADSInitType = 1
            $InitName = $Domain
        }
        elseif ($PSBoundParameters['Credential']) {
            $Cred = $Credential.GetNetworkCredential()
            $ADSInitType = 1
            $InitName = $Cred.Domain
        }
        else {
            # if no domain or server is specified, default to GC initialization
            $ADSInitType = 3
            $InitName = $Null
        }
    }

    PROCESS {
        ForEach ($TargetIdentity in $Identity) {
            if (-not $PSBoundParameters['OutputType']) {
                if ($TargetIdentity -match "^[A-Za-z]+\\[A-Za-z ]+") {
                    $ADSOutputType = $NameTypes['DomainSimple']
                }
                else {
                    $ADSOutputType = $NameTypes['NT4']
                }
            }
            else {
                $ADSOutputType = $NameTypes[$OutputType]
            }

            $Translate = New-Object -ComObject NameTranslate

            if ($PSBoundParameters['Credential']) {
                try {
                    $Cred = $Credential.GetNetworkCredential()

                    Invoke-Method $Translate 'InitEx' (
                        $ADSInitType,
                        $InitName,
                        $Cred.UserName,
                        $Cred.Domain,
                        $Cred.Password
                    )
                }
                catch {
                    Write-Verbose "[Convert-ADName] Error initializing translation for '$Identity' using alternate credentials : $_"
                }
            }
            else {
                try {
                    $Null = Invoke-Method $Translate 'Init' (
                        $ADSInitType,
                        $InitName
                    )
                }
                catch {
                    Write-Verbose "[Convert-ADName] Error initializing translation for '$Identity' : $_"
                }
            }

            # always chase all referrals
            Set-Property $Translate 'ChaseReferral' (0x60)

            try {
                # 8 = Unknown name type -> let the server do the work for us
                $Null = Invoke-Method $Translate 'Set' (8, $TargetIdentity)
                Invoke-Method $Translate 'Get' ($ADSOutputType)
            }
            catch [System.Management.Automation.MethodInvocationException] {
                Write-Verbose "[Convert-ADName] Error translating '$TargetIdentity' : $($_.Exception.InnerException.Message)"
            }
        }
    }
}

# --- ConvertFrom-SID ---
function ConvertFrom-SID {
<#
.SYNOPSIS

Converts a security identifier (SID) to a group/user name.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Convert-ADName  

.DESCRIPTION

Converts a security identifier string (SID) to a group/user name
using Convert-ADName.

.PARAMETER ObjectSid

Specifies one or more SIDs to convert.

.PARAMETER Domain

Specifies the domain to use for the translation, defaults to the current domain.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to for the translation.

.PARAMETER Credential

Specifies an alternate credential to use for the translation.

.EXAMPLE

ConvertFrom-SID S-1-5-21-890171859-3433809279-3366196753-1108

TESTLAB\harmj0y

.EXAMPLE

"S-1-5-21-890171859-3433809279-3366196753-1107", "S-1-5-21-890171859-3433809279-3366196753-1108", "S-1-5-32-562" | ConvertFrom-SID

TESTLAB\WINDOWS2$
TESTLAB\harmj0y
BUILTIN\Distributed COM Users

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm', $SecPassword)
ConvertFrom-SID S-1-5-21-890171859-3433809279-3366196753-1108 -Credential $Cred

TESTLAB\harmj0y

.INPUTS

String

Accepts one or more SID strings on the pipeline.

.OUTPUTS

String

The converted DOMAIN\username.
#>

    [OutputType([String])]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('SID')]
        [ValidatePattern('^S-1-.*')]
        [String[]]
        $ObjectSid,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $ADNameArguments = @{}
        if ($PSBoundParameters['Domain']) { $ADNameArguments['Domain'] = $Domain }
        if ($PSBoundParameters['Server']) { $ADNameArguments['Server'] = $Server }
        if ($PSBoundParameters['Credential']) { $ADNameArguments['Credential'] = $Credential }
    }

    PROCESS {
        ForEach ($TargetSid in $ObjectSid) {
            $TargetSid = $TargetSid.trim('*')
            try {
                # try to resolve any built-in SIDs first - https://support.microsoft.com/en-us/kb/243330
                Switch ($TargetSid) {
                    'S-1-0'         { 'Null Authority' }
                    'S-1-0-0'       { 'Nobody' }
                    'S-1-1'         { 'World Authority' }
                    'S-1-1-0'       { 'Everyone' }
                    'S-1-2'         { 'Local Authority' }
                    'S-1-2-0'       { 'Local' }
                    'S-1-2-1'       { 'Console Logon ' }
                    'S-1-3'         { 'Creator Authority' }
                    'S-1-3-0'       { 'Creator Owner' }
                    'S-1-3-1'       { 'Creator Group' }
                    'S-1-3-2'       { 'Creator Owner Server' }
                    'S-1-3-3'       { 'Creator Group Server' }
                    'S-1-3-4'       { 'Owner Rights' }
                    'S-1-4'         { 'Non-unique Authority' }
                    'S-1-5'         { 'NT Authority' }
                    'S-1-5-1'       { 'Dialup' }
                    'S-1-5-2'       { 'Network' }
                    'S-1-5-3'       { 'Batch' }
                    'S-1-5-4'       { 'Interactive' }
                    'S-1-5-6'       { 'Service' }
                    'S-1-5-7'       { 'Anonymous' }
                    'S-1-5-8'       { 'Proxy' }
                    'S-1-5-9'       { 'Enterprise Domain Controllers' }
                    'S-1-5-10'      { 'Principal Self' }
                    'S-1-5-11'      { 'Authenticated Users' }
                    'S-1-5-12'      { 'Restricted Code' }
                    'S-1-5-13'      { 'Terminal Server Users' }
                    'S-1-5-14'      { 'Remote Interactive Logon' }
                    'S-1-5-15'      { 'This Organization ' }
                    'S-1-5-17'      { 'This Organization ' }
                    'S-1-5-18'      { 'Local System' }
                    'S-1-5-19'      { 'NT Authority' }
                    'S-1-5-20'      { 'NT Authority' }
                    'S-1-5-80-0'    { 'All Services ' }
                    'S-1-5-32-544'  { 'BUILTIN\Administrators' }
                    'S-1-5-32-545'  { 'BUILTIN\Users' }
                    'S-1-5-32-546'  { 'BUILTIN\Guests' }
                    'S-1-5-32-547'  { 'BUILTIN\Power Users' }
                    'S-1-5-32-548'  { 'BUILTIN\Account Operators' }
                    'S-1-5-32-549'  { 'BUILTIN\Server Operators' }
                    'S-1-5-32-550'  { 'BUILTIN\Print Operators' }
                    'S-1-5-32-551'  { 'BUILTIN\Backup Operators' }
                    'S-1-5-32-552'  { 'BUILTIN\Replicators' }
                    'S-1-5-32-554'  { 'BUILTIN\Pre-Windows 2000 Compatible Access' }
                    'S-1-5-32-555'  { 'BUILTIN\Remote Desktop Users' }
                    'S-1-5-32-556'  { 'BUILTIN\Network Configuration Operators' }
                    'S-1-5-32-557'  { 'BUILTIN\Incoming Forest Trust Builders' }
                    'S-1-5-32-558'  { 'BUILTIN\Performance Monitor Users' }
                    'S-1-5-32-559'  { 'BUILTIN\Performance Log Users' }
                    'S-1-5-32-560'  { 'BUILTIN\Windows Authorization Access Group' }
                    'S-1-5-32-561'  { 'BUILTIN\Terminal Server License Servers' }
                    'S-1-5-32-562'  { 'BUILTIN\Distributed COM Users' }
                    'S-1-5-32-569'  { 'BUILTIN\Cryptographic Operators' }
                    'S-1-5-32-573'  { 'BUILTIN\Event Log Readers' }
                    'S-1-5-32-574'  { 'BUILTIN\Certificate Service DCOM Access' }
                    'S-1-5-32-575'  { 'BUILTIN\RDS Remote Access Servers' }
                    'S-1-5-32-576'  { 'BUILTIN\RDS Endpoint Servers' }
                    'S-1-5-32-577'  { 'BUILTIN\RDS Management Servers' }
                    'S-1-5-32-578'  { 'BUILTIN\Hyper-V Administrators' }
                    'S-1-5-32-579'  { 'BUILTIN\Access Control Assistance Operators' }
                    'S-1-5-32-580'  { 'BUILTIN\Access Control Assistance Operators' }
                    Default {
                        Convert-ADName -Identity $TargetSid @ADNameArguments
                    }
                }
            }
            catch {
                Write-Verbose "[ConvertFrom-SID] Error converting SID '$TargetSid' : $_"
            }
        }
    }
}

# --- Main Function: Get-AdaptPathAcl ---
function Get-AdaptPathAcl {
<#
.SYNOPSIS

Enumerates the ACL for a given file path.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Add-AdaptRemoteConnection, Remove-AdaptRemoteConnection, ConvertFrom-SID  

.DESCRIPTION

Enumerates the ACL for a specified file/folder path, and translates
the access rules for each entry into readable formats. If -Credential is passed,
Add-AdaptRemoteConnection/Remove-AdaptRemoteConnection is used to temporarily map the remote share.

.PARAMETER Path

Specifies the local or remote path to enumerate the ACLs for.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target path.

.EXAMPLE

Get-AdaptPathAcl "\\SERVER\Share\"

Returns ACLs for the given UNC share.

.EXAMPLE

gci .\test.txt | Get-AdaptPathAcl

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm', $SecPassword)
Get-AdaptPathAcl -Path "\\SERVER\Share\" -Credential $Cred

.INPUTS

String

One of more paths to enumerate ACLs for.

.OUTPUTS

PowerView.FileACL

A custom object with the full path and associated ACL entries.

.LINK

https://support.microsoft.com/en-us/kb/305144
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.FileACL')]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('FullName')]
        [String[]]
        $Path,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {

        function Convert-FileRight {
            # From Ansgar Wiechers at http://stackoverflow.com/questions/28029872/retrieving-security-descriptor-and-getting-number-for-filesystemrights
            [CmdletBinding()]
            Param(
                [Int]
                $FSR
            )

            $AccessMask = @{
                [uint32]'0x80000000' = 'GenericRead'
                [uint32]'0x40000000' = 'GenericWrite'
                [uint32]'0x20000000' = 'GenericExecute'
                [uint32]'0x10000000' = 'GenericAll'
                [uint32]'0x02000000' = 'MaximumAllowed'
                [uint32]'0x01000000' = 'AccessSystemSecurity'
                [uint32]'0x00100000' = 'Synchronize'
                [uint32]'0x00080000' = 'WriteOwner'
                [uint32]'0x00040000' = 'WriteDAC'
                [uint32]'0x00020000' = 'ReadControl'
                [uint32]'0x00010000' = 'Delete'
                [uint32]'0x00000100' = 'WriteAttributes'
                [uint32]'0x00000080' = 'ReadAttributes'
                [uint32]'0x00000040' = 'DeleteChild'
                [uint32]'0x00000020' = 'Execute/Traverse'
                [uint32]'0x00000010' = 'WriteExtendedAttributes'
                [uint32]'0x00000008' = 'ReadExtendedAttributes'
                [uint32]'0x00000004' = 'AppendData/AddSubdirectory'
                [uint32]'0x00000002' = 'WriteData/AddFile'
                [uint32]'0x00000001' = 'ReadData/ListDirectory'
            }

            $SimplePermissions = @{
                [uint32]'0x1f01ff' = 'FullControl'
                [uint32]'0x0301bf' = 'Modify'
                [uint32]'0x0200a9' = 'ReadAndExecute'
                [uint32]'0x02019f' = 'ReadAndWrite'
                [uint32]'0x020089' = 'Read'
                [uint32]'0x000116' = 'Write'
            }

            $Permissions = @()

            # get simple permission
            $Permissions += $SimplePermissions.Keys | ForEach-Object {
                              if (($FSR -band $_) -eq $_) {
                                $SimplePermissions[$_]
                                $FSR = $FSR -band (-not $_)
                              }
                            }

            # get remaining extended permissions
            $Permissions += $AccessMask.Keys | Where-Object { $FSR -band $_ } | ForEach-Object { $AccessMask[$_] }
            ($Permissions | Where-Object {$_}) -join ','
        }

        $ConvertArguments = @{}
        if ($PSBoundParameters['Credential']) { $ConvertArguments['Credential'] = $Credential }

        $MappedComputers = @{}
    }

    PROCESS {
        ForEach ($TargetPath in $Path) {
            try {
                if (($TargetPath -Match '\\\\.*\\.*') -and ($PSBoundParameters['Credential'])) {
                    $HostComputer = (New-Object System.Uri($TargetPath)).Host
                    if (-not $MappedComputers[$HostComputer]) {
                        # map IPC$ to this computer if it's not already
                        Add-AdaptRemoteConnection -ComputerName $HostComputer -Credential $Credential
                        $MappedComputers[$HostComputer] = $True
                    }
                }

                $ACL = Get-Acl -Path $TargetPath

                $ACL.GetAccessRules($True, $True, [System.Security.Principal.SecurityIdentifier]) | ForEach-Object {
                    $SID = $_.IdentityReference.Value
                    $Name = ConvertFrom-SID -ObjectSID $SID @ConvertArguments

                    $Out = New-Object PSObject
                    $Out | Add-Member Noteproperty 'Path' $TargetPath
                    $Out | Add-Member Noteproperty 'FileSystemRights' (Convert-FileRight -FSR $_.FileSystemRights.value__)
                    $Out | Add-Member Noteproperty 'IdentityReference' $Name
                    $Out | Add-Member Noteproperty 'IdentitySID' $SID
                    $Out | Add-Member Noteproperty 'AccessControlType' $_.AccessControlType
                    $Out.PSObject.TypeNames.Insert(0, 'PowerView.FileACL')
                    $Out
                }
            }
            catch {
                Write-Verbose "[Get-AdaptPathAcl] error: $_"
            }
        }
    }

    END {
        # remove the IPC$ mappings
        $MappedComputers.Keys | Remove-AdaptRemoteConnection
    }
}
