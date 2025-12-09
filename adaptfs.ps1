function Get-ADAPTDomainFileServer {

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType([String])]
    [CmdletBinding()]
    Param(
        [Parameter( ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullOrEmpty()]
        [Alias('DomainName', 'Name')]
        [String[]]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [Switch]
        $Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        # Renamed internal helper to avoid conflict with native Split-Path
        function Split-ADAPTUNCPath {
            Param([String]$Path)

            if ($Path -and ($Path.split('\\').Count -ge 3)) {
                $Temp = $Path.split('\\')[2]
                if ($Temp -and ($Temp -ne '')) {
                    $Temp
                }
            }
        }

        $SearcherArguments = @{
            'LDAPFilter' = '(&(samAccountType=805306368)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(|(homedirectory=*)(scriptpath=*)(profilepath=*)))'
            'Properties' = 'homedirectory,scriptpath,profilepath'
        }
        if ($PSBoundParameters['SearchBase']) { $SearcherArguments['SearchBase'] = $SearchBase }
        if ($PSBoundParameters['Server']) { $SearcherArguments['Server'] = $Server }
        if ($PSBoundParameters['SearchScope']) { $SearcherArguments['SearchScope'] = $SearchScope }
        if ($PSBoundParameters['ResultPageSize']) { $SearcherArguments['ResultPageSize'] = $ResultPageSize }
        if ($PSBoundParameters['ServerTimeLimit']) { $SearcherArguments['ServerTimeLimit'] = $ServerTimeLimit }
        if ($PSBoundParameters['Tombstone']) { $SearcherArguments['Tombstone'] = $Tombstone }
        if ($PSBoundParameters['Credential']) { $SearcherArguments['Credential'] = $Credential }
    }

    PROCESS {
        if ($PSBoundParameters['Domain']) {
            ForEach ($TargetDomain in $Domain) {
                $SearcherArguments['Domain'] = $TargetDomain
                # Calls the helper function from Script #1
                $UserSearcher = Get-ADAPTDomainSearcher @SearcherArguments
                
                $(ForEach($UserResult in $UserSearcher.FindAll()) {
                    if ($UserResult.Properties['homedirectory']) {Split-ADAPTUNCPath($UserResult.Properties['homedirectory'])}
                    if ($UserResult.Properties['scriptpath']) {Split-ADAPTUNCPath($UserResult.Properties['scriptpath'])}
                    if ($UserResult.Properties['profilepath']) {Split-ADAPTUNCPath($UserResult.Properties['profilepath'])}
                }) | Sort-Object -Unique
            }
        }
        else {
            # Calls the helper function from Script #1
            $UserSearcher = Get-ADAPTDomainSearcher @SearcherArguments
            
            $(ForEach($UserResult in $UserSearcher.FindAll()) {
                if ($UserResult.Properties['homedirectory']) {Split-ADAPTUNCPath($UserResult.Properties['homedirectory'])}
                if ($UserResult.Properties['scriptpath']) {Split-ADAPTUNCPath($UserResult.Properties['scriptpath'])}
                if ($UserResult.Properties['profilepath']) {Split-ADAPTUNCPath($UserResult.Properties['profilepath'])}
            }) | Sort-Object -Unique
        }
    }
}
