# =====================================================================
# CORE DEPENDENCIES (FIXED)
# =====================================================================

# 1. UAC Enumeration Variable ($UACEnum)
# NOTE: The definition is now a standard hashtable for simpler compatibility.
$Global:UACEnum = @{
    'SCRIPT' = 1
    'ACCOUNTDISABLE' = 2
    'HOMEDIR_REQUIRED' = 8
    'LOCKOUT' = 16
    'PASSWORD_NOT_REQUIRED' = 32
    'NORMAL_ACCOUNT' = 512
    'DONT_REQ_PREAUTH' = 4194304
    'TRUSTED_FOR_DELEGATION' = 524288
    'NOT_DELEGATED' = 1048576
}

# 2. Function to create the DirectorySearcher object (Get-DomainSearcher)
function Get-DomainSearcher {
    [CmdletBinding()]
    Param(
        [String]$Domain,
        [String[]]$Properties = @(),
        [String]$SearchBase,
        [String]$Server,
        [String]$SearchScope,
        [Int]$ResultPageSize,
        [Int]$ServerTimeLimit,
        [String]$SecurityMasks,
        [Switch]$Tombstone,
        [Management.Automation.PSCredential]$Credential
    )
    
    $Global:DefaultSearchBase = "DC=local"
    if ($Domain) {
        $SearchBase = "DC=$($Domain -replace '\.', ',DC=')"
    } elseif (-not $SearchBase) {
        $SearchBase = $Global:DefaultSearchBase
    }

    $Searcher = New-Object System.DirectoryServices.DirectorySearcher
    $Searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$SearchBase")
    $Searcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
    
    # Adding ReferralChasing logic to attempt fixing the "A referral was returned" error.
    $Searcher.ReferralChasing = [System.DirectoryServices.ReferralChasingOptions]::None
    
    if ($Properties.Count -gt 0) { $Searcher.PropertiesToLoad.AddRange($Properties) }
    if ($SearchScope) { $Searcher.SearchScope = $SearchScope }
    if ($ResultPageSize) { $Searcher.PageSize = $ResultPageSize }
    if ($ServerTimeLimit) { $Searcher.ServerTimeLimit = [System.TimeSpan]::FromSeconds($ServerTimeLimit) }
    
    if ($SecurityMasks) {
        $Searcher.SecurityMasks = [System.DirectoryServices.SecurityMasks]::$SecurityMasks
    }

    return $Searcher
}

# 3. Name conversion function (Convert-ADName)
function Convert-ADName {
    [CmdletBinding()]
    Param(
        [String]$InputName,
        [ValidateSet('Canonical')][String]$OutputType
    )
    
    if ($InputName -like '*\*') {
        return $InputName -replace '\\', '/'
    }
    return $InputName
}

# 4. Property translation function (Convert-LDAPProperty)
function Convert-LDAPProperty {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [Object]$Properties
    )
    
    $OutputObject = New-Object PSObject
    foreach ($Property in $Properties.PropertyNames) {
        $Value = $Properties[$Property].Value
        
        if ($Value -is [System.DirectoryServices.ResultPropertyValueCollection] -and $Value.Count -eq 1) {
            $Value = $Value[0]
        }
        
        $OutputObject | Add-Member -MemberType NoteProperty -Name $Property -Value $Value
    }
    return $OutputObject
}

# ---------------------------------------------------------------------
# FUNCTION: Get-DomainUser (Your logic with fixes applied)
# ---------------------------------------------------------------------

function Get-DomainUser {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.User')]
    [OutputType('PowerView.User.Raw')]
    [CmdletBinding(DefaultParameterSetName = 'AllowDelegation')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name', 'MemberDistinguishedName', 'MemberName')]
        [String[]]
        $Identity,

        [Switch]
        $SPN,

        [Switch]
        $AdminCount,

        [Parameter(ParameterSetName = 'AllowDelegation')]
        [Switch]
        $AllowDelegation,

        [Parameter(ParameterSetName = 'DisallowDelegation')]
        [Switch]
        $DisallowDelegation,

        [Switch]
        $TrustedToAuth,

        [Alias('KerberosPreauthNotRequired', 'NoPreauth')]
        [Switch]
        $PreauthNotRequired,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties,

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

        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $SecurityMasks,

        [Switch]
        $Tombstone,

        [Alias('ReturnOne')]
        [Switch]
        $FindOne,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [Switch]
        $Raw
    )

    DynamicParam {
        # FIX: Changed Enum::GetNames($UACEnum) to access keys from the hashtable
        $UACValueNames = $Global:UACEnum.Keys | ForEach-Object { "$_"; "NOT_$_" }

        # FIX: Replaced custom New-DynamicParameter with standard parameter construction
        $UACParam = New-Object System.Management.Automation.RuntimeDefinedParameter('UACFilter', [String[]])
        $UACParam.Attributes.Add((New-Object System.Management.Automation.ValidateSetAttribute($UACValueNames)))
        
        $UACParamDictionary = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary
        $UACParamDictionary.Add('UACFilter', $UACParam)
        return $UACParamDictionary
    }

    BEGIN {
        $SearcherArguments = @{}
        if ($PSBoundParameters['Domain']) { $SearcherArguments['Domain'] = $Domain }
        if ($PSBoundParameters['Properties']) { $SearcherArguments['Properties'] = $Properties }
        if ($PSBoundParameters['SearchBase']) { $SearcherArguments['SearchBase'] = $SearchBase }
        if ($PSBoundParameters['Server']) { $SearcherArguments['Server'] = $Server }
        if ($PSBoundParameters['SearchScope']) { $SearcherArguments['SearchScope'] = $SearchScope }
        if ($PSBoundParameters['ResultPageSize']) { $SearcherArguments['ResultPageSize'] = $ResultPageSize }
        if ($PSBoundParameters['ServerTimeLimit']) { $SearcherArguments['ServerTimeLimit'] = $ServerTimeLimit }
        if ($PSBoundParameters['SecurityMasks']) { $SearcherArguments['SecurityMasks'] = $SecurityMasks }
        if ($PSBoundParameters['Tombstone']) { $SearcherArguments['Tombstone'] = $Tombstone }
        if ($PSBoundParameters['Credential']) { $SearcherArguments['Credential'] = $Credential }
        $UserSearcher = Get-DomainSearcher @SearcherArguments
    }

    PROCESS {
        # FIX: The original logic for New-DynamicParameter -CreateVariables is removed
        # and instead we directly check for the dynamically bound parameter (UACFilter)
        $UACFilter = $PSBoundParameters['UACFilter']

        if ($UserSearcher) {
            $IdentityFilter = ''
            $Filter = ''
            $Identity | Where-Object {$_} | ForEach-Object {
                $IdentityInstance = $_.Replace('(', '\28').Replace(')', '\29')
                if ($IdentityInstance -match '^S-1-') {
                    $IdentityFilter += "(objectsid=$IdentityInstance)"
                }
                elseif ($IdentityInstance -match '^CN=') {
                    $IdentityFilter += "(distinguishedname=$IdentityInstance)"
                    if ((-not $PSBoundParameters['Domain']) -and (-not $PSBoundParameters['SearchBase'])) {
                        $IdentityDomain = $IdentityInstance.SubString($IdentityInstance.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        Write-Verbose "[Get-DomainUser] Extracted domain '$IdentityDomain' from '$IdentityInstance'"
                        $SearcherArguments['Domain'] = $IdentityDomain
                        $UserSearcher = Get-DomainSearcher @SearcherArguments
                        if (-not $UserSearcher) {
                            Write-Warning "[Get-DomainUser] Unable to retrieve domain searcher for '$IdentityDomain'"
                        }
                    }
                }
                elseif ($IdentityInstance -imatch '^[0-9A-F]{8}-([0-9A-F]{4}-){3}[0-9A-F]{12}$') {
                    $GuidByteString = (([Guid]$IdentityInstance).ToByteArray() | ForEach-Object { '\' + $_.ToString('X2') }) -join ''
                    $IdentityFilter += "(objectguid=$GuidByteString)"
                }
                elseif ($IdentityInstance.Contains('\')) {
                    $ConvertedIdentityInstance = $IdentityInstance.Replace('\28', '(').Replace('\29', ')') | Convert-ADName -OutputType Canonical
                    if ($ConvertedIdentityInstance) {
                        $UserDomain = $ConvertedIdentityInstance.SubString(0, $ConvertedIdentityInstance.IndexOf('/'))
                        $UserName = $IdentityInstance.Split('\')[1]
                        $IdentityFilter += "(samAccountName=$UserName)"
                        $SearcherArguments['Domain'] = $UserDomain
                        Write-Verbose "[Get-DomainUser] Extracted domain '$UserDomain' from '$IdentityInstance'"
                        $UserSearcher = Get-DomainSearcher @SearcherArguments
                    }
                }
                else {
                    $IdentityFilter += "(samAccountName=$IdentityInstance)"
                }
            }

            if ($IdentityFilter -and ($IdentityFilter.Trim() -ne '') ) {
                $Filter += "(|$IdentityFilter)"
            }

            if ($PSBoundParameters['SPN']) {
                Write-Verbose '[Get-DomainUser] Searching for non-null service principal names'
                $Filter += '(servicePrincipalName=*)'
            }
            if ($PSBoundParameters['AllowDelegation']) {
                Write-Verbose '[Get-DomainUser] Searching for users who can be delegated'
                $Filter += '(!(userAccountControl:1.2.840.113556.1.4.803:=1048574))'
            }
            if ($PSBoundParameters['DisallowDelegation']) {
                Write-Verbose '[Get-DomainUser] Searching for users who are sensitive and not trusted for delegation'
                $Filter += '(userAccountControl:1.2.840.113556.1.4.803:=1048574)'
            }
            if ($PSBoundParameters['AdminCount']) {
                Write-Verbose '[Get-DomainUser] Searching for adminCount=1'
                $Filter += '(admincount=1)'
            }
            if ($PSBoundParameters['TrustedToAuth']) {
                Write-Verbose '[Get-DomainUser] Searching for users that are trusted to authenticate for other principals'
                $Filter += '(msds-allowedtodelegateto=*)'
            }
            if ($PSBoundParameters['PreauthNotRequired']) {
                Write-Verbose '[Get-DomainUser] Searching for user accounts that do not require kerberos preauthenticate'
                $Filter += '(userAccountControl:1.2.840.113556.1.4.803:=4194304)'
            }
            if ($PSBoundParameters['LDAPFilter']) {
                Write-Verbose "[Get-DomainUser] Using additional LDAP filter: $LDAPFilter"
                $Filter += "$LDAPFilter"
            }

            # build the LDAP filter for the dynamic UAC filter value
            $UACFilter | Where-Object {$_} | ForEach-Object {
                if ($_ -match 'NOT_.*') {
                    $UACField = $_.Substring(4)
                    # FIX: Access keys/values directly from the hashtable
                    $UACValue = $Global:UACEnum[$UACField] 
                    $Filter += "(!(userAccountControl:1.2.840.113556.1.4.803:=$UACValue))"
                }
                else {
                    # FIX: Access keys/values directly from the hashtable
                    $UACValue = $Global:UACEnum[$_]
                    $Filter += "(userAccountControl:1.2.840.113556.1.4.803:=$UACValue)"
                }
            }

            $UserSearcher.filter = "(&(samAccountType=805306368)$Filter)"
            Write-Verbose "[Get-DomainUser] filter string: $($UserSearcher.filter)"

            if ($PSBoundParameters['FindOne']) { $Results = $UserSearcher.FindOne() }
            else { $Results = $UserSearcher.FindAll() }
            $Results | Where-Object {$_} | ForEach-Object {
                if ($PSBoundParameters['Raw']) {
                    $User = $_
                    $User.PSObject.TypeNames.Insert(0, 'PowerView.User.Raw')
                }
                else {
                    $User = Convert-LDAPProperty -Properties $_.Properties
                    $User.PSObject.TypeNames.Insert(0, 'PowerView.User')
                }
                $User
            }
            if ($Results) {
                try { $Results.dispose() }
                catch {
                    Write-Verbose "[Get-DomainUser] Error disposing of the Results object: $_"
                }
            }
            $UserSearcher.dispose()
        }
    }
}
