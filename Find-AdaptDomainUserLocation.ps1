#requires -version 2

<#
    Find-AdaptDomainUserLocation.ps1 - Fully Standalone Function
    Based on PowerView by Will Schroeder (@harmj0y)
    Original function: Find-AdaptDomainUserLocation
    
    This file contains all required dependencies and can be run independently.
#>

# --- New-InMemoryModule ---
function New-InMemoryModule {
<#
.SYNOPSIS

Creates an in-memory assembly and module

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

When defining custom enums, structs, and unmanaged functions, it is
necessary to associate to an assembly module. This helper function
creates an in-memory module that can be passed to the 'enum',
'struct', and Add-Win32Type functions.

.PARAMETER ModuleName

Specifies the desired name for the in-memory assembly and module. If
ModuleName is not provided, it will default to a GUID.

.EXAMPLE

$Module = New-InMemoryModule -ModuleName Win32
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ModuleName = [Guid]::NewGuid().ToString()
    )

    $AppDomain = [Reflection.Assembly].Assembly.GetType('System.AppDomain').GetProperty('CurrentDomain').GetValue($null, @())
    $LoadedAssemblies = $AppDomain.GetAssemblies()

    foreach ($Assembly in $LoadedAssemblies) {
        if ($Assembly.FullName -and ($Assembly.FullName.Split(',')[0] -eq $ModuleName)) {
            return $Assembly
        }
    }

    $DynAssembly = New-Object Reflection.AssemblyName($ModuleName)
    $Domain = $AppDomain
    $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, 'Run')
    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule($ModuleName, $False)

    return $ModuleBuilder
}

# --- func ---
function func {
    Param (
        [Parameter(Position = 0, Mandatory = $True)]
        [String]
        $DllName,

        [Parameter(Position = 1, Mandatory = $True)]
        [string]
        $FunctionName,

        [Parameter(Position = 2, Mandatory = $True)]
        [Type]
        $ReturnType,

        [Parameter(Position = 3)]
        [Type[]]
        $ParameterTypes,

        [Parameter(Position = 4)]
        [Runtime.InteropServices.CallingConvention]
        $NativeCallingConvention,

        [Parameter(Position = 5)]
        [Runtime.InteropServices.CharSet]
        $Charset,

        [String]
        $EntryPoint,

        [Switch]
        $SetLastError
    )

    $Properties = @{
        DllName = $DllName
        FunctionName = $FunctionName
        ReturnType = $ReturnType
    }

    if ($ParameterTypes) { $Properties['ParameterTypes'] = $ParameterTypes }
    if ($NativeCallingConvention) { $Properties['NativeCallingConvention'] = $NativeCallingConvention }
    if ($Charset) { $Properties['Charset'] = $Charset }
    if ($SetLastError) { $Properties['SetLastError'] = $SetLastError }
    if ($EntryPoint) { $Properties['EntryPoint'] = $EntryPoint }

    New-Object PSObject -Property $Properties
}

# --- Add-Win32Type ---
function Add-Win32Type
{
<#
.SYNOPSIS

Creates a .NET type for an unmanaged Win32 function.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: func

.DESCRIPTION

Add-Win32Type enables you to easily interact with unmanaged (i.e.
Win32 unmanaged) functions in PowerShell. After providing
Add-Win32Type with a function signature, a .NET type is created
using reflection (i.e. csc.exe is never called like with Add-Type).

The 'func' helper function can be used to reduce typing when defining
multiple function definitions.

.PARAMETER DllName

The name of the DLL.

.PARAMETER FunctionName

The name of the target function.

.PARAMETER EntryPoint

The DLL export function name. This argument should be specified if the
specified function name is different than the name of the exported
function.

.PARAMETER ReturnType

The return type of the function.

.PARAMETER ParameterTypes

The function parameters.

.PARAMETER NativeCallingConvention

Specifies the native calling convention of the function. Defaults to
stdcall.

.PARAMETER Charset

If you need to explicitly call an 'A' or 'W' Win32 function, you can
specify the character set.

.PARAMETER SetLastError

Indicates whether the callee calls the SetLastError Win32 API
function before returning from the attributed method.

.PARAMETER Module

The in-memory module that will host the functions. Use
New-InMemoryModule to define an in-memory module.

.PARAMETER Namespace

An optional namespace to prepend to the type. Add-Win32Type defaults
to a namespace consisting only of the name of the DLL.

.EXAMPLE

$Mod = New-InMemoryModule -ModuleName Win32

$FunctionDefinitions = @(
  (func kernel32 GetProcAddress ([IntPtr]) @([IntPtr], [String]) -Charset Ansi -SetLastError),
  (func kernel32 GetModuleHandle ([Intptr]) @([String]) -SetLastError),
  (func ntdll RtlGetCurrentPeb ([IntPtr]) @())
)

$Types = $FunctionDefinitions | Add-Win32Type -Module $Mod -Namespace 'Win32'
$Kernel32 = $Types['kernel32']
$Ntdll = $Types['ntdll']
$Ntdll::RtlGetCurrentPeb()
$ntdllbase = $Kernel32::GetModuleHandle('ntdll')
$Kernel32::GetProcAddress($ntdllbase, 'RtlGetCurrentPeb')

.NOTES

Inspired by Lee Holmes' Invoke-WindowsApi http://poshcode.org/2189

When defining multiple function prototypes, it is ideal to provide
Add-Win32Type with an array of function signatures. That way, they
are all incorporated into the same in-memory module.
#>

    [OutputType([Hashtable])]
    Param(
        [Parameter(Mandatory=$True, ValueFromPipelineByPropertyName=$True)]
        [String]
        $DllName,

        [Parameter(Mandatory=$True, ValueFromPipelineByPropertyName=$True)]
        [String]
        $FunctionName,

        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [String]
        $EntryPoint,

        [Parameter(Mandatory=$True, ValueFromPipelineByPropertyName=$True)]
        [Type]
        $ReturnType,

        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [Type[]]
        $ParameterTypes,

        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [Runtime.InteropServices.CallingConvention]
        $NativeCallingConvention = [Runtime.InteropServices.CallingConvention]::StdCall,

        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [Runtime.InteropServices.CharSet]
        $Charset = [Runtime.InteropServices.CharSet]::Auto,

        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [Switch]
        $SetLastError,

        [Parameter(Mandatory=$True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [ValidateNotNull()]
        [String]
        $Namespace = ''
    )

    BEGIN
    {
        $TypeHash = @{}
    }

    PROCESS
    {
        if ($Module -is [Reflection.Assembly])
        {
            if ($Namespace)
            {
                $TypeHash[$DllName] = $Module.GetType("$Namespace.$DllName")
            }
            else
            {
                $TypeHash[$DllName] = $Module.GetType($DllName)
            }
        }
        else
        {
            # Define one type for each DLL
            if (!$TypeHash.ContainsKey($DllName))
            {
                if ($Namespace)
                {
                    $TypeHash[$DllName] = $Module.DefineType("$Namespace.$DllName", 'Public,BeforeFieldInit')
                }
                else
                {
                    $TypeHash[$DllName] = $Module.DefineType($DllName, 'Public,BeforeFieldInit')
                }
            }

            $Method = $TypeHash[$DllName].DefineMethod(
                $FunctionName,
                'Public,Static,PinvokeImpl',
                $ReturnType,
                $ParameterTypes)

            # Make each ByRef parameter an Out parameter
            $i = 1
            foreach($Parameter in $ParameterTypes)
            {
                if ($Parameter.IsByRef)
                {
                    [void] $Method.DefineParameter($i, 'Out', $null)
                }

                $i++
            }

            $DllImport = [Runtime.InteropServices.DllImportAttribute]
            $SetLastErrorField = $DllImport.GetField('SetLastError')
            $CallingConventionField = $DllImport.GetField('CallingConvention')
            $CharsetField = $DllImport.GetField('CharSet')
            $EntryPointField = $DllImport.GetField('EntryPoint')
            if ($SetLastError) { $SLEValue = $True } else { $SLEValue = $False }

            if ($PSBoundParameters['EntryPoint']) { $ExportedFuncName = $EntryPoint } else { $ExportedFuncName = $FunctionName }

            # Equivalent to C# version of [DllImport(DllName)]
            $Constructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor([String])
            $DllImportAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($Constructor,
                $DllName, [Reflection.PropertyInfo[]] @(), [Object[]] @(),
                [Reflection.FieldInfo[]] @($SetLastErrorField,
                                           $CallingConventionField,
                                           $CharsetField,
                                           $EntryPointField),
                [Object[]] @($SLEValue,
                             ([Runtime.InteropServices.CallingConvention] $NativeCallingConvention),
                             ([Runtime.InteropServices.CharSet] $Charset),
                             $ExportedFuncName))

            $Method.SetCustomAttribute($DllImportAttribute)
        }
    }

    END
    {
        if ($Module -is [Reflection.Assembly])
        {
            return $TypeHash
        }

        $ReturnTypes = @{}

        foreach ($Key in $TypeHash.Keys)
        {
            $Type = $TypeHash[$Key].CreateType()

            $ReturnTypes[$Key] = $Type
        }

        return $ReturnTypes
    }
}

# --- psenum ---
function psenum {
<#
.SYNOPSIS

Creates an in-memory enumeration for use in your PowerShell session.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

The 'psenum' function facilitates the creation of enums entirely in
memory using as close to a "C style" as PowerShell will allow.

.PARAMETER Module

The in-memory module that will host the enum. Use
New-InMemoryModule to define an in-memory module.

.PARAMETER FullName

The fully-qualified name of the enum.

.PARAMETER Type

The type of each enum element.

.PARAMETER EnumElements

A hashtable of enum elements.

.PARAMETER Bitfield

Specifies that the enum should be treated as a bitfield.

.EXAMPLE

$Mod = New-InMemoryModule -ModuleName Win32

$ImageSubsystem = psenum $Mod PE.IMAGE_SUBSYSTEM UInt16 @{
    UNKNOWN =                  0
    NATIVE =                   1 # Image doesn't require a subsystem.
    WINDOWS_GUI =              2 # Image runs in the Windows GUI subsystem.
    WINDOWS_CUI =              3 # Image runs in the Windows character subsystem.
    OS2_CUI =                  5 # Image runs in the OS/2 character subsystem.
    POSIX_CUI =                7 # Image runs in the Posix character subsystem.
    NATIVE_WINDOWS =           8 # Image is a native Win9x driver.
    WINDOWS_CE_GUI =           9 # Image runs in the Windows CE subsystem.
    EFI_APPLICATION =          10
    EFI_BOOT_SERVICE_DRIVER =  11
    EFI_RUNTIME_DRIVER =       12
    EFI_ROM =                  13
    XBOX =                     14
    WINDOWS_BOOT_APPLICATION = 16
}

.NOTES

PowerShell purists may disagree with the naming of this function but
again, this was developed in such a way so as to emulate a "C style"
definition as closely as possible. Sorry, I'm not going to name it
New-Enum. :P
#>

    [OutputType([Type])]
    Param (
        [Parameter(Position = 0, Mandatory=$True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [Parameter(Position = 1, Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $FullName,

        [Parameter(Position = 2, Mandatory=$True)]
        [Type]
        $Type,

        [Parameter(Position = 3, Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $EnumElements,

        [Switch]
        $Bitfield
    )

    if ($Module -is [Reflection.Assembly])
    {
        return ($Module.GetType($FullName))
    }

    $EnumType = $Type -as [Type]

    $EnumBuilder = $Module.DefineEnum($FullName, 'Public', $EnumType)

    if ($Bitfield)
    {
        $FlagsConstructor = [FlagsAttribute].GetConstructor(@())
        $FlagsCustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($FlagsConstructor, @())
        $EnumBuilder.SetCustomAttribute($FlagsCustomAttribute)
    }

    foreach ($Key in $EnumElements.Keys)
    {
        # Apply the specified enum type to each element
        $null = $EnumBuilder.DefineLiteral($Key, $EnumElements[$Key] -as $EnumType)
    }

    $EnumBuilder.CreateType()
}

# --- field ---
function field {
    Param (
        [Parameter(Position = 0, Mandatory=$True)]
        [UInt16]
        $Position,

        [Parameter(Position = 1, Mandatory=$True)]
        [Type]
        $Type,

        [Parameter(Position = 2)]
        [UInt16]
        $Offset,

        [Object[]]
        $MarshalAs
    )

    @{
        Position = $Position
        Type = $Type -as [Type]
        Offset = $Offset
        MarshalAs = $MarshalAs
    }
}

# --- struct ---
function struct
{
<#
.SYNOPSIS

Creates an in-memory struct for use in your PowerShell session.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: field

.DESCRIPTION

The 'struct' function facilitates the creation of structs entirely in
memory using as close to a "C style" as PowerShell will allow. Struct
fields are specified using a hashtable where each field of the struct
is comprosed of the order in which it should be defined, its .NET
type, and optionally, its offset and special marshaling attributes.

One of the features of 'struct' is that after your struct is defined,
it will come with a built-in GetSize method as well as an explicit
converter so that you can easily cast an IntPtr to the struct without
relying upon calling SizeOf and/or PtrToStructure in the Marshal
class.

.PARAMETER Module

The in-memory module that will host the struct. Use
New-InMemoryModule to define an in-memory module.

.PARAMETER FullName

The fully-qualified name of the struct.

.PARAMETER StructFields

A hashtable of fields. Use the 'field' helper function to ease
defining each field.

.PARAMETER PackingSize

Specifies the memory alignment of fields.

.PARAMETER ExplicitLayout

Indicates that an explicit offset for each field will be specified.

.EXAMPLE

$Mod = New-InMemoryModule -ModuleName Win32

$ImageDosSignature = psenum $Mod PE.IMAGE_DOS_SIGNATURE UInt16 @{
    DOS_SIGNATURE =    0x5A4D
    OS2_SIGNATURE =    0x454E
    OS2_SIGNATURE_LE = 0x454C
    VXD_SIGNATURE =    0x454C
}

$ImageDosHeader = struct $Mod PE.IMAGE_DOS_HEADER @{
    e_magic =    field 0 $ImageDosSignature
    e_cblp =     field 1 UInt16
    e_cp =       field 2 UInt16
    e_crlc =     field 3 UInt16
    e_cparhdr =  field 4 UInt16
    e_minalloc = field 5 UInt16
    e_maxalloc = field 6 UInt16
    e_ss =       field 7 UInt16
    e_sp =       field 8 UInt16
    e_csum =     field 9 UInt16
    e_ip =       field 10 UInt16
    e_cs =       field 11 UInt16
    e_lfarlc =   field 12 UInt16
    e_ovno =     field 13 UInt16
    e_res =      field 14 UInt16[] -MarshalAs @('ByValArray', 4)
    e_oemid =    field 15 UInt16
    e_oeminfo =  field 16 UInt16
    e_res2 =     field 17 UInt16[] -MarshalAs @('ByValArray', 10)
    e_lfanew =   field 18 Int32
}

# Example of using an explicit layout in order to create a union.
$TestUnion = struct $Mod TestUnion @{
    field1 = field 0 UInt32 0
    field2 = field 1 IntPtr 0
} -ExplicitLayout

.NOTES

PowerShell purists may disagree with the naming of this function but
again, this was developed in such a way so as to emulate a "C style"
definition as closely as possible. Sorry, I'm not going to name it
New-Struct. :P
#>

    [OutputType([Type])]
    Param (
        [Parameter(Position = 1, Mandatory=$True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [Parameter(Position = 2, Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $FullName,

        [Parameter(Position = 3, Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $StructFields,

        [Reflection.Emit.PackingSize]
        $PackingSize = [Reflection.Emit.PackingSize]::Unspecified,

        [Switch]
        $ExplicitLayout
    )

    if ($Module -is [Reflection.Assembly])
    {
        return ($Module.GetType($FullName))
    }

    [Reflection.TypeAttributes] $StructAttributes = 'AnsiClass,
        Class,
        Public,
        Sealed,
        BeforeFieldInit'

    if ($ExplicitLayout)
    {
        $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::ExplicitLayout
    }
    else
    {
        $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::SequentialLayout
    }

    $StructBuilder = $Module.DefineType($FullName, $StructAttributes, [ValueType], $PackingSize)
    $ConstructorInfo = [Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]
    $SizeConst = @([Runtime.InteropServices.MarshalAsAttribute].GetField('SizeConst'))

    $Fields = New-Object Hashtable[]($StructFields.Count)

    # Sort each field according to the orders specified
    # Unfortunately, PSv2 doesn't have the luxury of the
    # hashtable [Ordered] accelerator.
    foreach ($Field in $StructFields.Keys)
    {
        $Index = $StructFields[$Field]['Position']
        $Fields[$Index] = @{FieldName = $Field; Properties = $StructFields[$Field]}
    }

    foreach ($Field in $Fields)
    {
        $FieldName = $Field['FieldName']
        $FieldProp = $Field['Properties']

        $Offset = $FieldProp['Offset']
        $Type = $FieldProp['Type']
        $MarshalAs = $FieldProp['MarshalAs']

        $NewField = $StructBuilder.DefineField($FieldName, $Type, 'Public')

        if ($MarshalAs)
        {
            $UnmanagedType = $MarshalAs[0] -as ([Runtime.InteropServices.UnmanagedType])
            if ($MarshalAs[1])
            {
                $Size = $MarshalAs[1]
                $AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ConstructorInfo,
                    $UnmanagedType, $SizeConst, @($Size))
            }
            else
            {
                $AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, [Object[]] @($UnmanagedType))
            }

            $NewField.SetCustomAttribute($AttribBuilder)
        }

        if ($ExplicitLayout) { $NewField.SetOffset($Offset) }
    }

    # Make the struct aware of its own size.
    # No more having to call [Runtime.InteropServices.Marshal]::SizeOf!
    $SizeMethod = $StructBuilder.DefineMethod('GetSize',
        'Public, Static',
        [Int],
        [Type[]] @())
    $ILGenerator = $SizeMethod.GetILGenerator()
    # Thanks for the help, Jason Shirk!
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Ldtoken, $StructBuilder)
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod('GetTypeFromHandle'))
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod('SizeOf', [Type[]] @([Type])))
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Ret)

    # Allow for explicit casting from an IntPtr
    # No more having to call [Runtime.InteropServices.Marshal]::PtrToStructure!
    $ImplicitConverter = $StructBuilder.DefineMethod('op_Implicit',
        'PrivateScope, Public, Static, HideBySig, SpecialName',
        $StructBuilder,
        [Type[]] @([IntPtr]))
    $ILGenerator2 = $ImplicitConverter.GetILGenerator()
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Nop)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldarg_0)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldtoken, $StructBuilder)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod('GetTypeFromHandle'))
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod('PtrToStructure', [Type[]] @([IntPtr], [Type])))
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Unbox_Any, $StructBuilder)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ret)

    $StructBuilder.CreateType()
}

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

# --- Convert-LDAPProperty ---
function Convert-LDAPProperty {
<#
.SYNOPSIS

Helper that converts specific LDAP property result fields and outputs
a custom psobject.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: None  

.DESCRIPTION

Converts a set of raw LDAP properties results from ADSI/LDAP searches
into a proper PSObject. Used by several of the Get-AdaptDomain* function.

.PARAMETER Properties

Properties object to extract out LDAP fields for display.

.OUTPUTS

System.Management.Automation.PSCustomObject

A custom PSObject with LDAP hashtable properties translated.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('System.Management.Automation.PSCustomObject')]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        $Properties
    )

    $ObjectProperties = @{}

    $Properties.PropertyNames | ForEach-Object {
        if ($_ -ne 'adspath') {
            if (($_ -eq 'objectsid') -or ($_ -eq 'sidhistory')) {
                # convert all listed sids (i.e. if multiple are listed in sidHistory)
                $ObjectProperties[$_] = $Properties[$_] | ForEach-Object { (New-Object System.Security.Principal.SecurityIdentifier($_, 0)).Value }
            }
            elseif ($_ -eq 'grouptype') {
                $ObjectProperties[$_] = $Properties[$_][0] -as $GroupTypeEnum
            }
            elseif ($_ -eq 'samaccounttype') {
                $ObjectProperties[$_] = $Properties[$_][0] -as $SamAccountTypeEnum
            }
            elseif ($_ -eq 'objectguid') {
                # convert the GUID to a string
                $ObjectProperties[$_] = (New-Object Guid (,$Properties[$_][0])).Guid
            }
            elseif ($_ -eq 'useraccountcontrol') {
                $ObjectProperties[$_] = $Properties[$_][0] -as $UACEnum
            }
            elseif ($_ -eq 'ntsecuritydescriptor') {
                # $ObjectProperties[$_] = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $Properties[$_][0], 0
                $Descriptor = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $Properties[$_][0], 0
                if ($Descriptor.Owner) {
                    $ObjectProperties['Owner'] = $Descriptor.Owner
                }
                if ($Descriptor.Group) {
                    $ObjectProperties['Group'] = $Descriptor.Group
                }
                if ($Descriptor.DiscretionaryAcl) {
                    $ObjectProperties['DiscretionaryAcl'] = $Descriptor.DiscretionaryAcl
                }
                if ($Descriptor.SystemAcl) {
                    $ObjectProperties['SystemAcl'] = $Descriptor.SystemAcl
                }
            }
            elseif ($_ -eq 'accountexpires') {
                if ($Properties[$_][0] -gt [DateTime]::MaxValue.Ticks) {
                    $ObjectProperties[$_] = "NEVER"
                }
                else {
                    $ObjectProperties[$_] = [datetime]::fromfiletime($Properties[$_][0])
                }
            }
            elseif ( ($_ -eq 'lastlogon') -or ($_ -eq 'lastlogontimestamp') -or ($_ -eq 'pwdlastset') -or ($_ -eq 'lastlogoff') -or ($_ -eq 'badPasswordTime') ) {
                # convert timestamps
                if ($Properties[$_][0] -is [System.MarshalByRefObject]) {
                    # if we have a System.__ComObject
                    $Temp = $Properties[$_][0]
                    [Int32]$High = $Temp.GetType().InvokeMember('HighPart', [System.Reflection.BindingFlags]::GetProperty, $Null, $Temp, $Null)
                    [Int32]$Low  = $Temp.GetType().InvokeMember('LowPart',  [System.Reflection.BindingFlags]::GetProperty, $Null, $Temp, $Null)
                    $ObjectProperties[$_] = ([datetime]::FromFileTime([Int64]("0x{0:x8}{1:x8}" -f $High, $Low)))
                }
                else {
                    # otherwise just a string
                    $ObjectProperties[$_] = ([datetime]::FromFileTime(($Properties[$_][0])))
                }
            }
            elseif ($Properties[$_][0] -is [System.MarshalByRefObject]) {
                # try to convert misc com objects
                $Prop = $Properties[$_]
                try {
                    $Temp = $Prop[$_][0]
                    [Int32]$High = $Temp.GetType().InvokeMember('HighPart', [System.Reflection.BindingFlags]::GetProperty, $Null, $Temp, $Null)
                    [Int32]$Low  = $Temp.GetType().InvokeMember('LowPart',  [System.Reflection.BindingFlags]::GetProperty, $Null, $Temp, $Null)
                    $ObjectProperties[$_] = [Int64]("0x{0:x8}{1:x8}" -f $High, $Low)
                }
                catch {
                    Write-Verbose "[Convert-LDAPProperty] error: $_"
                    $ObjectProperties[$_] = $Prop[$_]
                }
            }
            elseif ($Properties[$_].count -eq 1) {
                $ObjectProperties[$_] = $Properties[$_][0]
            }
            else {
                $ObjectProperties[$_] = $Properties[$_]
            }
        }
    }
    try {
        New-Object -TypeName PSObject -Property $ObjectProperties
    }
    catch {
        Write-Warning "[Convert-LDAPProperty] Error parsing LDAP properties : $_"
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

# --- ConvertFrom-UACValue ---
function ConvertFrom-UACValue {
<#
.SYNOPSIS

Converts a UAC int value to human readable form.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: None  

.DESCRIPTION

This function will take an integer that represents a User Account
Control (UAC) binary blob and will covert it to an ordered
dictionary with each bitwise value broken out. By default only values
set are displayed- the -ShowAll switch will display all values with
a + next to the ones set.

.PARAMETER Value

Specifies the integer UAC value to convert.

.PARAMETER ShowAll

Switch. Signals ConvertFrom-UACValue to display all UAC values, with a + indicating the value is currently set.

.EXAMPLE

ConvertFrom-UACValue -Value 66176

Name                           Value
----                           -----
ENCRYPTED_TEXT_PWD_ALLOWED     128
NORMAL_ACCOUNT                 512
DONT_EXPIRE_PASSWORD           65536

.EXAMPLE

Get-AdaptDomainUser harmj0y | ConvertFrom-UACValue

Name                           Value
----                           -----
NORMAL_ACCOUNT                 512
DONT_EXPIRE_PASSWORD           65536

.EXAMPLE

Get-AdaptDomainUser harmj0y | ConvertFrom-UACValue -ShowAll

Name                           Value
----                           -----
SCRIPT                         1
ACCOUNTDISABLE                 2
HOMEDIR_REQUIRED               8
LOCKOUT                        16
PASSWD_NOTREQD                 32
PASSWD_CANT_CHANGE             64
ENCRYPTED_TEXT_PWD_ALLOWED     128
TEMP_DUPLICATE_ACCOUNT         256
NORMAL_ACCOUNT                 512+
INTERDOMAIN_TRUST_ACCOUNT      2048
WORKSTATION_TRUST_ACCOUNT      4096
SERVER_TRUST_ACCOUNT           8192
DONT_EXPIRE_PASSWORD           65536+
MNS_LOGON_ACCOUNT              131072
SMARTCARD_REQUIRED             262144
TRUSTED_FOR_DELEGATION         524288
NOT_DELEGATED                  1048576
USE_DES_KEY_ONLY               2097152
DONT_REQ_PREAUTH               4194304
PASSWORD_EXPIRED               8388608
TRUSTED_TO_AUTH_FOR_DELEGATION 16777216
PARTIAL_SECRETS_ACCOUNT        67108864

.INPUTS

Int

Accepts an integer representing a UAC binary blob.

.OUTPUTS

System.Collections.Specialized.OrderedDictionary

An ordered dictionary with the converted UAC fields.

.LINK

https://support.microsoft.com/en-us/kb/305144
#>

    [OutputType('System.Collections.Specialized.OrderedDictionary')]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('UAC', 'useraccountcontrol')]
        [Int]
        $Value,

        [Switch]
        $ShowAll
    )

    BEGIN {
        # values from https://support.microsoft.com/en-us/kb/305144
        $UACValues = New-Object System.Collections.Specialized.OrderedDictionary
        $UACValues.Add("SCRIPT", 1)
        $UACValues.Add("ACCOUNTDISABLE", 2)
        $UACValues.Add("HOMEDIR_REQUIRED", 8)
        $UACValues.Add("LOCKOUT", 16)
        $UACValues.Add("PASSWD_NOTREQD", 32)
        $UACValues.Add("PASSWD_CANT_CHANGE", 64)
        $UACValues.Add("ENCRYPTED_TEXT_PWD_ALLOWED", 128)
        $UACValues.Add("TEMP_DUPLICATE_ACCOUNT", 256)
        $UACValues.Add("NORMAL_ACCOUNT", 512)
        $UACValues.Add("INTERDOMAIN_TRUST_ACCOUNT", 2048)
        $UACValues.Add("WORKSTATION_TRUST_ACCOUNT", 4096)
        $UACValues.Add("SERVER_TRUST_ACCOUNT", 8192)
        $UACValues.Add("DONT_EXPIRE_PASSWORD", 65536)
        $UACValues.Add("MNS_LOGON_ACCOUNT", 131072)
        $UACValues.Add("SMARTCARD_REQUIRED", 262144)
        $UACValues.Add("TRUSTED_FOR_DELEGATION", 524288)
        $UACValues.Add("NOT_DELEGATED", 1048576)
        $UACValues.Add("USE_DES_KEY_ONLY", 2097152)
        $UACValues.Add("DONT_REQ_PREAUTH", 4194304)
        $UACValues.Add("PASSWORD_EXPIRED", 8388608)
        $UACValues.Add("TRUSTED_TO_AUTH_FOR_DELEGATION", 16777216)
        $UACValues.Add("PARTIAL_SECRETS_ACCOUNT", 67108864)
    }

    PROCESS {
        $ResultUACValues = New-Object System.Collections.Specialized.OrderedDictionary

        if ($ShowAll) {
            ForEach ($UACValue in $UACValues.GetEnumerator()) {
                if ( ($Value -band $UACValue.Value) -eq $UACValue.Value) {
                    $ResultUACValues.Add($UACValue.Name, "$($UACValue.Value)+")
                }
                else {
                    $ResultUACValues.Add($UACValue.Name, "$($UACValue.Value)")
                }
            }
        }
        else {
            ForEach ($UACValue in $UACValues.GetEnumerator()) {
                if ( ($Value -band $UACValue.Value) -eq $UACValue.Value) {
                    $ResultUACValues.Add($UACValue.Name, "$($UACValue.Value)")
                }
            }
        }
        $ResultUACValues
    }
}

# --- Get-DomainSearcher ---
function Get-DomainSearcher {
<#
.SYNOPSIS

Helper used by various functions that builds a custom AD searcher object.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-AdaptDomain  

.DESCRIPTION

Takes a given domain and a number of customizations and returns a
System.DirectoryServices.DirectorySearcher object. This function is used
heavily by other LDAP/ADSI searcher functions (Verb-Domain*).

.PARAMETER Domain

Specifies the domain to use for the query, defaults to the current domain.

.PARAMETER LDAPFilter

Specifies an LDAP query string that is used to filter Active Directory objects.

.PARAMETER Properties

Specifies the properties of the output object to retrieve from the server.

.PARAMETER SearchBase

The LDAP source to search through, e.g. "LDAP://OU=secret,DC=testlab,DC=local"
Useful for OU queries.

.PARAMETER SearchBasePrefix

Specifies a prefix for the LDAP search string (i.e. "CN=Sites,CN=Configuration").

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to for the search.

.PARAMETER SearchScope

Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER SecurityMasks

Specifies an option for examining security information of a directory object.
One of 'Dacl', 'Group', 'None', 'Owner', 'Sacl'.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.EXAMPLE

Get-DomainSearcher -Domain testlab.local

Return a searcher for all objects in testlab.local.

.EXAMPLE

Get-DomainSearcher -Domain testlab.local -LDAPFilter '(samAccountType=805306368)' -Properties 'SamAccountName,lastlogon'

Return a searcher for user objects in testlab.local and only return the SamAccountName and LastLogon properties.

.EXAMPLE

Get-DomainSearcher -SearchBase "LDAP://OU=secret,DC=testlab,DC=local"

Return a searcher that searches through the specific ADS/LDAP search base (i.e. OU).

.OUTPUTS

System.DirectoryServices.DirectorySearcher
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('System.DirectoryServices.DirectorySearcher')]
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline = $True)]
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
        [String]
        $SearchBasePrefix,

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
        $ServerTimeLimit = 120,

        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $SecurityMasks,

        [Switch]
        $Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        if ($PSBoundParameters['Domain']) {
            $TargetDomain = $Domain

            if ($ENV:USERDNSDOMAIN -and ($ENV:USERDNSDOMAIN.Trim() -ne '')) {
                # see if we can grab the user DNS logon domain from environment variables
                $UserDomain = $ENV:USERDNSDOMAIN
                if ($ENV:LOGONSERVER -and ($ENV:LOGONSERVER.Trim() -ne '') -and $UserDomain) {
                    $BindServer = "$($ENV:LOGONSERVER -replace '\\','').$UserDomain"
                }
            }
        }
        elseif ($PSBoundParameters['Credential']) {
            # if not -Domain is specified, but -Credential is, try to retrieve the current domain name with Get-AdaptDomain
            $DomainObject = Get-AdaptDomain -Credential $Credential
            $BindServer = ($DomainObject.PdcRoleOwner).Name
            $TargetDomain = $DomainObject.Name
        }
        elseif ($ENV:USERDNSDOMAIN -and ($ENV:USERDNSDOMAIN.Trim() -ne '')) {
            # see if we can grab the user DNS logon domain from environment variables
            $TargetDomain = $ENV:USERDNSDOMAIN
            if ($ENV:LOGONSERVER -and ($ENV:LOGONSERVER.Trim() -ne '') -and $TargetDomain) {
                $BindServer = "$($ENV:LOGONSERVER -replace '\\','').$TargetDomain"
            }
        }
        else {
            # otherwise, resort to Get-AdaptDomain to retrieve the current domain object
            write-verbose "get-domain"
            $DomainObject = Get-AdaptDomain
            $BindServer = ($DomainObject.PdcRoleOwner).Name
            $TargetDomain = $DomainObject.Name
        }

        if ($PSBoundParameters['Server']) {
            # if there's not a specified server to bind to, try to pull a logon server from ENV variables
            $BindServer = $Server
        }

        $SearchString = 'LDAP://'

        if ($BindServer -and ($BindServer.Trim() -ne '')) {
            $SearchString += $BindServer
            if ($TargetDomain) {
                $SearchString += '/'
            }
        }

        if ($PSBoundParameters['SearchBasePrefix']) {
            $SearchString += $SearchBasePrefix + ','
        }

        if ($PSBoundParameters['SearchBase']) {
            if ($SearchBase -Match '^GC://') {
                # if we're searching the global catalog, get the path in the right format
                $DN = $SearchBase.ToUpper().Trim('/')
                $SearchString = ''
            }
            else {
                if ($SearchBase -match '^LDAP://') {
                    if ($SearchBase -match "LDAP://.+/.+") {
                        $SearchString = ''
                        $DN = $SearchBase
                    }
                    else {
                        $DN = $SearchBase.SubString(7)
                    }
                }
                else {
                    $DN = $SearchBase
                }
            }
        }
        else {
            # transform the target domain name into a distinguishedName if an ADS search base is not specified
            if ($TargetDomain -and ($TargetDomain.Trim() -ne '')) {
                $DN = "DC=$($TargetDomain.Replace('.', ',DC='))"
            }
        }

        $SearchString += $DN
        Write-Verbose "[Get-DomainSearcher] search base: $SearchString"

        if ($Credential -ne [Management.Automation.PSCredential]::Empty) {
            Write-Verbose "[Get-DomainSearcher] Using alternate credentials for LDAP connection"
            # bind to the inital search object using alternate credentials
            $DomainObject = New-Object DirectoryServices.DirectoryEntry($SearchString, $Credential.UserName, $Credential.GetNetworkCredential().Password)
            $Searcher = New-Object System.DirectoryServices.DirectorySearcher($DomainObject)
        }
        else {
            # bind to the inital object using the current credentials
            $Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
        }

        $Searcher.PageSize = $ResultPageSize
        $Searcher.SearchScope = $SearchScope
        $Searcher.CacheResults = $False
        $Searcher.ReferralChasing = [System.DirectoryServices.ReferralChasingOption]::All

        if ($PSBoundParameters['ServerTimeLimit']) {
            $Searcher.ServerTimeLimit = $ServerTimeLimit
        }

        if ($PSBoundParameters['Tombstone']) {
            $Searcher.Tombstone = $True
        }

        if ($PSBoundParameters['LDAPFilter']) {
            $Searcher.filter = $LDAPFilter
        }

        if ($PSBoundParameters['SecurityMasks']) {
            $Searcher.SecurityMasks = Switch ($SecurityMasks) {
                'Dacl' { [System.DirectoryServices.SecurityMasks]::Dacl }
                'Group' { [System.DirectoryServices.SecurityMasks]::Group }
                'None' { [System.DirectoryServices.SecurityMasks]::None }
                'Owner' { [System.DirectoryServices.SecurityMasks]::Owner }
                'Sacl' { [System.DirectoryServices.SecurityMasks]::Sacl }
            }
        }

        if ($PSBoundParameters['Properties']) {
            # handle an array of properties to load w/ the possibility of comma-separated strings
            $PropertiesToLoad = $Properties| ForEach-Object { $_.Split(',') }
            $Null = $Searcher.PropertiesToLoad.AddRange(($PropertiesToLoad))
        }

        $Searcher
    }
}

# --- Invoke-RevertToSelf ---
function Invoke-RevertToSelf {
<#
.SYNOPSIS

Reverts any token impersonation.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: PSReflect  

.DESCRIPTION

This function uses RevertToSelf() to revert any impersonated tokens.
If -TokenHandle is passed (the token handle returned by Invoke-UserImpersonation),
CloseHandle() is used to close the opened handle.

.PARAMETER TokenHandle

An optional IntPtr TokenHandle returned by Invoke-UserImpersonation.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
$Token = Invoke-UserImpersonation -Credential $Cred
Invoke-RevertToSelf -TokenHandle $Token
#>

    [CmdletBinding()]
    Param(
        [ValidateNotNull()]
        [IntPtr]
        $TokenHandle
    )

    if ($PSBoundParameters['TokenHandle']) {
        Write-Warning "[Invoke-RevertToSelf] Reverting token impersonation and closing LogonUser() token handle"
        $Result = $Kernel32::CloseHandle($TokenHandle)
    }

    $Result = $Advapi32::RevertToSelf();$LastError = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error();

    if (-not $Result) {
        throw "[Invoke-RevertToSelf] RevertToSelf() Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
    }

    Write-Verbose "[Invoke-RevertToSelf] Token impersonation successfully reverted"
}

# --- Invoke-UserImpersonation ---
function Invoke-UserImpersonation {
<#
.SYNOPSIS

Creates a new "runas /netonly" type logon and impersonates the token.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: PSReflect  

.DESCRIPTION

This function uses LogonUser() with the LOGON32_LOGON_NEW_CREDENTIALS LogonType
to simulate "runas /netonly". The resulting token is then impersonated with
ImpersonateLoggedOnUser() and the token handle is returned for later usage
with Invoke-RevertToSelf.

.PARAMETER Credential

A [Management.Automation.PSCredential] object with alternate credentials
to impersonate in the current thread space.

.PARAMETER TokenHandle

An IntPtr TokenHandle returned by a previous Invoke-UserImpersonation.
If this is supplied, LogonUser() is skipped and only ImpersonateLoggedOnUser()
is executed.

.PARAMETER Quiet

Suppress any warnings about STA vs MTA.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Invoke-UserImpersonation -Credential $Cred

.OUTPUTS

IntPtr

The TokenHandle result from LogonUser.
#>

    [OutputType([IntPtr])]
    [CmdletBinding(DefaultParameterSetName = 'Credential')]
    Param(
        [Parameter(Mandatory = $True, ParameterSetName = 'Credential')]
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential,

        [Parameter(Mandatory = $True, ParameterSetName = 'TokenHandle')]
        [ValidateNotNull()]
        [IntPtr]
        $TokenHandle,

        [Switch]
        $Quiet
    )

    if (([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') -and (-not $PSBoundParameters['Quiet'])) {
        Write-Warning "[Invoke-UserImpersonation] powershell.exe is not currently in a single-threaded apartment state, token impersonation may not work."
    }

    if ($PSBoundParameters['TokenHandle']) {
        $LogonTokenHandle = $TokenHandle
    }
    else {
        $LogonTokenHandle = [IntPtr]::Zero
        $NetworkCredential = $Credential.GetNetworkCredential()
        $UserDomain = $NetworkCredential.Domain
        $UserName = $NetworkCredential.UserName
        Write-Warning "[Invoke-UserImpersonation] Executing LogonUser() with user: $($UserDomain)\$($UserName)"

        # LOGON32_LOGON_NEW_CREDENTIALS = 9, LOGON32_PROVIDER_WINNT50 = 3
        #   this is to simulate "runas.exe /netonly" functionality
        $Result = $Advapi32::LogonUser($UserName, $UserDomain, $NetworkCredential.Password, 9, 3, [ref]$LogonTokenHandle);$LastError = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error();

        if (-not $Result) {
            throw "[Invoke-UserImpersonation] LogonUser() Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
        }
    }

    # actually impersonate the token from LogonUser()
    $Result = $Advapi32::ImpersonateLoggedOnUser($LogonTokenHandle)

    if (-not $Result) {
        throw "[Invoke-UserImpersonation] ImpersonateLoggedOnUser() Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
    }

    Write-Verbose "[Invoke-UserImpersonation] Alternate credentials successfully impersonated"
    $LogonTokenHandle
}

# --- Resolve-IPAddress ---
function Resolve-IPAddress {
<#
.SYNOPSIS

Resolves a given hostename to its associated IPv4 address.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: None  

.DESCRIPTION

Resolves a given hostename to its associated IPv4 address using
[Net.Dns]::GetHostEntry(). If no hostname is provided, the default
is the IP address of the localhost.

.EXAMPLE

Resolve-IPAddress -ComputerName SERVER

.EXAMPLE

@("SERVER1", "SERVER2") | Resolve-IPAddress

.INPUTS

String

Accepts one or more IP address strings on the pipeline.

.OUTPUTS

System.Management.Automation.PSCustomObject

A custom PSObject with the ComputerName and IPAddress.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('System.Management.Automation.PSCustomObject')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $ComputerName = $Env:COMPUTERNAME
    )

    PROCESS {
        ForEach ($Computer in $ComputerName) {
            try {
                @(([Net.Dns]::GetHostEntry($Computer)).AddressList) | ForEach-Object {
                    if ($_.AddressFamily -eq 'InterNetwork') {
                        $Out = New-Object PSObject
                        $Out | Add-Member Noteproperty 'ComputerName' $Computer
                        $Out | Add-Member Noteproperty 'IPAddress' $_.IPAddressToString
                        $Out
                    }
                }
            }
            catch {
                Write-Verbose "[Resolve-IPAddress] Could not resolve $Computer to an IP Address."
            }
        }
    }
}


# --- Win32 Type Definitions ---
$Mod = New-InMemoryModule -ModuleName Win32

# [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPositionalParameters', Scope='Function', Target='psenum')]

# used to parse the 'samAccountType' property for users/computers/groups
$SamAccountTypeEnum = psenum $Mod PowerView.SamAccountTypeEnum UInt32 @{
    DOMAIN_OBJECT                   =   '0x00000000'
    GROUP_OBJECT                    =   '0x10000000'
    NON_SECURITY_GROUP_OBJECT       =   '0x10000001'
    ALIAS_OBJECT                    =   '0x20000000'
    NON_SECURITY_ALIAS_OBJECT       =   '0x20000001'
    USER_OBJECT                     =   '0x30000000'
    MACHINE_ACCOUNT                 =   '0x30000001'
    TRUST_ACCOUNT                   =   '0x30000002'
    APP_BASIC_GROUP                 =   '0x40000000'
    APP_QUERY_GROUP                 =   '0x40000001'
    ACCOUNT_TYPE_MAX                =   '0x7fffffff'
}

# used to parse the 'grouptype' property for groups
$GroupTypeEnum = psenum $Mod PowerView.GroupTypeEnum UInt32 @{
    CREATED_BY_SYSTEM               =   '0x00000001'
    GLOBAL_SCOPE                    =   '0x00000002'
    DOMAIN_LOCAL_SCOPE              =   '0x00000004'
    UNIVERSAL_SCOPE                 =   '0x00000008'
    APP_BASIC                       =   '0x00000010'
    APP_QUERY                       =   '0x00000020'
    SECURITY                        =   '0x80000000'
} -Bitfield

# used to parse the 'userAccountControl' property for users/groups
$UACEnum = psenum $Mod PowerView.UACEnum UInt32 @{
    SCRIPT                          =   1
    ACCOUNTDISABLE                  =   2
    HOMEDIR_REQUIRED                =   8
    LOCKOUT                         =   16
    PASSWD_NOTREQD                  =   32
    PASSWD_CANT_CHANGE              =   64
    ENCRYPTED_TEXT_PWD_ALLOWED      =   128
    TEMP_DUPLICATE_ACCOUNT          =   256
    NORMAL_ACCOUNT                  =   512
    INTERDOMAIN_TRUST_ACCOUNT       =   2048
    WORKSTATION_TRUST_ACCOUNT       =   4096
    SERVER_TRUST_ACCOUNT            =   8192
    DONT_EXPIRE_PASSWORD            =   65536
    MNS_LOGON_ACCOUNT               =   131072
    SMARTCARD_REQUIRED              =   262144
    TRUSTED_FOR_DELEGATION          =   524288
    NOT_DELEGATED                   =   1048576
    USE_DES_KEY_ONLY                =   2097152
    DONT_REQ_PREAUTH                =   4194304
    PASSWORD_EXPIRED                =   8388608
    TRUSTED_TO_AUTH_FOR_DELEGATION  =   16777216
    PARTIAL_SECRETS_ACCOUNT         =   67108864
} -Bitfield

# enum used by $WTS_SESSION_INFO_1 below
$WTSConnectState = psenum $Mod WTS_CONNECTSTATE_CLASS UInt16 @{
    Active       =    0
    Connected    =    1
    ConnectQuery =    2
    Shadow       =    3
    Disconnected =    4
    Idle         =    5
    Listen       =    6
    Reset        =    7
    Down         =    8
    Init         =    9
}

# the WTSEnumerateSessionsEx result structure
$WTS_SESSION_INFO_1 = struct $Mod PowerView.RDPSessionInfo @{
    ExecEnvId = field 0 UInt32
    State = field 1 $WTSConnectState
    SessionId = field 2 UInt32
    pSessionName = field 3 String -MarshalAs @('LPWStr')
    pHostName = field 4 String -MarshalAs @('LPWStr')
    pUserName = field 5 String -MarshalAs @('LPWStr')
    pDomainName = field 6 String -MarshalAs @('LPWStr')
    pFarmName = field 7 String -MarshalAs @('LPWStr')
}

# the particular WTSQuerySessionInformation result structure
$WTS_CLIENT_ADDRESS = struct $mod WTS_CLIENT_ADDRESS @{
    AddressFamily = field 0 UInt32
    Address = field 1 Byte[] -MarshalAs @('ByValArray', 20)
}

# the NetShareEnum result structure
$SHARE_INFO_1 = struct $Mod PowerView.ShareInfo @{
    Name = field 0 String -MarshalAs @('LPWStr')
    Type = field 1 UInt32
    Remark = field 2 String -MarshalAs @('LPWStr')
}

# the NetWkstaUserEnum result structure
$WKSTA_USER_INFO_1 = struct $Mod PowerView.LoggedOnUserInfo @{
    UserName = field 0 String -MarshalAs @('LPWStr')
    LogonDomain = field 1 String -MarshalAs @('LPWStr')
    AuthDomains = field 2 String -MarshalAs @('LPWStr')
    LogonServer = field 3 String -MarshalAs @('LPWStr')
}

# the NetSessionEnum result structure
$SESSION_INFO_10 = struct $Mod PowerView.SessionInfo @{
    CName = field 0 String -MarshalAs @('LPWStr')
    UserName = field 1 String -MarshalAs @('LPWStr')
    Time = field 2 UInt32
    IdleTime = field 3 UInt32
}

# enum used by $LOCALGROUP_MEMBERS_INFO_2 below
$SID_NAME_USE = psenum $Mod SID_NAME_USE UInt16 @{
    SidTypeUser             = 1
    SidTypeGroup            = 2
    SidTypeDomain           = 3
    SidTypeAlias            = 4
    SidTypeWellKnownGroup   = 5
    SidTypeDeletedAccount   = 6
    SidTypeInvalid          = 7
    SidTypeUnknown          = 8
    SidTypeComputer         = 9
}

# the NetLocalGroupEnum result structure
$LOCALGROUP_INFO_1 = struct $Mod LOCALGROUP_INFO_1 @{
    lgrpi1_name = field 0 String -MarshalAs @('LPWStr')
    lgrpi1_comment = field 1 String -MarshalAs @('LPWStr')
}

# the NetLocalGroupGetMembers result structure
$LOCALGROUP_MEMBERS_INFO_2 = struct $Mod LOCALGROUP_MEMBERS_INFO_2 @{
    lgrmi2_sid = field 0 IntPtr
    lgrmi2_sidusage = field 1 $SID_NAME_USE
    lgrmi2_domainandname = field 2 String -MarshalAs @('LPWStr')
}

# enums used in DS_DOMAIN_TRUSTS
$DsDomainFlag = psenum $Mod DsDomain.Flags UInt32 @{
    IN_FOREST       = 1
    DIRECT_OUTBOUND = 2
    TREE_ROOT       = 4
    PRIMARY         = 8
    NATIVE_MODE     = 16
    DIRECT_INBOUND  = 32
} -Bitfield
$DsDomainTrustType = psenum $Mod DsDomain.TrustType UInt32 @{
    DOWNLEVEL   = 1
    UPLEVEL     = 2
    MIT         = 3
    DCE         = 4
}
$DsDomainTrustAttributes = psenum $Mod DsDomain.TrustAttributes UInt32 @{
    NON_TRANSITIVE      = 1
    UPLEVEL_ONLY        = 2
    FILTER_SIDS         = 4
    FOREST_TRANSITIVE   = 8
    CROSS_ORGANIZATION  = 16
    WITHIN_FOREST       = 32
    TREAT_AS_EXTERNAL   = 64
}

# the DsEnumerateDomainTrusts result structure
$DS_DOMAIN_TRUSTS = struct $Mod DS_DOMAIN_TRUSTS @{
    NetbiosDomainName = field 0 String -MarshalAs @('LPWStr')
    DnsDomainName = field 1 String -MarshalAs @('LPWStr')
    Flags = field 2 $DsDomainFlag
    ParentIndex = field 3 UInt32
    TrustType = field 4 $DsDomainTrustType
    TrustAttributes = field 5 $DsDomainTrustAttributes
    DomainSid = field 6 IntPtr
    DomainGuid = field 7 Guid
}

# used by WNetAddConnection2W
$NETRESOURCEW = struct $Mod NETRESOURCEW @{
    dwScope =         field 0 UInt32
    dwType =          field 1 UInt32
    dwDisplayType =   field 2 UInt32
    dwUsage =         field 3 UInt32
    lpLocalName =     field 4 String -MarshalAs @('LPWStr')
    lpRemoteName =    field 5 String -MarshalAs @('LPWStr')
    lpComment =       field 6 String -MarshalAs @('LPWStr')
    lpProvider =      field 7 String -MarshalAs @('LPWStr')
}

# all of the Win32 API functions we need
$FunctionDefinitions = @(
    (func netapi32 NetShareEnum ([Int]) @([String], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (func netapi32 NetWkstaUserEnum ([Int]) @([String], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (func netapi32 NetSessionEnum ([Int]) @([String], [String], [String], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (func netapi32 NetLocalGroupEnum ([Int]) @([String], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (func netapi32 NetLocalGroupGetMembers ([Int]) @([String], [String], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (func netapi32 DsGetSiteName ([Int]) @([String], [IntPtr].MakeByRefType())),
    (func netapi32 DsEnumerateDomainTrusts ([Int]) @([String], [UInt32], [IntPtr].MakeByRefType(), [IntPtr].MakeByRefType())),
    (func netapi32 NetApiBufferFree ([Int]) @([IntPtr])),
    (func advapi32 ConvertSidToStringSid ([Int]) @([IntPtr], [String].MakeByRefType()) -SetLastError),
    (func advapi32 OpenSCManagerW ([IntPtr]) @([String], [String], [Int]) -SetLastError),
    (func advapi32 CloseServiceHandle ([Int]) @([IntPtr])),
    (func advapi32 LogonUser ([Bool]) @([String], [String], [String], [UInt32], [UInt32], [IntPtr].MakeByRefType()) -SetLastError),
    (func advapi32 ImpersonateLoggedOnUser ([Bool]) @([IntPtr]) -SetLastError),
    (func advapi32 RevertToSelf ([Bool]) @() -SetLastError),
    (func wtsapi32 WTSOpenServerEx ([IntPtr]) @([String])),
    (func wtsapi32 WTSEnumerateSessionsEx ([Int]) @([IntPtr], [Int32].MakeByRefType(), [Int], [IntPtr].MakeByRefType(), [Int32].MakeByRefType()) -SetLastError),
    (func wtsapi32 WTSQuerySessionInformation ([Int]) @([IntPtr], [Int], [Int], [IntPtr].MakeByRefType(), [Int32].MakeByRefType()) -SetLastError),
    (func wtsapi32 WTSFreeMemoryEx ([Int]) @([Int32], [IntPtr], [Int32])),
    (func wtsapi32 WTSFreeMemory ([Int]) @([IntPtr])),
    (func wtsapi32 WTSCloseServer ([Int]) @([IntPtr])),
    (func Mpr WNetAddConnection2W ([Int]) @($NETRESOURCEW, [String], [String], [UInt32])),
    (func Mpr WNetCancelConnection2 ([Int]) @([String], [Int], [Bool])),
    (func kernel32 CloseHandle ([Bool]) @([IntPtr]) -SetLastError)
)

$Types = $FunctionDefinitions | Add-Win32Type -Module $Mod -Namespace 'Win32'
$Netapi32 = $Types['netapi32']
$Advapi32 = $Types['advapi32']
$Wtsapi32 = $Types['wtsapi32']
$Mpr = $Types['Mpr']
$Kernel32 = $Types['kernel32']

# --- Get-AdaptDomain (dependency) ---
function Get-AdaptDomain {
<#
.SYNOPSIS

Returns the domain object for the current (or specified) domain.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: None  

.DESCRIPTION

Returns a System.DirectoryServices.ActiveDirectory.Domain object for the current
domain or the domain specified with -Domain X.

.PARAMETER Domain

Specifies the domain name to query for, defaults to the current domain.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.EXAMPLE

Get-AdaptDomain -Domain testlab.local

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-AdaptDomain -Credential $Cred

.OUTPUTS

System.DirectoryServices.ActiveDirectory.Domain

A complex .NET domain object.

.LINK

http://social.technet.microsoft.com/Forums/scriptcenter/en-US/0c5b3f83-e528-4d49-92a4-dee31f4b481c/finding-the-dn-of-the-the-domain-without-admodule-in-powershell?forum=ITCG
#>

    [OutputType([System.DirectoryServices.ActiveDirectory.Domain])]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        if ($PSBoundParameters['Credential']) {

            Write-Verbose '[Get-AdaptDomain] Using alternate credentials for Get-AdaptDomain'

            if ($PSBoundParameters['Domain']) {
                $TargetDomain = $Domain
            }
            else {
                # if no domain is supplied, extract the logon domain from the PSCredential passed
                $TargetDomain = $Credential.GetNetworkCredential().Domain
                Write-Verbose "[Get-AdaptDomain] Extracted domain '$TargetDomain' from -Credential"
            }

            $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $TargetDomain, $Credential.UserName, $Credential.GetNetworkCredential().Password)

            try {
                [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
            }
            catch {
                Write-Verbose "[Get-AdaptDomain] The specified domain '$TargetDomain' does not exist, could not be contacted, there isn't an existing trust, or the specified credentials are invalid: $_"
            }
        }
        elseif ($PSBoundParameters['Domain']) {
            $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $Domain)
            try {
                [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
            }
            catch {
                Write-Verbose "[Get-AdaptDomain] The specified domain '$Domain' does not exist, could not be contacted, or there isn't an existing trust : $_"
            }
        }
        else {
            try {
                [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            }
            catch {
                Write-Verbose "[Get-AdaptDomain] Error retrieving the current domain: $_"
            }
        }
    }
}

# --- Get-AdaptDomainComputer (dependency) ---
function Get-AdaptDomainComputer {
<#
.SYNOPSIS

Return all computers or specific computer objects in AD.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainSearcher, Convert-LDAPProperty  

.DESCRIPTION

Builds a directory searcher object using Get-DomainSearcher, builds a custom
LDAP filter based on targeting/filter parameters, and searches for all objects
matching the criteria. To only return specific properties, use
"-Properties samaccountname,usnchanged,...". By default, all computer objects for
the current domain are returned.

.PARAMETER Identity

A SamAccountName (e.g. WINDOWS10$), DistinguishedName (e.g. CN=WINDOWS10,CN=Computers,DC=testlab,DC=local),
SID (e.g. S-1-5-21-890171859-3433809279-3366196753-1124), GUID (e.g. 4f16b6bc-7010-4cbf-b628-f3cfe20f6994),
or a dns host name (e.g. windows10.testlab.local). Wildcards accepted.

.PARAMETER UACFilter

Dynamic parameter that accepts one or more values from $UACEnum, including
"NOT_X" negation forms. To see all possible values, run '0|ConvertFrom-UACValue -ShowAll'.

.PARAMETER Unconstrained

Switch. Return computer objects that have unconstrained delegation.

.PARAMETER TrustedToAuth

Switch. Return computer objects that are trusted to authenticate for other principals.

.PARAMETER Printers

Switch. Return only printers.

.PARAMETER SPN

Return computers with a specific service principal name, wildcards accepted.

.PARAMETER OperatingSystem

Return computers with a specific operating system, wildcards accepted.

.PARAMETER ServicePack

Return computers with a specific service pack, wildcards accepted.

.PARAMETER SiteName

Return computers in the specific AD Site name, wildcards accepted.

.PARAMETER Ping

Switch. Ping each host to ensure it's up before enumerating.

.PARAMETER Domain

Specifies the domain to use for the query, defaults to the current domain.

.PARAMETER LDAPFilter

Specifies an LDAP query string that is used to filter Active Directory objects.

.PARAMETER Properties

Specifies the properties of the output object to retrieve from the server.

.PARAMETER SearchBase

The LDAP source to search through, e.g. "LDAP://OU=secret,DC=testlab,DC=local"
Useful for OU queries.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER SecurityMasks

Specifies an option for examining security information of a directory object.
One of 'Dacl', 'Group', 'None', 'Owner', 'Sacl'.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER FindOne

Only return one result object.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.PARAMETER Raw

Switch. Return raw results instead of translating the fields into a custom PSObject.

.EXAMPLE

Get-AdaptDomainComputer

Returns the current computers in current domain.

.EXAMPLE

Get-AdaptDomainComputer -SPN mssql* -Domain testlab.local

Returns all MS SQL servers in the testlab.local domain.

.EXAMPLE

Get-AdaptDomainComputer -UACFilter TRUSTED_FOR_DELEGATION,SERVER_TRUST_ACCOUNT -Properties dnshostname

Return the dns hostnames of servers trusted for delegation.

.EXAMPLE

Get-AdaptDomainComputer -SearchBase "LDAP://OU=secret,DC=testlab,DC=local" -Unconstrained

Search the specified OU for computeres that allow unconstrained delegation.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-AdaptDomainComputer -Credential $Cred

.OUTPUTS

PowerView.Computer

Custom PSObject with translated computer property fields.

PowerView.Computer.Raw

The raw DirectoryServices.SearchResult object, if -Raw is enabled.
#>

    [OutputType('PowerView.Computer')]
    [OutputType('PowerView.Computer.Raw')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('SamAccountName', 'Name', 'DNSHostName')]
        [String[]]
        $Identity,

        [Switch]
        $Unconstrained,

        [Switch]
        $TrustedToAuth,

        [Switch]
        $Printers,

        [ValidateNotNullOrEmpty()]
        [Alias('ServicePrincipalName')]
        [String]
        $SPN,

        [ValidateNotNullOrEmpty()]
        [String]
        $OperatingSystem,

        [ValidateNotNullOrEmpty()]
        [String]
        $ServicePack,

        [ValidateNotNullOrEmpty()]
        [String]
        $SiteName,

        [Switch]
        $Ping,

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
        $UACValueNames = [Enum]::GetNames($UACEnum)
        # add in the negations
        $UACValueNames = $UACValueNames | ForEach-Object {$_; "NOT_$_"}
        # create new dynamic parameter
        New-DynamicParameter -Name UACFilter -ValidateSet $UACValueNames -Type ([array])
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
        $CompSearcher = Get-DomainSearcher @SearcherArguments
    }

    PROCESS {
        #bind dynamic parameter to a friendly variable
        if ($PSBoundParameters -and ($PSBoundParameters.Count -ne 0)) {
            New-DynamicParameter -CreateVariables -BoundParameters $PSBoundParameters
        }

        if ($CompSearcher) {
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
                        # if a -Domain isn't explicitly set, extract the object domain out of the distinguishedname
                        #   and rebuild the domain searcher
                        $IdentityDomain = $IdentityInstance.SubString($IdentityInstance.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        Write-Verbose "[Get-AdaptDomainComputer] Extracted domain '$IdentityDomain' from '$IdentityInstance'"
                        $SearcherArguments['Domain'] = $IdentityDomain
                        $CompSearcher = Get-DomainSearcher @SearcherArguments
                        if (-not $CompSearcher) {
                            Write-Warning "[Get-AdaptDomainComputer] Unable to retrieve domain searcher for '$IdentityDomain'"
                        }
                    }
                }
                elseif ($IdentityInstance.Contains('.')) {
                    $IdentityFilter += "(|(name=$IdentityInstance)(dnshostname=$IdentityInstance))"
                }
                elseif ($IdentityInstance -imatch '^[0-9A-F]{8}-([0-9A-F]{4}-){3}[0-9A-F]{12}$') {
                    $GuidByteString = (([Guid]$IdentityInstance).ToByteArray() | ForEach-Object { '\' + $_.ToString('X2') }) -join ''
                    $IdentityFilter += "(objectguid=$GuidByteString)"
                }
                else {
                    $IdentityFilter += "(name=$IdentityInstance)"
                }
            }
            if ($IdentityFilter -and ($IdentityFilter.Trim() -ne '') ) {
                $Filter += "(|$IdentityFilter)"
            }

            if ($PSBoundParameters['Unconstrained']) {
                Write-Verbose '[Get-AdaptDomainComputer] Searching for computers with for unconstrained delegation'
                $Filter += '(userAccountControl:1.2.840.113556.1.4.803:=524288)'
            }
            if ($PSBoundParameters['TrustedToAuth']) {
                Write-Verbose '[Get-AdaptDomainComputer] Searching for computers that are trusted to authenticate for other principals'
                $Filter += '(msds-allowedtodelegateto=*)'
            }
            if ($PSBoundParameters['Printers']) {
                Write-Verbose '[Get-AdaptDomainComputer] Searching for printers'
                $Filter += '(objectCategory=printQueue)'
            }
            if ($PSBoundParameters['SPN']) {
                Write-Verbose "[Get-AdaptDomainComputer] Searching for computers with SPN: $SPN"
                $Filter += "(servicePrincipalName=$SPN)"
            }
            if ($PSBoundParameters['OperatingSystem']) {
                Write-Verbose "[Get-AdaptDomainComputer] Searching for computers with operating system: $OperatingSystem"
                $Filter += "(operatingsystem=$OperatingSystem)"
            }
            if ($PSBoundParameters['ServicePack']) {
                Write-Verbose "[Get-AdaptDomainComputer] Searching for computers with service pack: $ServicePack"
                $Filter += "(operatingsystemservicepack=$ServicePack)"
            }
            if ($PSBoundParameters['SiteName']) {
                Write-Verbose "[Get-AdaptDomainComputer] Searching for computers with site name: $SiteName"
                $Filter += "(serverreferencebl=$SiteName)"
            }
            if ($PSBoundParameters['LDAPFilter']) {
                Write-Verbose "[Get-AdaptDomainComputer] Using additional LDAP filter: $LDAPFilter"
                $Filter += "$LDAPFilter"
            }
            # build the LDAP filter for the dynamic UAC filter value
            $UACFilter | Where-Object {$_} | ForEach-Object {
                if ($_ -match 'NOT_.*') {
                    $UACField = $_.Substring(4)
                    $UACValue = [Int]($UACEnum::$UACField)
                    $Filter += "(!(userAccountControl:1.2.840.113556.1.4.803:=$UACValue))"
                }
                else {
                    $UACValue = [Int]($UACEnum::$_)
                    $Filter += "(userAccountControl:1.2.840.113556.1.4.803:=$UACValue)"
                }
            }

            $CompSearcher.filter = "(&(samAccountType=805306369)$Filter)"
            Write-Verbose "[Get-AdaptDomainComputer] Get-AdaptDomainComputer filter string: $($CompSearcher.filter)"

            if ($PSBoundParameters['FindOne']) { $Results = $CompSearcher.FindOne() }
            else { $Results = $CompSearcher.FindAll() }
            $Results | Where-Object {$_} | ForEach-Object {
                $Up = $True
                if ($PSBoundParameters['Ping']) {
                    $Up = Test-Connection -Count 1 -Quiet -ComputerName $_.properties.dnshostname
                }
                if ($Up) {
                    if ($PSBoundParameters['Raw']) {
                        # return raw result objects
                        $Computer = $_
                        $Computer.PSObject.TypeNames.Insert(0, 'PowerView.Computer.Raw')
                    }
                    else {
                        $Computer = Convert-LDAPProperty -Properties $_.Properties
                        $Computer.PSObject.TypeNames.Insert(0, 'PowerView.Computer')
                    }
                    $Computer
                }
            }
            if ($Results) {
                try { $Results.dispose() }
                catch {
                    Write-Verbose "[Get-AdaptDomainComputer] Error disposing of the Results object: $_"
                }
            }
            $CompSearcher.dispose()
        }
    }
}

# --- Get-AdaptDomainController (dependency) ---
function Get-AdaptDomainController {
<#
.SYNOPSIS

Return the domain controllers for the current (or specified) domain.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-AdaptDomainComputer, Get-AdaptDomain  

.DESCRIPTION

Enumerates the domain controllers for the current or specified domain.
By default built in .NET methods are used. The -LDAP switch uses Get-AdaptDomainComputer
to search for domain controllers.

.PARAMETER Domain

The domain to query for domain controllers, defaults to the current domain.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER LDAP

Switch. Use LDAP queries to determine the domain controllers instead of built in .NET methods.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.EXAMPLE

Get-AdaptDomainController -Domain 'test.local'

Determine the domain controllers for 'test.local'.

.EXAMPLE

Get-AdaptDomainController -Domain 'test.local' -LDAP

Determine the domain controllers for 'test.local' using LDAP queries.

.EXAMPLE

'test.local' | Get-AdaptDomainController

Determine the domain controllers for 'test.local'.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-AdaptDomainController -Credential $Cred

.OUTPUTS

PowerView.Computer

Outputs custom PSObjects with details about the enumerated domain controller if -LDAP is specified.

System.DirectoryServices.ActiveDirectory.DomainController

If -LDAP isn't specified.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.Computer')]
    [OutputType('System.DirectoryServices.ActiveDirectory.DomainController')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True)]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [Switch]
        $LDAP,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        $Arguments = @{}
        if ($PSBoundParameters['Domain']) { $Arguments['Domain'] = $Domain }
        if ($PSBoundParameters['Credential']) { $Arguments['Credential'] = $Credential }

        if ($PSBoundParameters['LDAP'] -or $PSBoundParameters['Server']) {
            if ($PSBoundParameters['Server']) { $Arguments['Server'] = $Server }

            # UAC specification for domain controllers
            $Arguments['LDAPFilter'] = '(userAccountControl:1.2.840.113556.1.4.803:=8192)'

            Get-AdaptDomainComputer @Arguments
        }
        else {
            $FoundDomain = Get-AdaptDomain @Arguments
            if ($FoundDomain) {
                $FoundDomain.DomainControllers
            }
        }
    }
}

# --- Get-AdaptDomainDFSShare (dependency) ---
function Get-AdaptDomainDFSShare {
<#
.SYNOPSIS

Returns a list of all fault-tolerant distributed file systems
for the current (or specified) domains.

Author: Ben Campbell (@meatballs__)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainSearcher  

.DESCRIPTION

This function searches for all distributed file systems (either version
1, 2, or both depending on -Version X) by searching for domain objects
matching (objectClass=fTDfs) or (objectClass=msDFS-Linkv2), respectively
The server data is parsed appropriately and returned.

.PARAMETER Domain

Specifies the domains to use for the query, defaults to the current domain.

.PARAMETER SearchBase

The LDAP source to search through, e.g. "LDAP://OU=secret,DC=testlab,DC=local"
Useful for OU queries.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.EXAMPLE

Get-AdaptDomainDFSShare

Returns all distributed file system shares for the current domain.

.EXAMPLE

Get-AdaptDomainDFSShare -Domain testlab.local

Returns all distributed file system shares for the 'testlab.local' domain.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-AdaptDomainDFSShare -Credential $Cred

.OUTPUTS

System.Management.Automation.PSCustomObject

A custom PSObject describing the distributed file systems.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
    [OutputType('System.Management.Automation.PSCustomObject')]
    [CmdletBinding()]
    Param(
        [Parameter( ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullOrEmpty()]
        [Alias('DomainName', 'Name')]
        [String[]]
        $Domain,

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
        $Credential = [Management.Automation.PSCredential]::Empty,

        [ValidateSet('All', 'V1', '1', 'V2', '2')]
        [String]
        $Version = 'All'
    )

    BEGIN {
        $SearcherArguments = @{}
        if ($PSBoundParameters['SearchBase']) { $SearcherArguments['SearchBase'] = $SearchBase }
        if ($PSBoundParameters['Server']) { $SearcherArguments['Server'] = $Server }
        if ($PSBoundParameters['SearchScope']) { $SearcherArguments['SearchScope'] = $SearchScope }
        if ($PSBoundParameters['ResultPageSize']) { $SearcherArguments['ResultPageSize'] = $ResultPageSize }
        if ($PSBoundParameters['ServerTimeLimit']) { $SearcherArguments['ServerTimeLimit'] = $ServerTimeLimit }
        if ($PSBoundParameters['Tombstone']) { $SearcherArguments['Tombstone'] = $Tombstone }
        if ($PSBoundParameters['Credential']) { $SearcherArguments['Credential'] = $Credential }

        function Parse-Pkt {
            [CmdletBinding()]
            Param(
                [Byte[]]
                $Pkt
            )

            $bin = $Pkt
            $blob_version = [bitconverter]::ToUInt32($bin[0..3],0)
            $blob_element_count = [bitconverter]::ToUInt32($bin[4..7],0)
            $offset = 8
            #https://msdn.microsoft.com/en-us/library/cc227147.aspx
            $object_list = @()
            for($i=1; $i -le $blob_element_count; $i++){
                $blob_name_size_start = $offset
                $blob_name_size_end = $offset + 1
                $blob_name_size = [bitconverter]::ToUInt16($bin[$blob_name_size_start..$blob_name_size_end],0)

                $blob_name_start = $blob_name_size_end + 1
                $blob_name_end = $blob_name_start + $blob_name_size - 1
                $blob_name = [System.Text.Encoding]::Unicode.GetString($bin[$blob_name_start..$blob_name_end])

                $blob_data_size_start = $blob_name_end + 1
                $blob_data_size_end = $blob_data_size_start + 3
                $blob_data_size = [bitconverter]::ToUInt32($bin[$blob_data_size_start..$blob_data_size_end],0)

                $blob_data_start = $blob_data_size_end + 1
                $blob_data_end = $blob_data_start + $blob_data_size - 1
                $blob_data = $bin[$blob_data_start..$blob_data_end]
                switch -wildcard ($blob_name) {
                    "\siteroot" {  }
                    "\domainroot*" {
                        # Parse DFSNamespaceRootOrLinkBlob object. Starts with variable length DFSRootOrLinkIDBlob which we parse first...
                        # DFSRootOrLinkIDBlob
                        $root_or_link_guid_start = 0
                        $root_or_link_guid_end = 15
                        $root_or_link_guid = [byte[]]$blob_data[$root_or_link_guid_start..$root_or_link_guid_end]
                        $guid = New-Object Guid(,$root_or_link_guid) # should match $guid_str
                        $prefix_size_start = $root_or_link_guid_end + 1
                        $prefix_size_end = $prefix_size_start + 1
                        $prefix_size = [bitconverter]::ToUInt16($blob_data[$prefix_size_start..$prefix_size_end],0)
                        $prefix_start = $prefix_size_end + 1
                        $prefix_end = $prefix_start + $prefix_size - 1
                        $prefix = [System.Text.Encoding]::Unicode.GetString($blob_data[$prefix_start..$prefix_end])

                        $short_prefix_size_start = $prefix_end + 1
                        $short_prefix_size_end = $short_prefix_size_start + 1
                        $short_prefix_size = [bitconverter]::ToUInt16($blob_data[$short_prefix_size_start..$short_prefix_size_end],0)
                        $short_prefix_start = $short_prefix_size_end + 1
                        $short_prefix_end = $short_prefix_start + $short_prefix_size - 1
                        $short_prefix = [System.Text.Encoding]::Unicode.GetString($blob_data[$short_prefix_start..$short_prefix_end])

                        $type_start = $short_prefix_end + 1
                        $type_end = $type_start + 3
                        $type = [bitconverter]::ToUInt32($blob_data[$type_start..$type_end],0)

                        $state_start = $type_end + 1
                        $state_end = $state_start + 3
                        $state = [bitconverter]::ToUInt32($blob_data[$state_start..$state_end],0)

                        $comment_size_start = $state_end + 1
                        $comment_size_end = $comment_size_start + 1
                        $comment_size = [bitconverter]::ToUInt16($blob_data[$comment_size_start..$comment_size_end],0)
                        $comment_start = $comment_size_end + 1
                        $comment_end = $comment_start + $comment_size - 1
                        if ($comment_size -gt 0)  {
                            $comment = [System.Text.Encoding]::Unicode.GetString($blob_data[$comment_start..$comment_end])
                        }
                        $prefix_timestamp_start = $comment_end + 1
                        $prefix_timestamp_end = $prefix_timestamp_start + 7
                        # https://msdn.microsoft.com/en-us/library/cc230324.aspx FILETIME
                        $prefix_timestamp = $blob_data[$prefix_timestamp_start..$prefix_timestamp_end] #dword lowDateTime #dword highdatetime
                        $state_timestamp_start = $prefix_timestamp_end + 1
                        $state_timestamp_end = $state_timestamp_start + 7
                        $state_timestamp = $blob_data[$state_timestamp_start..$state_timestamp_end]
                        $comment_timestamp_start = $state_timestamp_end + 1
                        $comment_timestamp_end = $comment_timestamp_start + 7
                        $comment_timestamp = $blob_data[$comment_timestamp_start..$comment_timestamp_end]
                        $version_start = $comment_timestamp_end  + 1
                        $version_end = $version_start + 3
                        $version = [bitconverter]::ToUInt32($blob_data[$version_start..$version_end],0)

                        # Parse rest of DFSNamespaceRootOrLinkBlob here
                        $dfs_targetlist_blob_size_start = $version_end + 1
                        $dfs_targetlist_blob_size_end = $dfs_targetlist_blob_size_start + 3
                        $dfs_targetlist_blob_size = [bitconverter]::ToUInt32($blob_data[$dfs_targetlist_blob_size_start..$dfs_targetlist_blob_size_end],0)

                        $dfs_targetlist_blob_start = $dfs_targetlist_blob_size_end + 1
                        $dfs_targetlist_blob_end = $dfs_targetlist_blob_start + $dfs_targetlist_blob_size - 1
                        $dfs_targetlist_blob = $blob_data[$dfs_targetlist_blob_start..$dfs_targetlist_blob_end]
                        $reserved_blob_size_start = $dfs_targetlist_blob_end + 1
                        $reserved_blob_size_end = $reserved_blob_size_start + 3
                        $reserved_blob_size = [bitconverter]::ToUInt32($blob_data[$reserved_blob_size_start..$reserved_blob_size_end],0)

                        $reserved_blob_start = $reserved_blob_size_end + 1
                        $reserved_blob_end = $reserved_blob_start + $reserved_blob_size - 1
                        $reserved_blob = $blob_data[$reserved_blob_start..$reserved_blob_end]
                        $referral_ttl_start = $reserved_blob_end + 1
                        $referral_ttl_end = $referral_ttl_start + 3
                        $referral_ttl = [bitconverter]::ToUInt32($blob_data[$referral_ttl_start..$referral_ttl_end],0)

                        #Parse DFSTargetListBlob
                        $target_count_start = 0
                        $target_count_end = $target_count_start + 3
                        $target_count = [bitconverter]::ToUInt32($dfs_targetlist_blob[$target_count_start..$target_count_end],0)
                        $t_offset = $target_count_end + 1

                        for($j=1; $j -le $target_count; $j++){
                            $target_entry_size_start = $t_offset
                            $target_entry_size_end = $target_entry_size_start + 3
                            $target_entry_size = [bitconverter]::ToUInt32($dfs_targetlist_blob[$target_entry_size_start..$target_entry_size_end],0)
                            $target_time_stamp_start = $target_entry_size_end + 1
                            $target_time_stamp_end = $target_time_stamp_start + 7
                            # FILETIME again or special if priority rank and priority class 0
                            $target_time_stamp = $dfs_targetlist_blob[$target_time_stamp_start..$target_time_stamp_end]
                            $target_state_start = $target_time_stamp_end + 1
                            $target_state_end = $target_state_start + 3
                            $target_state = [bitconverter]::ToUInt32($dfs_targetlist_blob[$target_state_start..$target_state_end],0)

                            $target_type_start = $target_state_end + 1
                            $target_type_end = $target_type_start + 3
                            $target_type = [bitconverter]::ToUInt32($dfs_targetlist_blob[$target_type_start..$target_type_end],0)

                            $server_name_size_start = $target_type_end + 1
                            $server_name_size_end = $server_name_size_start + 1
                            $server_name_size = [bitconverter]::ToUInt16($dfs_targetlist_blob[$server_name_size_start..$server_name_size_end],0)

                            $server_name_start = $server_name_size_end + 1
                            $server_name_end = $server_name_start + $server_name_size - 1
                            $server_name = [System.Text.Encoding]::Unicode.GetString($dfs_targetlist_blob[$server_name_start..$server_name_end])

                            $share_name_size_start = $server_name_end + 1
                            $share_name_size_end = $share_name_size_start + 1
                            $share_name_size = [bitconverter]::ToUInt16($dfs_targetlist_blob[$share_name_size_start..$share_name_size_end],0)
                            $share_name_start = $share_name_size_end + 1
                            $share_name_end = $share_name_start + $share_name_size - 1
                            $share_name = [System.Text.Encoding]::Unicode.GetString($dfs_targetlist_blob[$share_name_start..$share_name_end])

                            $target_list += "\\$server_name\$share_name"
                            $t_offset = $share_name_end + 1
                        }
                    }
                }
                $offset = $blob_data_end + 1
                $dfs_pkt_properties = @{
                    'Name' = $blob_name
                    'Prefix' = $prefix
                    'TargetList' = $target_list
                }
                $object_list += New-Object -TypeName PSObject -Property $dfs_pkt_properties
                $prefix = $Null
                $blob_name = $Null
                $target_list = $Null
            }

            $servers = @()
            $object_list | ForEach-Object {
                if ($_.TargetList) {
                    $_.TargetList | ForEach-Object {
                        $servers += $_.split('\')[2]
                    }
                }
            }

            $servers
        }

        function Get-DomainDFSShareV1 {
            [CmdletBinding()]
            Param(
                [String]
                $Domain,

                [String]
                $SearchBase,

                [String]
                $Server,

                [String]
                $SearchScope = 'Subtree',

                [Int]
                $ResultPageSize = 200,

                [Int]
                $ServerTimeLimit,

                [Switch]
                $Tombstone,

                [Management.Automation.PSCredential]
                [Management.Automation.CredentialAttribute()]
                $Credential = [Management.Automation.PSCredential]::Empty
            )

            $DFSsearcher = Get-DomainSearcher @PSBoundParameters

            if ($DFSsearcher) {
                $DFSshares = @()
                $DFSsearcher.filter = '(&(objectClass=fTDfs))'

                try {
                    $Results = $DFSSearcher.FindAll()
                    $Results | Where-Object {$_} | ForEach-Object {
                        $Properties = $_.Properties
                        $RemoteNames = $Properties.remoteservername
                        $Pkt = $Properties.pkt

                        $DFSshares += $RemoteNames | ForEach-Object {
                            try {
                                if ( $_.Contains('\') ) {
                                    New-Object -TypeName PSObject -Property @{'Name'=$Properties.name[0];'RemoteServerName'=$_.split('\')[2]}
                                }
                            }
                            catch {
                                Write-Verbose "[Get-AdaptDomainDFSShare] Get-DomainDFSShareV1 error in parsing DFS share : $_"
                            }
                        }
                    }
                    if ($Results) {
                        try { $Results.dispose() }
                        catch {
                            Write-Verbose "[Get-AdaptDomainDFSShare] Get-DomainDFSShareV1 error disposing of the Results object: $_"
                        }
                    }
                    $DFSSearcher.dispose()

                    if ($pkt -and $pkt[0]) {
                        Parse-Pkt $pkt[0] | ForEach-Object {
                            # If a folder doesn't have a redirection it will have a target like
                            # \\null\TestNameSpace\folder\.DFSFolderLink so we do actually want to match
                            # on 'null' rather than $Null
                            if ($_ -ne 'null') {
                                New-Object -TypeName PSObject -Property @{'Name'=$Properties.name[0];'RemoteServerName'=$_}
                            }
                        }
                    }
                }
                catch {
                    Write-Warning "[Get-AdaptDomainDFSShare] Get-DomainDFSShareV1 error : $_"
                }
                $DFSshares | Sort-Object -Unique -Property 'RemoteServerName'
            }
        }

        function Get-DomainDFSShareV2 {
            [CmdletBinding()]
            Param(
                [String]
                $Domain,

                [String]
                $SearchBase,

                [String]
                $Server,

                [String]
                $SearchScope = 'Subtree',

                [Int]
                $ResultPageSize = 200,

                [Int]
                $ServerTimeLimit,

                [Switch]
                $Tombstone,

                [Management.Automation.PSCredential]
                [Management.Automation.CredentialAttribute()]
                $Credential = [Management.Automation.PSCredential]::Empty
            )

            $DFSsearcher = Get-DomainSearcher @PSBoundParameters

            if ($DFSsearcher) {
                $DFSshares = @()
                $DFSsearcher.filter = '(&(objectClass=msDFS-Linkv2))'
                $Null = $DFSSearcher.PropertiesToLoad.AddRange(('msdfs-linkpathv2','msDFS-TargetListv2'))

                try {
                    $Results = $DFSSearcher.FindAll()
                    $Results | Where-Object {$_} | ForEach-Object {
                        $Properties = $_.Properties
                        $target_list = $Properties.'msdfs-targetlistv2'[0]
                        $xml = [xml][System.Text.Encoding]::Unicode.GetString($target_list[2..($target_list.Length-1)])
                        $DFSshares += $xml.targets.ChildNodes | ForEach-Object {
                            try {
                                $Target = $_.InnerText
                                if ( $Target.Contains('\') ) {
                                    $DFSroot = $Target.split('\')[3]
                                    $ShareName = $Properties.'msdfs-linkpathv2'[0]
                                    New-Object -TypeName PSObject -Property @{'Name'="$DFSroot$ShareName";'RemoteServerName'=$Target.split('\')[2]}
                                }
                            }
                            catch {
                                Write-Verbose "[Get-AdaptDomainDFSShare] Get-DomainDFSShareV2 error in parsing target : $_"
                            }
                        }
                    }
                    if ($Results) {
                        try { $Results.dispose() }
                        catch {
                            Write-Verbose "[Get-AdaptDomainDFSShare] Error disposing of the Results object: $_"
                        }
                    }
                    $DFSSearcher.dispose()
                }
                catch {
                    Write-Warning "[Get-AdaptDomainDFSShare] Get-DomainDFSShareV2 error : $_"
                }
                $DFSshares | Sort-Object -Unique -Property 'RemoteServerName'
            }
        }
    }

    PROCESS {
        $DFSshares = @()

        if ($PSBoundParameters['Domain']) {
            ForEach ($TargetDomain in $Domain) {
                $SearcherArguments['Domain'] = $TargetDomain
                if ($Version -match 'all|1') {
                    $DFSshares += Get-DomainDFSShareV1 @SearcherArguments
                }
                if ($Version -match 'all|2') {
                    $DFSshares += Get-DomainDFSShareV2 @SearcherArguments
                }
            }
        }
        else {
            if ($Version -match 'all|1') {
                $DFSshares += Get-DomainDFSShareV1 @SearcherArguments
            }
            if ($Version -match 'all|2') {
                $DFSshares += Get-DomainDFSShareV2 @SearcherArguments
            }
        }

        $DFSshares | Sort-Object -Property ('RemoteServerName','Name') -Unique
    }
}

# --- Get-AdaptDomainFileServer (dependency) ---
function Get-AdaptDomainFileServer {
<#
.SYNOPSIS

Returns a list of servers likely functioning as file servers.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainSearcher  

.DESCRIPTION

Returns a list of likely fileservers by searching for all users in Active Directory
with non-null homedirectory, scriptpath, or profilepath fields, and extracting/uniquifying
the server names.

.PARAMETER Domain

Specifies the domain to use for the query, defaults to the current domain.

.PARAMETER LDAPFilter

Specifies an LDAP query string that is used to filter Active Directory objects.

.PARAMETER SearchBase

The LDAP source to search through, e.g. "LDAP://OU=secret,DC=testlab,DC=local"
Useful for OU queries.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.EXAMPLE

Get-AdaptDomainFileServer

Returns active file servers for the current domain.

.EXAMPLE

Get-AdaptDomainFileServer -Domain testing.local

Returns active file servers for the 'testing.local' domain.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-AdaptDomainFileServer -Credential $Cred

.OUTPUTS

String

One or more strings representing file server names.
#>

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
        function Split-Path {
            # short internal helper to split UNC server paths
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
                $UserSearcher = Get-DomainSearcher @SearcherArguments
                # get all results w/o the pipeline and uniquify them (I know it's not pretty)
                $(ForEach($UserResult in $UserSearcher.FindAll()) {if ($UserResult.Properties['homedirectory']) {Split-Path($UserResult.Properties['homedirectory'])}if ($UserResult.Properties['scriptpath']) {Split-Path($UserResult.Properties['scriptpath'])}if ($UserResult.Properties['profilepath']) {Split-Path($UserResult.Properties['profilepath'])}}) | Sort-Object -Unique
            }
        }
        else {
            $UserSearcher = Get-DomainSearcher @SearcherArguments
            $(ForEach($UserResult in $UserSearcher.FindAll()) {if ($UserResult.Properties['homedirectory']) {Split-Path($UserResult.Properties['homedirectory'])}if ($UserResult.Properties['scriptpath']) {Split-Path($UserResult.Properties['scriptpath'])}if ($UserResult.Properties['profilepath']) {Split-Path($UserResult.Properties['profilepath'])}}) | Sort-Object -Unique
        }
    }
}

# --- Get-AdaptDomainGroup (dependency) ---
function Get-AdaptDomainGroup {
<#
.SYNOPSIS

Return all groups or specific group objects in AD.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainSearcher, Get-AdaptDomainObject, Convert-ADName, Convert-LDAPProperty  

.DESCRIPTION

Builds a directory searcher object using Get-DomainSearcher, builds a custom
LDAP filter based on targeting/filter parameters, and searches for all objects
matching the criteria. To only return specific properties, use
"-Properties samaccountname,usnchanged,...". By default, all group objects for
the current domain are returned. To return the groups a specific user/group is
a part of, use -MemberIdentity X to execute token groups enumeration.

.PARAMETER Identity

A SamAccountName (e.g. Group1), DistinguishedName (e.g. CN=group1,CN=Users,DC=testlab,DC=local),
SID (e.g. S-1-5-21-890171859-3433809279-3366196753-1114), or GUID (e.g. 4c435dd7-dc58-4b14-9a5e-1fdb0e80d202)
specifying the group to query for. Wildcards accepted.

.PARAMETER MemberIdentity

A SamAccountName (e.g. Group1), DistinguishedName (e.g. CN=group1,CN=Users,DC=testlab,DC=local),
SID (e.g. S-1-5-21-890171859-3433809279-3366196753-1114), or GUID (e.g. 4c435dd7-dc58-4b14-9a5e-1fdb0e80d202)
specifying the user/group member to query for group membership.

.PARAMETER AdminCount

Switch. Return users with '(adminCount=1)' (meaning are/were privileged).

.PARAMETER GroupScope

Specifies the scope (DomainLocal, Global, or Universal) of the group(s) to search for.
Also accepts NotDomainLocal, NotGloba, and NotUniversal as negations.

.PARAMETER GroupProperty

Specifies a specific property to search for when performing the group search.
Possible values are Security, Distribution, CreatedBySystem, and NotCreatedBySystem.

.PARAMETER Domain

Specifies the domain to use for the query, defaults to the current domain.

.PARAMETER LDAPFilter

Specifies an LDAP query string that is used to filter Active Directory objects.

.PARAMETER Properties

Specifies the properties of the output object to retrieve from the server.

.PARAMETER SearchBase

The LDAP source to search through, e.g. "LDAP://OU=secret,DC=testlab,DC=local"
Useful for OU queries.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER SecurityMasks

Specifies an option for examining security information of a directory object.
One of 'Dacl', 'Group', 'None', 'Owner', 'Sacl'.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER FindOne

Only return one result object.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.PARAMETER Raw

Switch. Return raw results instead of translating the fields into a custom PSObject.

.EXAMPLE

Get-AdaptDomainGroup | select samaccountname

samaccountname
--------------
WinRMRemoteWMIUsers__
Administrators
Users
Guests
Print Operators
Backup Operators
...

.EXAMPLE

Get-AdaptDomainGroup *admin* | select distinguishedname

distinguishedname
-----------------
CN=Administrators,CN=Builtin,DC=testlab,DC=local
CN=Hyper-V Administrators,CN=Builtin,DC=testlab,DC=local
CN=Schema Admins,CN=Users,DC=testlab,DC=local
CN=Enterprise Admins,CN=Users,DC=testlab,DC=local
CN=Domain Admins,CN=Users,DC=testlab,DC=local
CN=DnsAdmins,CN=Users,DC=testlab,DC=local
CN=Server Admins,CN=Users,DC=testlab,DC=local
CN=Desktop Admins,CN=Users,DC=testlab,DC=local

.EXAMPLE

Get-AdaptDomainGroup -Properties samaccountname -Identity 'S-1-5-21-890171859-3433809279-3366196753-1117' | fl

samaccountname
--------------
Server Admins

.EXAMPLE

'CN=Desktop Admins,CN=Users,DC=testlab,DC=local' | Get-AdaptDomainGroup -Server primary.testlab.local -Verbose
VERBOSE: Get-DomainSearcher search string: LDAP://DC=testlab,DC=local
VERBOSE: Get-AdaptDomainGroup filter string: (&(objectCategory=group)(|(distinguishedname=CN=DesktopAdmins,CN=Users,DC=testlab,DC=local)))

usncreated            : 13245
grouptype             : -2147483646
samaccounttype        : 268435456
samaccountname        : Desktop Admins
whenchanged           : 8/10/2016 12:30:30 AM
objectsid             : S-1-5-21-890171859-3433809279-3366196753-1118
objectclass           : {top, group}
cn                    : Desktop Admins
usnchanged            : 13255
dscorepropagationdata : 1/1/1601 12:00:00 AM
name                  : Desktop Admins
distinguishedname     : CN=Desktop Admins,CN=Users,DC=testlab,DC=local
member                : CN=Andy Robbins (admin),CN=Users,DC=testlab,DC=local
whencreated           : 8/10/2016 12:29:43 AM
instancetype          : 4
objectguid            : f37903ed-b333-49f4-abaa-46c65e9cca71
objectcategory        : CN=Group,CN=Schema,CN=Configuration,DC=testlab,DC=local

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-AdaptDomainGroup -Credential $Cred

.EXAMPLE

Get-AdaptDomain | Select-Object -Expand name
testlab.local

'DEV\Domain Admins' | Get-AdaptDomainGroup -Verbose -Properties distinguishedname
VERBOSE: [Get-DomainSearcher] search string: LDAP://PRIMARY.testlab.local/DC=testlab,DC=local
VERBOSE: [Get-AdaptDomainGroup] Extracted domain 'dev.testlab.local' from 'DEV\Domain Admins'
VERBOSE: [Get-DomainSearcher] search string: LDAP://PRIMARY.testlab.local/DC=dev,DC=testlab,DC=local
VERBOSE: [Get-AdaptDomainGroup] filter string: (&(objectCategory=group)(|(samAccountName=Domain Admins)))

distinguishedname
-----------------
CN=Domain Admins,CN=Users,DC=dev,DC=testlab,DC=local

.OUTPUTS

PowerView.Group

Custom PSObject with translated group property fields.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [OutputType('PowerView.Group')]
    [CmdletBinding(DefaultParameterSetName = 'AllowDelegation')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name', 'MemberDistinguishedName', 'MemberName')]
        [String[]]
        $Identity,

        [ValidateNotNullOrEmpty()]
        [Alias('UserName')]
        [String]
        $MemberIdentity,

        [Switch]
        $AdminCount,

        [ValidateSet('DomainLocal', 'NotDomainLocal', 'Global', 'NotGlobal', 'Universal', 'NotUniversal')]
        [Alias('Scope')]
        [String]
        $GroupScope,

        [ValidateSet('Security', 'Distribution', 'CreatedBySystem', 'NotCreatedBySystem')]
        [String]
        $GroupProperty,

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
        $GroupSearcher = Get-DomainSearcher @SearcherArguments
    }

    PROCESS {
        if ($GroupSearcher) {
            if ($PSBoundParameters['MemberIdentity']) {

                if ($SearcherArguments['Properties']) {
                    $OldProperties = $SearcherArguments['Properties']
                }

                $SearcherArguments['Identity'] = $MemberIdentity
                $SearcherArguments['Raw'] = $True

                Get-AdaptDomainObject @SearcherArguments | ForEach-Object {
                    # convert the user/group to a directory entry
                    $ObjectDirectoryEntry = $_.GetDirectoryEntry()

                    # cause the cache to calculate the token groups for the user/group
                    $ObjectDirectoryEntry.RefreshCache('tokenGroups')

                    $ObjectDirectoryEntry.TokenGroups | ForEach-Object {
                        # convert the token group sid
                        $GroupSid = (New-Object System.Security.Principal.SecurityIdentifier($_,0)).Value

                        # ignore the built in groups
                        if ($GroupSid -notmatch '^S-1-5-32-.*') {
                            $SearcherArguments['Identity'] = $GroupSid
                            $SearcherArguments['Raw'] = $False
                            if ($OldProperties) { $SearcherArguments['Properties'] = $OldProperties }
                            $Group = Get-AdaptDomainObject @SearcherArguments
                            if ($Group) {
                                $Group.PSObject.TypeNames.Insert(0, 'PowerView.Group')
                                $Group
                            }
                        }
                    }
                }
            }
            else {
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
                            # if a -Domain isn't explicitly set, extract the object domain out of the distinguishedname
                            #   and rebuild the domain searcher
                            $IdentityDomain = $IdentityInstance.SubString($IdentityInstance.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                            Write-Verbose "[Get-AdaptDomainGroup] Extracted domain '$IdentityDomain' from '$IdentityInstance'"
                            $SearcherArguments['Domain'] = $IdentityDomain
                            $GroupSearcher = Get-DomainSearcher @SearcherArguments
                            if (-not $GroupSearcher) {
                                Write-Warning "[Get-AdaptDomainGroup] Unable to retrieve domain searcher for '$IdentityDomain'"
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
                            $GroupDomain = $ConvertedIdentityInstance.SubString(0, $ConvertedIdentityInstance.IndexOf('/'))
                            $GroupName = $IdentityInstance.Split('\')[1]
                            $IdentityFilter += "(samAccountName=$GroupName)"
                            $SearcherArguments['Domain'] = $GroupDomain
                            Write-Verbose "[Get-AdaptDomainGroup] Extracted domain '$GroupDomain' from '$IdentityInstance'"
                            $GroupSearcher = Get-DomainSearcher @SearcherArguments
                        }
                    }
                    else {
                        $IdentityFilter += "(|(samAccountName=$IdentityInstance)(name=$IdentityInstance))"
                    }
                }

                if ($IdentityFilter -and ($IdentityFilter.Trim() -ne '') ) {
                    $Filter += "(|$IdentityFilter)"
                }

                if ($PSBoundParameters['AdminCount']) {
                    Write-Verbose '[Get-AdaptDomainGroup] Searching for adminCount=1'
                    $Filter += '(admincount=1)'
                }
                if ($PSBoundParameters['GroupScope']) {
                    $GroupScopeValue = $PSBoundParameters['GroupScope']
                    $Filter = Switch ($GroupScopeValue) {
                        'DomainLocal'       { '(groupType:1.2.840.113556.1.4.803:=4)' }
                        'NotDomainLocal'    { '(!(groupType:1.2.840.113556.1.4.803:=4))' }
                        'Global'            { '(groupType:1.2.840.113556.1.4.803:=2)' }
                        'NotGlobal'         { '(!(groupType:1.2.840.113556.1.4.803:=2))' }
                        'Universal'         { '(groupType:1.2.840.113556.1.4.803:=8)' }
                        'NotUniversal'      { '(!(groupType:1.2.840.113556.1.4.803:=8))' }
                    }
                    Write-Verbose "[Get-AdaptDomainGroup] Searching for group scope '$GroupScopeValue'"
                }
                if ($PSBoundParameters['GroupProperty']) {
                    $GroupPropertyValue = $PSBoundParameters['GroupProperty']
                    $Filter = Switch ($GroupPropertyValue) {
                        'Security'              { '(groupType:1.2.840.113556.1.4.803:=2147483648)' }
                        'Distribution'          { '(!(groupType:1.2.840.113556.1.4.803:=2147483648))' }
                        'CreatedBySystem'       { '(groupType:1.2.840.113556.1.4.803:=1)' }
                        'NotCreatedBySystem'    { '(!(groupType:1.2.840.113556.1.4.803:=1))' }
                    }
                    Write-Verbose "[Get-AdaptDomainGroup] Searching for group property '$GroupPropertyValue'"
                }
                if ($PSBoundParameters['LDAPFilter']) {
                    Write-Verbose "[Get-AdaptDomainGroup] Using additional LDAP filter: $LDAPFilter"
                    $Filter += "$LDAPFilter"
                }

                $GroupSearcher.filter = "(&(objectCategory=group)$Filter)"
                Write-Verbose "[Get-AdaptDomainGroup] filter string: $($GroupSearcher.filter)"

                if ($PSBoundParameters['FindOne']) { $Results = $GroupSearcher.FindOne() }
                else { $Results = $GroupSearcher.FindAll() }
                $Results | Where-Object {$_} | ForEach-Object {
                    if ($PSBoundParameters['Raw']) {
                        # return raw result objects
                        $Group = $_
                    }
                    else {
                        $Group = Convert-LDAPProperty -Properties $_.Properties
                    }
                    $Group.PSObject.TypeNames.Insert(0, 'PowerView.Group')
                    $Group
                }
                if ($Results) {
                    try { $Results.dispose() }
                    catch {
                        Write-Verbose "[Get-AdaptDomainGroup] Error disposing of the Results object"
                    }
                }
                $GroupSearcher.dispose()
            }
        }
    }
}

# --- Get-AdaptDomainGroupMember (dependency) ---
function Get-AdaptDomainGroupMember {
<#
.SYNOPSIS

Return the members of a specific domain group.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainSearcher, Get-AdaptDomainGroup, Get-AdaptDomainGroupMember, Convert-ADName, Get-AdaptDomainObject, ConvertFrom-SID  

.DESCRIPTION

Builds a directory searcher object using Get-DomainSearcher, builds a custom
LDAP filter based on targeting/filter parameters, and searches for the specified
group matching the criteria. Each result is then rebound and the full user
or group object is returned.

.PARAMETER Identity

A SamAccountName (e.g. Group1), DistinguishedName (e.g. CN=group1,CN=Users,DC=testlab,DC=local),
SID (e.g. S-1-5-21-890171859-3433809279-3366196753-1114), or GUID (e.g. 4c435dd7-dc58-4b14-9a5e-1fdb0e80d202)
specifying the group to query for. Wildcards accepted.

.PARAMETER Domain

Specifies the domain to use for the query, defaults to the current domain.

.PARAMETER Recurse

Switch. If the group member is a group, recursively try to query its members as well.

.PARAMETER RecurseUsingMatchingRule

Switch. Use LDAP_MATCHING_RULE_IN_CHAIN in the LDAP search query to recurse.
Much faster than manual recursion, but doesn't reveal cross-domain groups,
and only returns user accounts (no nested group objects themselves).

.PARAMETER LDAPFilter

Specifies an LDAP query string that is used to filter Active Directory objects.

.PARAMETER SearchBase

The LDAP source to search through, e.g. "LDAP://OU=secret,DC=testlab,DC=local"
Useful for OU queries.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER SecurityMasks

Specifies an option for examining security information of a directory object.
One of 'Dacl', 'Group', 'None', 'Owner', 'Sacl'.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.EXAMPLE

Get-AdaptDomainGroupMember "Desktop Admins"

GroupDomain             : testlab.local
GroupName               : Desktop Admins
GroupDistinguishedName  : CN=Desktop Admins,CN=Users,DC=testlab,DC=local
MemberDomain            : testlab.local
MemberName              : Testing Group
MemberDistinguishedName : CN=Testing Group,CN=Users,DC=testlab,DC=local
MemberObjectClass       : group
MemberSID               : S-1-5-21-890171859-3433809279-3366196753-1129

GroupDomain             : testlab.local
GroupName               : Desktop Admins
GroupDistinguishedName  : CN=Desktop Admins,CN=Users,DC=testlab,DC=local
MemberDomain            : testlab.local
MemberName              : arobbins.a
MemberDistinguishedName : CN=Andy Robbins (admin),CN=Users,DC=testlab,DC=local
MemberObjectClass       : user
MemberSID               : S-1-5-21-890171859-3433809279-3366196753-1112

.EXAMPLE

'Desktop Admins' | Get-AdaptDomainGroupMember -Recurse

GroupDomain             : testlab.local
GroupName               : Desktop Admins
GroupDistinguishedName  : CN=Desktop Admins,CN=Users,DC=testlab,DC=local
MemberDomain            : testlab.local
MemberName              : Testing Group
MemberDistinguishedName : CN=Testing Group,CN=Users,DC=testlab,DC=local
MemberObjectClass       : group
MemberSID               : S-1-5-21-890171859-3433809279-3366196753-1129

GroupDomain             : testlab.local
GroupName               : Testing Group
GroupDistinguishedName  : CN=Testing Group,CN=Users,DC=testlab,DC=local
MemberDomain            : testlab.local
MemberName              : harmj0y
MemberDistinguishedName : CN=harmj0y,CN=Users,DC=testlab,DC=local
MemberObjectClass       : user
MemberSID               : S-1-5-21-890171859-3433809279-3366196753-1108

GroupDomain             : testlab.local
GroupName               : Desktop Admins
GroupDistinguishedName  : CN=Desktop Admins,CN=Users,DC=testlab,DC=local
MemberDomain            : testlab.local
MemberName              : arobbins.a
MemberDistinguishedName : CN=Andy Robbins (admin),CN=Users,DC=testlab,DC=local
MemberObjectClass       : user
MemberSID               : S-1-5-21-890171859-3433809279-3366196753-1112

.EXAMPLE

Get-AdaptDomainGroupMember -Domain testlab.local -Identity 'Desktop Admins' -RecurseUingMatchingRule

GroupDomain             : testlab.local
GroupName               : Desktop Admins
GroupDistinguishedName  : CN=Desktop Admins,CN=Users,DC=testlab,DC=local
MemberDomain            : testlab.local
MemberName              : harmj0y
MemberDistinguishedName : CN=harmj0y,CN=Users,DC=testlab,DC=local
MemberObjectClass       : user
MemberSID               : S-1-5-21-890171859-3433809279-3366196753-1108

GroupDomain             : testlab.local
GroupName               : Desktop Admins
GroupDistinguishedName  : CN=Desktop Admins,CN=Users,DC=testlab,DC=local
MemberDomain            : testlab.local
MemberName              : arobbins.a
MemberDistinguishedName : CN=Andy Robbins (admin),CN=Users,DC=testlab,DC=local
MemberObjectClass       : user
MemberSID               : S-1-5-21-890171859-3433809279-3366196753-1112

.EXAMPLE

Get-AdaptDomainGroup *admin* -Properties samaccountname | Get-AdaptDomainGroupMember

.EXAMPLE

'CN=Enterprise Admins,CN=Users,DC=testlab,DC=local', 'Domain Admins' | Get-AdaptDomainGroupMember

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-AdaptDomainGroupMember -Credential $Cred -Identity 'Domain Admins'

.EXAMPLE

Get-AdaptDomain | Select-Object -Expand name
testlab.local

'dev\domain admins' | Get-AdaptDomainGroupMember -Verbose
VERBOSE: [Get-DomainSearcher] search string: LDAP://PRIMARY.testlab.local/DC=testlab,DC=local
VERBOSE: [Get-AdaptDomainGroupMember] Extracted domain 'dev.testlab.local' from 'dev\domain admins'
VERBOSE: [Get-DomainSearcher] search string: LDAP://PRIMARY.testlab.local/DC=dev,DC=testlab,DC=local
VERBOSE: [Get-AdaptDomainGroupMember] Get-AdaptDomainGroupMember filter string: (&(objectCategory=group)(|(samAccountName=domain admins)))
VERBOSE: [Get-DomainSearcher] search string: LDAP://PRIMARY.testlab.local/DC=dev,DC=testlab,DC=local
VERBOSE: [Get-AdaptDomainObject] Get-AdaptDomainObject filter string: (&(|(distinguishedname=CN=user1,CN=Users,DC=dev,DC=testlab,DC=local)))

GroupDomain             : dev.testlab.local
GroupName               : Domain Admins
GroupDistinguishedName  : CN=Domain Admins,CN=Users,DC=dev,DC=testlab,DC=local
MemberDomain            : dev.testlab.local
MemberName              : user1
MemberDistinguishedName : CN=user1,CN=Users,DC=dev,DC=testlab,DC=local
MemberObjectClass       : user
MemberSID               : S-1-5-21-339048670-1233568108-4141518690-201108

VERBOSE: [Get-DomainSearcher] search string: LDAP://PRIMARY.testlab.local/DC=dev,DC=testlab,DC=local
VERBOSE: [Get-AdaptDomainObject] Get-AdaptDomainObject filter string: (&(|(distinguishedname=CN=Administrator,CN=Users,DC=dev,DC=testlab,DC=local)))
GroupDomain             : dev.testlab.local
GroupName               : Domain Admins
GroupDistinguishedName  : CN=Domain Admins,CN=Users,DC=dev,DC=testlab,DC=local
MemberDomain            : dev.testlab.local
MemberName              : Administrator
MemberDistinguishedName : CN=Administrator,CN=Users,DC=dev,DC=testlab,DC=local
MemberObjectClass       : user
MemberSID               : S-1-5-21-339048670-1233568108-4141518690-500

.OUTPUTS

PowerView.GroupMember

Custom PSObject with translated group member property fields.

.LINK

http://www.powershellmagazine.com/2013/05/23/pstip-retrieve-group-membership-of-an-active-directory-group-recursively/
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [OutputType('PowerView.GroupMember')]
    [CmdletBinding(DefaultParameterSetName = 'None')]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name', 'MemberDistinguishedName', 'MemberName')]
        [String[]]
        $Identity,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [Parameter(ParameterSetName = 'ManualRecurse')]
        [Switch]
        $Recurse,

        [Parameter(ParameterSetName = 'RecurseUsingMatchingRule')]
        [Switch]
        $RecurseUsingMatchingRule,

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

        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $SecurityMasks,

        [Switch]
        $Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $SearcherArguments = @{
            'Properties' = 'member,samaccountname,distinguishedname'
        }
        if ($PSBoundParameters['Domain']) { $SearcherArguments['Domain'] = $Domain }
        if ($PSBoundParameters['LDAPFilter']) { $SearcherArguments['LDAPFilter'] = $LDAPFilter }
        if ($PSBoundParameters['SearchBase']) { $SearcherArguments['SearchBase'] = $SearchBase }
        if ($PSBoundParameters['Server']) { $SearcherArguments['Server'] = $Server }
        if ($PSBoundParameters['SearchScope']) { $SearcherArguments['SearchScope'] = $SearchScope }
        if ($PSBoundParameters['ResultPageSize']) { $SearcherArguments['ResultPageSize'] = $ResultPageSize }
        if ($PSBoundParameters['ServerTimeLimit']) { $SearcherArguments['ServerTimeLimit'] = $ServerTimeLimit }
        if ($PSBoundParameters['Tombstone']) { $SearcherArguments['Tombstone'] = $Tombstone }
        if ($PSBoundParameters['Credential']) { $SearcherArguments['Credential'] = $Credential }

        $ADNameArguments = @{}
        if ($PSBoundParameters['Domain']) { $ADNameArguments['Domain'] = $Domain }
        if ($PSBoundParameters['Server']) { $ADNameArguments['Server'] = $Server }
        if ($PSBoundParameters['Credential']) { $ADNameArguments['Credential'] = $Credential }
    }

    PROCESS {
        $GroupSearcher = Get-DomainSearcher @SearcherArguments
        if ($GroupSearcher) {
            if ($PSBoundParameters['RecurseUsingMatchingRule']) {
                $SearcherArguments['Identity'] = $Identity
                $SearcherArguments['Raw'] = $True
                $Group = Get-AdaptDomainGroup @SearcherArguments

                if (-not $Group) {
                    Write-Warning "[Get-AdaptDomainGroupMember] Error searching for group with identity: $Identity"
                }
                else {
                    $GroupFoundName = $Group.properties.item('samaccountname')[0]
                    $GroupFoundDN = $Group.properties.item('distinguishedname')[0]

                    if ($PSBoundParameters['Domain']) {
                        $GroupFoundDomain = $Domain
                    }
                    else {
                        # if a domain isn't passed, try to extract it from the found group distinguished name
                        if ($GroupFoundDN) {
                            $GroupFoundDomain = $GroupFoundDN.SubString($GroupFoundDN.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        }
                    }
                    Write-Verbose "[Get-AdaptDomainGroupMember] Using LDAP matching rule to recurse on '$GroupFoundDN', only user accounts will be returned."
                    $GroupSearcher.filter = "(&(samAccountType=805306368)(memberof:1.2.840.113556.1.4.1941:=$GroupFoundDN))"
                    $GroupSearcher.PropertiesToLoad.AddRange(('distinguishedName'))
                    $Members = $GroupSearcher.FindAll() | ForEach-Object {$_.Properties.distinguishedname[0]}
                }
                $Null = $SearcherArguments.Remove('Raw')
            }
            else {
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
                            # if a -Domain isn't explicitly set, extract the object domain out of the distinguishedname
                            #   and rebuild the domain searcher
                            $IdentityDomain = $IdentityInstance.SubString($IdentityInstance.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                            Write-Verbose "[Get-AdaptDomainGroupMember] Extracted domain '$IdentityDomain' from '$IdentityInstance'"
                            $SearcherArguments['Domain'] = $IdentityDomain
                            $GroupSearcher = Get-DomainSearcher @SearcherArguments
                            if (-not $GroupSearcher) {
                                Write-Warning "[Get-AdaptDomainGroupMember] Unable to retrieve domain searcher for '$IdentityDomain'"
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
                            $GroupDomain = $ConvertedIdentityInstance.SubString(0, $ConvertedIdentityInstance.IndexOf('/'))
                            $GroupName = $IdentityInstance.Split('\')[1]
                            $IdentityFilter += "(samAccountName=$GroupName)"
                            $SearcherArguments['Domain'] = $GroupDomain
                            Write-Verbose "[Get-AdaptDomainGroupMember] Extracted domain '$GroupDomain' from '$IdentityInstance'"
                            $GroupSearcher = Get-DomainSearcher @SearcherArguments
                        }
                    }
                    else {
                        $IdentityFilter += "(samAccountName=$IdentityInstance)"
                    }
                }

                if ($IdentityFilter -and ($IdentityFilter.Trim() -ne '') ) {
                    $Filter += "(|$IdentityFilter)"
                }

                if ($PSBoundParameters['LDAPFilter']) {
                    Write-Verbose "[Get-AdaptDomainGroupMember] Using additional LDAP filter: $LDAPFilter"
                    $Filter += "$LDAPFilter"
                }

                $GroupSearcher.filter = "(&(objectCategory=group)$Filter)"
                Write-Verbose "[Get-AdaptDomainGroupMember] Get-AdaptDomainGroupMember filter string: $($GroupSearcher.filter)"
                try {
                    $Result = $GroupSearcher.FindOne()
                }
                catch {
                    Write-Warning "[Get-AdaptDomainGroupMember] Error searching for group with identity '$Identity': $_"
                    $Members = @()
                }

                $GroupFoundName = ''
                $GroupFoundDN = ''

                if ($Result) {
                    $Members = $Result.properties.item('member')

                    if ($Members.count -eq 0) {
                        # ranged searching, thanks @meatballs__ !
                        $Finished = $False
                        $Bottom = 0
                        $Top = 0

                        while (-not $Finished) {
                            $Top = $Bottom + 1499
                            $MemberRange="member;range=$Bottom-$Top"
                            $Bottom += 1500
                            $Null = $GroupSearcher.PropertiesToLoad.Clear()
                            $Null = $GroupSearcher.PropertiesToLoad.Add("$MemberRange")
                            $Null = $GroupSearcher.PropertiesToLoad.Add('samaccountname')
                            $Null = $GroupSearcher.PropertiesToLoad.Add('distinguishedname')

                            try {
                                $Result = $GroupSearcher.FindOne()
                                $RangedProperty = $Result.Properties.PropertyNames -like "member;range=*"
                                $Members += $Result.Properties.item($RangedProperty)
                                $GroupFoundName = $Result.properties.item('samaccountname')[0]
                                $GroupFoundDN = $Result.properties.item('distinguishedname')[0]

                                if ($Members.count -eq 0) {
                                    $Finished = $True
                                }
                            }
                            catch [System.Management.Automation.MethodInvocationException] {
                                $Finished = $True
                            }
                        }
                    }
                    else {
                        $GroupFoundName = $Result.properties.item('samaccountname')[0]
                        $GroupFoundDN = $Result.properties.item('distinguishedname')[0]
                        $Members += $Result.Properties.item($RangedProperty)
                    }

                    if ($PSBoundParameters['Domain']) {
                        $GroupFoundDomain = $Domain
                    }
                    else {
                        # if a domain isn't passed, try to extract it from the found group distinguished name
                        if ($GroupFoundDN) {
                            $GroupFoundDomain = $GroupFoundDN.SubString($GroupFoundDN.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        }
                    }
                }
            }

            ForEach ($Member in $Members) {
                if ($Recurse -and $UseMatchingRule) {
                    $Properties = $_.Properties
                }
                else {
                    $ObjectSearcherArguments = $SearcherArguments.Clone()
                    $ObjectSearcherArguments['Identity'] = $Member
                    $ObjectSearcherArguments['Raw'] = $True
                    $ObjectSearcherArguments['Properties'] = 'distinguishedname,cn,samaccountname,objectsid,objectclass'
                    $Object = Get-AdaptDomainObject @ObjectSearcherArguments
                    $Properties = $Object.Properties
                }

                if ($Properties) {
                    $GroupMember = New-Object PSObject
                    $GroupMember | Add-Member Noteproperty 'GroupDomain' $GroupFoundDomain
                    $GroupMember | Add-Member Noteproperty 'GroupName' $GroupFoundName
                    $GroupMember | Add-Member Noteproperty 'GroupDistinguishedName' $GroupFoundDN

                    if ($Properties.objectsid) {
                        $MemberSID = ((New-Object System.Security.Principal.SecurityIdentifier $Properties.objectsid[0], 0).Value)
                    }
                    else {
                        $MemberSID = $Null
                    }

                    try {
                        $MemberDN = $Properties.distinguishedname[0]
                        if ($MemberDN -match 'ForeignSecurityPrincipals|S-1-5-21') {
                            try {
                                if (-not $MemberSID) {
                                    $MemberSID = $Properties.cn[0]
                                }
                                $MemberSimpleName = Convert-ADName -Identity $MemberSID -OutputType 'DomainSimple' @ADNameArguments

                                if ($MemberSimpleName) {
                                    $MemberDomain = $MemberSimpleName.Split('@')[1]
                                }
                                else {
                                    Write-Warning "[Get-AdaptDomainGroupMember] Error converting $MemberDN"
                                    $MemberDomain = $Null
                                }
                            }
                            catch {
                                Write-Warning "[Get-AdaptDomainGroupMember] Error converting $MemberDN"
                                $MemberDomain = $Null
                            }
                        }
                        else {
                            # extract the FQDN from the Distinguished Name
                            $MemberDomain = $MemberDN.SubString($MemberDN.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        }
                    }
                    catch {
                        $MemberDN = $Null
                        $MemberDomain = $Null
                    }

                    if ($Properties.samaccountname) {
                        # forest users have the samAccountName set
                        $MemberName = $Properties.samaccountname[0]
                    }
                    else {
                        # external trust users have a SID, so convert it
                        try {
                            $MemberName = ConvertFrom-SID -ObjectSID $Properties.cn[0] @ADNameArguments
                        }
                        catch {
                            # if there's a problem contacting the domain to resolve the SID
                            $MemberName = $Properties.cn[0]
                        }
                    }

                    if ($Properties.objectclass -match 'computer') {
                        $MemberObjectClass = 'computer'
                    }
                    elseif ($Properties.objectclass -match 'group') {
                        $MemberObjectClass = 'group'
                    }
                    elseif ($Properties.objectclass -match 'user') {
                        $MemberObjectClass = 'user'
                    }
                    else {
                        $MemberObjectClass = $Null
                    }
                    $GroupMember | Add-Member Noteproperty 'MemberDomain' $MemberDomain
                    $GroupMember | Add-Member Noteproperty 'MemberName' $MemberName
                    $GroupMember | Add-Member Noteproperty 'MemberDistinguishedName' $MemberDN
                    $GroupMember | Add-Member Noteproperty 'MemberObjectClass' $MemberObjectClass
                    $GroupMember | Add-Member Noteproperty 'MemberSID' $MemberSID
                    $GroupMember.PSObject.TypeNames.Insert(0, 'PowerView.GroupMember')
                    $GroupMember

                    # if we're doing manual recursion
                    if ($PSBoundParameters['Recurse'] -and $MemberDN -and ($MemberObjectClass -match 'group')) {
                        Write-Verbose "[Get-AdaptDomainGroupMember] Manually recursing on group: $MemberDN"
                        $SearcherArguments['Identity'] = $MemberDN
                        $Null = $SearcherArguments.Remove('Properties')
                        Get-AdaptDomainGroupMember @SearcherArguments
                    }
                }
            }
            $GroupSearcher.dispose()
        }
    }
}

# --- Get-AdaptDomainObject (dependency) ---
function Get-AdaptDomainObject {
<#
.SYNOPSIS

Return all (or specified) domain objects in AD.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainSearcher, Convert-LDAPProperty, Convert-ADName  

.DESCRIPTION

Builds a directory searcher object using Get-DomainSearcher, builds a custom
LDAP filter based on targeting/filter parameters, and searches for all objects
matching the criteria. To only return specific properties, use
"-Properties samaccountname,usnchanged,...". By default, all objects for
the current domain are returned.

.PARAMETER Identity

A SamAccountName (e.g. harmj0y), DistinguishedName (e.g. CN=harmj0y,CN=Users,DC=testlab,DC=local),
SID (e.g. S-1-5-21-890171859-3433809279-3366196753-1108), or GUID (e.g. 4c435dd7-dc58-4b14-9a5e-1fdb0e80d201).
Wildcards accepted.

.PARAMETER UACFilter

Dynamic parameter that accepts one or more values from $UACEnum, including
"NOT_X" negation forms. To see all possible values, run '0|ConvertFrom-UACValue -ShowAll'.

.PARAMETER Domain

Specifies the domain to use for the query, defaults to the current domain.

.PARAMETER LDAPFilter

Specifies an LDAP query string that is used to filter Active Directory objects.

.PARAMETER Properties

Specifies the properties of the output object to retrieve from the server.

.PARAMETER SearchBase

The LDAP source to search through, e.g. "LDAP://OU=secret,DC=testlab,DC=local"
Useful for OU queries.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER SecurityMasks

Specifies an option for examining security information of a directory object.
One of 'Dacl', 'Group', 'None', 'Owner', 'Sacl'.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER FindOne

Only return one result object.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.PARAMETER Raw

Switch. Return raw results instead of translating the fields into a custom PSObject.

.EXAMPLE

Get-AdaptDomainObject -Domain testlab.local

Return all objects for the testlab.local domain

.EXAMPLE

'S-1-5-21-890171859-3433809279-3366196753-1003', 'CN=dfm,CN=Users,DC=testlab,DC=local','b6a9a2fb-bbd5-4f28-9a09-23213cea6693','dfm.a' | Get-AdaptDomainObject -Properties distinguishedname

distinguishedname
-----------------
CN=PRIMARY,OU=Domain Controllers,DC=testlab,DC=local
CN=dfm,CN=Users,DC=testlab,DC=local
OU=OU3,DC=testlab,DC=local
CN=dfm (admin),CN=Users,DC=testlab,DC=local

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-AdaptDomainObject -Credential $Cred -Identity 'windows1'

.EXAMPLE

Get-AdaptDomain | Select-Object -Expand name
testlab.local

'testlab\harmj0y','DEV\Domain Admins' | Get-AdaptDomainObject -Verbose -Properties distinguishedname
VERBOSE: [Get-DomainSearcher] search string: LDAP://PRIMARY.testlab.local/DC=testlab,DC=local
VERBOSE: [Get-AdaptDomainUser] Extracted domain 'testlab.local' from 'testlab\harmj0y'
VERBOSE: [Get-DomainSearcher] search string: LDAP://PRIMARY.testlab.local/DC=testlab,DC=local
VERBOSE: [Get-AdaptDomainObject] Get-AdaptDomainObject filter string: (&(|(samAccountName=harmj0y)))

distinguishedname
-----------------
CN=harmj0y,CN=Users,DC=testlab,DC=local
VERBOSE: [Get-AdaptDomainUser] Extracted domain 'dev.testlab.local' from 'DEV\Domain Admins'
VERBOSE: [Get-DomainSearcher] search string: LDAP://PRIMARY.testlab.local/DC=dev,DC=testlab,DC=local
VERBOSE: [Get-AdaptDomainObject] Get-AdaptDomainObject filter string: (&(|(samAccountName=Domain Admins)))
CN=Domain Admins,CN=Users,DC=dev,DC=testlab,DC=local

.OUTPUTS

PowerView.ADObject

Custom PSObject with translated AD object property fields.

PowerView.ADObject.Raw

The raw DirectoryServices.SearchResult object, if -Raw is enabled.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [OutputType('PowerView.ADObject')]
    [OutputType('PowerView.ADObject.Raw')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name', 'MemberDistinguishedName', 'MemberName')]
        [String[]]
        $Identity,

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
        $UACValueNames = [Enum]::GetNames($UACEnum)
        # add in the negations
        $UACValueNames = $UACValueNames | ForEach-Object {$_; "NOT_$_"}
        # create new dynamic parameter
        New-DynamicParameter -Name UACFilter -ValidateSet $UACValueNames -Type ([array])
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
        $ObjectSearcher = Get-DomainSearcher @SearcherArguments
    }

    PROCESS {
        #bind dynamic parameter to a friendly variable
        if ($PSBoundParameters -and ($PSBoundParameters.Count -ne 0)) {
            New-DynamicParameter -CreateVariables -BoundParameters $PSBoundParameters
        }
        if ($ObjectSearcher) {
            $IdentityFilter = ''
            $Filter = ''
            $Identity | Where-Object {$_} | ForEach-Object {
                $IdentityInstance = $_.Replace('(', '\28').Replace(')', '\29')
                if ($IdentityInstance -match '^S-1-') {
                    $IdentityFilter += "(objectsid=$IdentityInstance)"
                }
                elseif ($IdentityInstance -match '^(CN|OU|DC)=') {
                    $IdentityFilter += "(distinguishedname=$IdentityInstance)"
                    if ((-not $PSBoundParameters['Domain']) -and (-not $PSBoundParameters['SearchBase'])) {
                        # if a -Domain isn't explicitly set, extract the object domain out of the distinguishedname
                        #   and rebuild the domain searcher
                        $IdentityDomain = $IdentityInstance.SubString($IdentityInstance.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        Write-Verbose "[Get-AdaptDomainObject] Extracted domain '$IdentityDomain' from '$IdentityInstance'"
                        $SearcherArguments['Domain'] = $IdentityDomain
                        $ObjectSearcher = Get-DomainSearcher @SearcherArguments
                        if (-not $ObjectSearcher) {
                            Write-Warning "[Get-AdaptDomainObject] Unable to retrieve domain searcher for '$IdentityDomain'"
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
                        $ObjectDomain = $ConvertedIdentityInstance.SubString(0, $ConvertedIdentityInstance.IndexOf('/'))
                        $ObjectName = $IdentityInstance.Split('\')[1]
                        $IdentityFilter += "(samAccountName=$ObjectName)"
                        $SearcherArguments['Domain'] = $ObjectDomain
                        Write-Verbose "[Get-AdaptDomainObject] Extracted domain '$ObjectDomain' from '$IdentityInstance'"
                        $ObjectSearcher = Get-DomainSearcher @SearcherArguments
                    }
                }
                elseif ($IdentityInstance.Contains('.')) {
                    $IdentityFilter += "(|(samAccountName=$IdentityInstance)(name=$IdentityInstance)(dnshostname=$IdentityInstance))"
                }
                else {
                    $IdentityFilter += "(|(samAccountName=$IdentityInstance)(name=$IdentityInstance)(displayname=$IdentityInstance))"
                }
            }
            if ($IdentityFilter -and ($IdentityFilter.Trim() -ne '') ) {
                $Filter += "(|$IdentityFilter)"
            }

            if ($PSBoundParameters['LDAPFilter']) {
                Write-Verbose "[Get-AdaptDomainObject] Using additional LDAP filter: $LDAPFilter"
                $Filter += "$LDAPFilter"
            }

            # build the LDAP filter for the dynamic UAC filter value
            $UACFilter | Where-Object {$_} | ForEach-Object {
                if ($_ -match 'NOT_.*') {
                    $UACField = $_.Substring(4)
                    $UACValue = [Int]($UACEnum::$UACField)
                    $Filter += "(!(userAccountControl:1.2.840.113556.1.4.803:=$UACValue))"
                }
                else {
                    $UACValue = [Int]($UACEnum::$_)
                    $Filter += "(userAccountControl:1.2.840.113556.1.4.803:=$UACValue)"
                }
            }

            if ($Filter -and $Filter -ne '') {
                $ObjectSearcher.filter = "(&$Filter)"
            }
            Write-Verbose "[Get-AdaptDomainObject] Get-AdaptDomainObject filter string: $($ObjectSearcher.filter)"

            if ($PSBoundParameters['FindOne']) { $Results = $ObjectSearcher.FindOne() }
            else { $Results = $ObjectSearcher.FindAll() }
            $Results | Where-Object {$_} | ForEach-Object {
                if ($PSBoundParameters['Raw']) {
                    # return raw result objects
                    $Object = $_
                    $Object.PSObject.TypeNames.Insert(0, 'PowerView.ADObject.Raw')
                }
                else {
                    $Object = Convert-LDAPProperty -Properties $_.Properties
                    $Object.PSObject.TypeNames.Insert(0, 'PowerView.ADObject')
                }
                $Object
            }
            if ($Results) {
                try { $Results.dispose() }
                catch {
                    Write-Verbose "[Get-AdaptDomainObject] Error disposing of the Results object: $_"
                }
            }
            $ObjectSearcher.dispose()
        }
    }
}

# --- Get-AdaptDomainUser (dependency) ---
function Get-AdaptDomainUser {
<#
.SYNOPSIS

Return all users or specific user objects in AD.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainSearcher, Convert-ADName, Convert-LDAPProperty  

.DESCRIPTION

Builds a directory searcher object using Get-DomainSearcher, builds a custom
LDAP filter based on targeting/filter parameters, and searches for all objects
matching the criteria. To only return specific properties, use
"-Properties samaccountname,usnchanged,...". By default, all user objects for
the current domain are returned.

.PARAMETER Identity

A SamAccountName (e.g. harmj0y), DistinguishedName (e.g. CN=harmj0y,CN=Users,DC=testlab,DC=local),
SID (e.g. S-1-5-21-890171859-3433809279-3366196753-1108), or GUID (e.g. 4c435dd7-dc58-4b14-9a5e-1fdb0e80d201).
Wildcards accepted. Also accepts DOMAIN\user format.

.PARAMETER SPN

Switch. Only return user objects with non-null service principal names.

.PARAMETER UACFilter

Dynamic parameter that accepts one or more values from $UACEnum, including
"NOT_X" negation forms. To see all possible values, run '0|ConvertFrom-UACValue -ShowAll'.

.PARAMETER AdminCount

Switch. Return users with '(adminCount=1)' (meaning are/were privileged).

.PARAMETER AllowDelegation

Switch. Return user accounts that are not marked as 'sensitive and not allowed for delegation'

.PARAMETER DisallowDelegation

Switch. Return user accounts that are marked as 'sensitive and not allowed for delegation'

.PARAMETER TrustedToAuth

Switch. Return computer objects that are trusted to authenticate for other principals.

.PARAMETER PreauthNotRequired

Switch. Return user accounts with "Do not require Kerberos preauthentication" set.

.PARAMETER Domain

Specifies the domain to use for the query, defaults to the current domain.

.PARAMETER LDAPFilter

Specifies an LDAP query string that is used to filter Active Directory objects.

.PARAMETER Properties

Specifies the properties of the output object to retrieve from the server.

.PARAMETER SearchBase

The LDAP source to search through, e.g. "LDAP://OU=secret,DC=testlab,DC=local"
Useful for OU queries.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER SecurityMasks

Specifies an option for examining security information of a directory object.
One of 'Dacl', 'Group', 'None', 'Owner', 'Sacl'.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER FindOne

Only return one result object.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.PARAMETER Raw

Switch. Return raw results instead of translating the fields into a custom PSObject.

.EXAMPLE

Get-AdaptDomainUser -Domain testlab.local

Return all users for the testlab.local domain

.EXAMPLE

Get-AdaptDomainUser "S-1-5-21-890171859-3433809279-3366196753-1108","administrator"

Return the user with the given SID, as well as Administrator.

.EXAMPLE

'S-1-5-21-890171859-3433809279-3366196753-1114', 'CN=dfm,CN=Users,DC=testlab,DC=local','4c435dd7-dc58-4b14-9a5e-1fdb0e80d201','administrator' | Get-AdaptDomainUser -Properties samaccountname,lastlogoff

lastlogoff                                   samaccountname
----------                                   --------------
12/31/1600 4:00:00 PM                        dfm.a
12/31/1600 4:00:00 PM                        dfm
12/31/1600 4:00:00 PM                        harmj0y
12/31/1600 4:00:00 PM                        Administrator

.EXAMPLE

Get-AdaptDomainUser -SearchBase "LDAP://OU=secret,DC=testlab,DC=local" -AdminCount -AllowDelegation

Search the specified OU for privileged user (AdminCount = 1) that allow delegation

.EXAMPLE

Get-AdaptDomainUser -LDAPFilter '(!primarygroupid=513)' -Properties samaccountname,lastlogon

Search for users with a primary group ID other than 513 ('domain users') and only return samaccountname and lastlogon

.EXAMPLE

Get-AdaptDomainUser -UACFilter DONT_REQ_PREAUTH,NOT_PASSWORD_EXPIRED

Find users who doesn't require Kerberos preauthentication and DON'T have an expired password.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-AdaptDomainUser -Credential $Cred

.EXAMPLE

Get-AdaptDomain | Select-Object -Expand name
testlab.local

Get-AdaptDomainUser dev\user1 -Verbose -Properties distinguishedname
VERBOSE: [Get-DomainSearcher] search string: LDAP://PRIMARY.testlab.local/DC=testlab,DC=local
VERBOSE: [Get-DomainSearcher] search string: LDAP://PRIMARY.testlab.local/DC=dev,DC=testlab,DC=local
VERBOSE: [Get-AdaptDomainUser] filter string: (&(samAccountType=805306368)(|(samAccountName=user1)))

distinguishedname
-----------------
CN=user1,CN=Users,DC=dev,DC=testlab,DC=local

.INPUTS

String

.OUTPUTS

PowerView.User

Custom PSObject with translated user property fields.

PowerView.User.Raw

The raw DirectoryServices.SearchResult object, if -Raw is enabled.
#>

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
        $UACValueNames = [Enum]::GetNames($UACEnum)
        # add in the negations
        $UACValueNames = $UACValueNames | ForEach-Object {$_; "NOT_$_"}
        # create new dynamic parameter
        New-DynamicParameter -Name UACFilter -ValidateSet $UACValueNames -Type ([array])
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
        #bind dynamic parameter to a friendly variable
        if ($PSBoundParameters -and ($PSBoundParameters.Count -ne 0)) {
            New-DynamicParameter -CreateVariables -BoundParameters $PSBoundParameters
        }

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
                        # if a -Domain isn't explicitly set, extract the object domain out of the distinguishedname
                        #   and rebuild the domain searcher
                        $IdentityDomain = $IdentityInstance.SubString($IdentityInstance.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        Write-Verbose "[Get-AdaptDomainUser] Extracted domain '$IdentityDomain' from '$IdentityInstance'"
                        $SearcherArguments['Domain'] = $IdentityDomain
                        $UserSearcher = Get-DomainSearcher @SearcherArguments
                        if (-not $UserSearcher) {
                            Write-Warning "[Get-AdaptDomainUser] Unable to retrieve domain searcher for '$IdentityDomain'"
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
                        Write-Verbose "[Get-AdaptDomainUser] Extracted domain '$UserDomain' from '$IdentityInstance'"
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
                Write-Verbose '[Get-AdaptDomainUser] Searching for non-null service principal names'
                $Filter += '(servicePrincipalName=*)'
            }
            if ($PSBoundParameters['AllowDelegation']) {
                Write-Verbose '[Get-AdaptDomainUser] Searching for users who can be delegated'
                # negation of "Accounts that are sensitive and not trusted for delegation"
                $Filter += '(!(userAccountControl:1.2.840.113556.1.4.803:=1048574))'
            }
            if ($PSBoundParameters['DisallowDelegation']) {
                Write-Verbose '[Get-AdaptDomainUser] Searching for users who are sensitive and not trusted for delegation'
                $Filter += '(userAccountControl:1.2.840.113556.1.4.803:=1048574)'
            }
            if ($PSBoundParameters['AdminCount']) {
                Write-Verbose '[Get-AdaptDomainUser] Searching for adminCount=1'
                $Filter += '(admincount=1)'
            }
            if ($PSBoundParameters['TrustedToAuth']) {
                Write-Verbose '[Get-AdaptDomainUser] Searching for users that are trusted to authenticate for other principals'
                $Filter += '(msds-allowedtodelegateto=*)'
            }
            if ($PSBoundParameters['PreauthNotRequired']) {
                Write-Verbose '[Get-AdaptDomainUser] Searching for user accounts that do not require kerberos preauthenticate'
                $Filter += '(userAccountControl:1.2.840.113556.1.4.803:=4194304)'
            }
            if ($PSBoundParameters['LDAPFilter']) {
                Write-Verbose "[Get-AdaptDomainUser] Using additional LDAP filter: $LDAPFilter"
                $Filter += "$LDAPFilter"
            }

            # build the LDAP filter for the dynamic UAC filter value
            $UACFilter | Where-Object {$_} | ForEach-Object {
                if ($_ -match 'NOT_.*') {
                    $UACField = $_.Substring(4)
                    $UACValue = [Int]($UACEnum::$UACField)
                    $Filter += "(!(userAccountControl:1.2.840.113556.1.4.803:=$UACValue))"
                }
                else {
                    $UACValue = [Int]($UACEnum::$_)
                    $Filter += "(userAccountControl:1.2.840.113556.1.4.803:=$UACValue)"
                }
            }

            $UserSearcher.filter = "(&(samAccountType=805306368)$Filter)"
            Write-Verbose "[Get-AdaptDomainUser] filter string: $($UserSearcher.filter)"

            if ($PSBoundParameters['FindOne']) { $Results = $UserSearcher.FindOne() }
            else { $Results = $UserSearcher.FindAll() }
            $Results | Where-Object {$_} | ForEach-Object {
                if ($PSBoundParameters['Raw']) {
                    # return raw result objects
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
                    Write-Verbose "[Get-AdaptDomainUser] Error disposing of the Results object: $_"
                }
            }
            $UserSearcher.dispose()
        }
    }
}

# --- Get-AdaptNetLoggedon (dependency) ---
function Get-AdaptNetLoggedon {
<#
.SYNOPSIS

Returns users logged on the local (or a remote) machine.
Note: administrative rights needed for newer Windows OSes.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: PSReflect, Invoke-UserImpersonation, Invoke-RevertToSelf  

.DESCRIPTION

This function will execute the NetWkstaUserEnum Win32API call to query
a given host for actively logged on users.

.PARAMETER ComputerName

Specifies the hostname to query for logged on users (also accepts IP addresses).
Defaults to 'localhost'.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the remote system using Invoke-UserImpersonation.

.EXAMPLE

Get-AdaptNetLoggedon

Returns users actively logged onto the local host.

.EXAMPLE

Get-AdaptNetLoggedon -ComputerName sqlserver

Returns users actively logged onto the 'sqlserver' host.

.EXAMPLE

Get-AdaptDomainComputer | Get-AdaptNetLoggedon

Returns all logged on users for all computers in the domain.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-AdaptNetLoggedon -ComputerName sqlserver -Credential $Cred

.OUTPUTS

PowerView.LoggedOnUserInfo

A PSCustomObject representing a WKSTA_USER_INFO_1 structure, including
the UserName/LogonDomain/AuthDomains/LogonServer for each user, with the ComputerName added.

.LINK

http://www.powershellmagazine.com/2014/09/25/easily-defining-enums-structs-and-win32-functions-in-memory/
#>

    [OutputType('PowerView.LoggedOnUserInfo')]
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

    BEGIN {
        if ($PSBoundParameters['Credential']) {
            $LogonToken = Invoke-UserImpersonation -Credential $Credential
        }
    }

    PROCESS {
        ForEach ($Computer in $ComputerName) {
            # declare the reference variables
            $QueryLevel = 1
            $PtrInfo = [IntPtr]::Zero
            $EntriesRead = 0
            $TotalRead = 0
            $ResumeHandle = 0

            # get logged on user information
            $Result = $Netapi32::NetWkstaUserEnum($Computer, $QueryLevel, [ref]$PtrInfo, -1, [ref]$EntriesRead, [ref]$TotalRead, [ref]$ResumeHandle)

            # locate the offset of the initial intPtr
            $Offset = $PtrInfo.ToInt64()

            # 0 = success
            if (($Result -eq 0) -and ($Offset -gt 0)) {

                # work out how much to increment the pointer by finding out the size of the structure
                $Increment = $WKSTA_USER_INFO_1::GetSize()

                # parse all the result structures
                for ($i = 0; ($i -lt $EntriesRead); $i++) {
                    # create a new int ptr at the given offset and cast the pointer as our result structure
                    $NewIntPtr = New-Object System.Intptr -ArgumentList $Offset
                    $Info = $NewIntPtr -as $WKSTA_USER_INFO_1

                    # return all the sections of the structure - have to do it this way for V2
                    $LoggedOn = $Info | Select-Object *
                    $LoggedOn | Add-Member Noteproperty 'ComputerName' $Computer
                    $LoggedOn.PSObject.TypeNames.Insert(0, 'PowerView.LoggedOnUserInfo')
                    $Offset = $NewIntPtr.ToInt64()
                    $Offset += $Increment
                    $LoggedOn
                }

                # free up the result buffer
                $Null = $Netapi32::NetApiBufferFree($PtrInfo)
            }
            else {
                Write-Verbose "[Get-AdaptNetLoggedon] Error: $(([ComponentModel.Win32Exception] $Result).Message)"
            }
        }
    }

    END {
        if ($LogonToken) {
            Invoke-RevertToSelf -TokenHandle $LogonToken
        }
    }
}

# --- Get-AdaptNetSession (dependency) ---
function Get-AdaptNetSession {
<#
.SYNOPSIS

Returns session information for the local (or a remote) machine.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: PSReflect, Invoke-UserImpersonation, Invoke-RevertToSelf  

.DESCRIPTION

This function will execute the NetSessionEnum Win32API call to query
a given host for active sessions.

.PARAMETER ComputerName

Specifies the hostname to query for sessions (also accepts IP addresses).
Defaults to 'localhost'.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the remote system using Invoke-UserImpersonation.

.EXAMPLE

Get-AdaptNetSession

Returns active sessions on the local host.

.EXAMPLE

Get-AdaptNetSession -ComputerName sqlserver

Returns active sessions on the 'sqlserver' host.

.EXAMPLE

Get-AdaptDomainController | Get-AdaptNetSession

Returns active sessions on all domain controllers.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-AdaptNetSession -ComputerName sqlserver -Credential $Cred

.OUTPUTS

PowerView.SessionInfo

A PSCustomObject representing a WKSTA_USER_INFO_1 structure, including
the CName/UserName/Time/IdleTime for each session, with the ComputerName added.

.LINK

http://www.powershellmagazine.com/2014/09/25/easily-defining-enums-structs-and-win32-functions-in-memory/
#>

    [OutputType('PowerView.SessionInfo')]
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

    BEGIN {
        if ($PSBoundParameters['Credential']) {
            $LogonToken = Invoke-UserImpersonation -Credential $Credential
        }
    }

    PROCESS {
        ForEach ($Computer in $ComputerName) {
            # arguments for NetSessionEnum
            $QueryLevel = 10
            $PtrInfo = [IntPtr]::Zero
            $EntriesRead = 0
            $TotalRead = 0
            $ResumeHandle = 0

            # get session information
            $Result = $Netapi32::NetSessionEnum($Computer, '', $UserName, $QueryLevel, [ref]$PtrInfo, -1, [ref]$EntriesRead, [ref]$TotalRead, [ref]$ResumeHandle)

            # locate the offset of the initial intPtr
            $Offset = $PtrInfo.ToInt64()

            # 0 = success
            if (($Result -eq 0) -and ($Offset -gt 0)) {

                # work out how much to increment the pointer by finding out the size of the structure
                $Increment = $SESSION_INFO_10::GetSize()

                # parse all the result structures
                for ($i = 0; ($i -lt $EntriesRead); $i++) {
                    # create a new int ptr at the given offset and cast the pointer as our result structure
                    $NewIntPtr = New-Object System.Intptr -ArgumentList $Offset
                    $Info = $NewIntPtr -as $SESSION_INFO_10

                    # return all the sections of the structure - have to do it this way for V2
                    $Session = $Info | Select-Object *
                    $Session | Add-Member Noteproperty 'ComputerName' $Computer
                    $Session.PSObject.TypeNames.Insert(0, 'PowerView.SessionInfo')
                    $Offset = $NewIntPtr.ToInt64()
                    $Offset += $Increment
                    $Session
                }

                # free up the result buffer
                $Null = $Netapi32::NetApiBufferFree($PtrInfo)
            }
            else {
                Write-Verbose "[Get-AdaptNetSession] Error: $(([ComponentModel.Win32Exception] $Result).Message)"
            }
        }
    }


    END {
        if ($LogonToken) {
            Invoke-RevertToSelf -TokenHandle $LogonToken
        }
    }
}

# --- New-AdaptThreadedFunction (dependency) ---
function New-AdaptThreadedFunction {
    # Helper used by any threaded host enumeration functions
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [String[]]
        $ComputerName,

        [Parameter(Position = 1, Mandatory = $True)]
        [System.Management.Automation.ScriptBlock]
        $ScriptBlock,

        [Parameter(Position = 2)]
        [Hashtable]
        $ScriptParameters,

        [Int]
        [ValidateRange(1,  100)]
        $Threads = 20,

        [Switch]
        $NoImports
    )

    BEGIN {
        # Adapted from:
        #   http://powershell.org/wp/forums/topic/invpke-parallel-need-help-to-clone-the-current-runspace/
        $SessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()

        # # $SessionState.ApartmentState = [System.Threading.Thread]::CurrentThread.GetApartmentState()
        # force a single-threaded apartment state (for token-impersonation stuffz)
        $SessionState.ApartmentState = [System.Threading.ApartmentState]::STA

        # import the current session state's variables and functions so the chained PowerView
        #   functionality can be used by the threaded blocks
        if (-not $NoImports) {
            # grab all the current variables for this runspace
            $MyVars = Get-Variable -Scope 2

            # these Variables are added by Runspace.Open() Method and produce Stop errors if you add them twice
            $VorbiddenVars = @('?','args','ConsoleFileName','Error','ExecutionContext','false','HOME','Host','input','InputObject','MaximumAliasCount','MaximumDriveCount','MaximumErrorCount','MaximumFunctionCount','MaximumHistoryCount','MaximumVariableCount','MyInvocation','null','PID','PSBoundParameters','PSCommandPath','PSCulture','PSDefaultParameterValues','PSHOME','PSScriptRoot','PSUICulture','PSVersionTable','PWD','ShellId','SynchronizedHash','true')

            # add Variables from Parent Scope (current runspace) into the InitialSessionState
            ForEach ($Var in $MyVars) {
                if ($VorbiddenVars -NotContains $Var.Name) {
                $SessionState.Variables.Add((New-Object -TypeName System.Management.Automation.Runspaces.SessionStateVariableEntry -ArgumentList $Var.name,$Var.Value,$Var.description,$Var.options,$Var.attributes))
                }
            }

            # add Functions from current runspace to the InitialSessionState
            ForEach ($Function in (Get-ChildItem Function:)) {
                $SessionState.Commands.Add((New-Object -TypeName System.Management.Automation.Runspaces.SessionStateFunctionEntry -ArgumentList $Function.Name, $Function.Definition))
            }
        }

        # threading adapted from
        # https://github.com/darkoperator/Posh-SecMod/blob/master/Discovery/Discovery.psm1#L407
        #   Thanks Carlos!

        # create a pool of maxThread runspaces
        $Pool = [RunspaceFactory]::CreateRunspacePool(1, $Threads, $SessionState, $Host)
        $Pool.Open()

        # do some trickery to get the proper BeginInvoke() method that allows for an output queue
        $Method = $Null
        ForEach ($M in [PowerShell].GetMethods() | Where-Object { $_.Name -eq 'BeginInvoke' }) {
            $MethodParameters = $M.GetParameters()
            if (($MethodParameters.Count -eq 2) -and $MethodParameters[0].Name -eq 'input' -and $MethodParameters[1].Name -eq 'output') {
                $Method = $M.MakeGenericMethod([Object], [Object])
                break
            }
        }

        $Jobs = @()
        $ComputerName = $ComputerName | Where-Object {$_ -and $_.Trim()}
        Write-Verbose "[New-AdaptThreadedFunction] Total number of hosts: $($ComputerName.count)"

        # partition all hosts from -ComputerName into $Threads number of groups
        if ($Threads -ge $ComputerName.Length) {
            $Threads = $ComputerName.Length
        }
        $ElementSplitSize = [Int]($ComputerName.Length/$Threads)
        $ComputerNamePartitioned = @()
        $Start = 0
        $End = $ElementSplitSize

        for($i = 1; $i -le $Threads; $i++) {
            $List = New-Object System.Collections.ArrayList
            if ($i -eq $Threads) {
                $End = $ComputerName.Length
            }
            $List.AddRange($ComputerName[$Start..($End-1)])
            $Start += $ElementSplitSize
            $End += $ElementSplitSize
            $ComputerNamePartitioned += @(,@($List.ToArray()))
        }

        Write-Verbose "[New-AdaptThreadedFunction] Total number of threads/partitions: $Threads"

        ForEach ($ComputerNamePartition in $ComputerNamePartitioned) {
            # create a "powershell pipeline runner"
            $PowerShell = [PowerShell]::Create()
            $PowerShell.runspacepool = $Pool

            # add the script block + arguments with the given computer partition
            $Null = $PowerShell.AddScript($ScriptBlock).AddParameter('ComputerName', $ComputerNamePartition)
            if ($ScriptParameters) {
                ForEach ($Param in $ScriptParameters.GetEnumerator()) {
                    $Null = $PowerShell.AddParameter($Param.Name, $Param.Value)
                }
            }

            # create the output queue
            $Output = New-Object Management.Automation.PSDataCollection[Object]

            # kick off execution using the BeginInvok() method that allows queues
            $Jobs += @{
                PS = $PowerShell
                Output = $Output
                Result = $Method.Invoke($PowerShell, @($Null, [Management.Automation.PSDataCollection[Object]]$Output))
            }
        }
    }

    END {
        Write-Verbose "[New-AdaptThreadedFunction] Threads executing"

        # continuously loop through each job queue, consuming output as appropriate
        Do {
            ForEach ($Job in $Jobs) {
                $Job.Output.ReadAll()
            }
            Start-Sleep -Seconds 1
        }
        While (($Jobs | Where-Object { -not $_.Result.IsCompleted }).Count -gt 0)

        $SleepSeconds = 100
        Write-Verbose "[New-AdaptThreadedFunction] Waiting $SleepSeconds seconds for final cleanup..."

        # cleanup- make sure we didn't miss anything
        for ($i=0; $i -lt $SleepSeconds; $i++) {
            ForEach ($Job in $Jobs) {
                $Job.Output.ReadAll()
                $Job.PS.Dispose()
            }
            Start-Sleep -S 1
        }

        $Pool.Dispose()
        Write-Verbose "[New-AdaptThreadedFunction] all threads completed"
    }
}

# --- Test-AdaptAdminAccess (dependency) ---
function Test-AdaptAdminAccess {
<#
.SYNOPSIS

Tests if the current user has administrative access to the local (or a remote) machine.

Idea stolen from the local_admin_search_enum post module in Metasploit written by:  
    'Brandon McCann "zeknox" <bmccann[at]accuvant.com>'  
    'Thomas McCarthy "smilingraccoon" <smilingraccoon[at]gmail.com>'  
    'Royce Davis "r3dy" <rdavis[at]accuvant.com>'  

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: PSReflect, Invoke-UserImpersonation, Invoke-RevertToSelf  

.DESCRIPTION

This function will use the OpenSCManagerW Win32API call to establish
a handle to the remote host. If this succeeds, the current user context
has local administrator acess to the target.

.PARAMETER ComputerName

Specifies the hostname to check for local admin access (also accepts IP addresses).
Defaults to 'localhost'.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the remote system using Invoke-UserImpersonation.

.EXAMPLE

Test-AdaptAdminAccess -ComputerName sqlserver

Returns results indicating whether the current user has admin access to the 'sqlserver' host.

.EXAMPLE

Get-AdaptDomainComputer | Test-AdaptAdminAccess

Returns what machines in the domain the current user has access to.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Test-AdaptAdminAccess -ComputerName sqlserver -Credential $Cred

.OUTPUTS

PowerView.AdminAccess

A PSCustomObject containing the ComputerName and 'IsAdmin' set to whether
the current user has local admin rights, along with the ComputerName added.

.LINK

https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/local_admin_search_enum.rb
http://www.powershellmagazine.com/2014/09/25/easily-defining-enums-structs-and-win32-functions-in-memory/
#>

    [OutputType('PowerView.AdminAccess')]
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

    BEGIN {
        if ($PSBoundParameters['Credential']) {
            $LogonToken = Invoke-UserImpersonation -Credential $Credential
        }
    }

    PROCESS {
        ForEach ($Computer in $ComputerName) {
            # 0xF003F - SC_MANAGER_ALL_ACCESS
            #   http://msdn.microsoft.com/en-us/library/windows/desktop/ms685981(v=vs.85).aspx
            $Handle = $Advapi32::OpenSCManagerW("\\$Computer", 'ServicesActive', 0xF003F);$LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

            $IsAdmin = New-Object PSObject
            $IsAdmin | Add-Member Noteproperty 'ComputerName' $Computer

            # if we get a non-zero handle back, everything was successful
            if ($Handle -ne 0) {
                $Null = $Advapi32::CloseServiceHandle($Handle)
                $IsAdmin | Add-Member Noteproperty 'IsAdmin' $True
            }
            else {
                Write-Verbose "[Test-AdaptAdminAccess] Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
                $IsAdmin | Add-Member Noteproperty 'IsAdmin' $False
            }
            $IsAdmin.PSObject.TypeNames.Insert(0, 'PowerView.AdminAccess')
            $IsAdmin
        }
    }

    END {
        if ($LogonToken) {
            Invoke-RevertToSelf -TokenHandle $LogonToken
        }
    }
}

# --- Main Function: Find-AdaptDomainUserLocation ---
function Find-AdaptDomainUserLocation {
<#
.SYNOPSIS

Finds domain machines where specific users are logged into.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-AdaptDomainFileServer, Get-AdaptDomainDFSShare, Get-AdaptDomainController, Get-AdaptDomainComputer, Get-AdaptDomainUser, Get-AdaptDomainGroupMember, Invoke-UserImpersonation, Invoke-RevertToSelf, Get-AdaptNetSession, Test-AdaptAdminAccess, Get-AdaptNetLoggedon, Resolve-IPAddress, New-AdaptThreadedFunction  

.DESCRIPTION

This function enumerates all machines on the current (or specified) domain
using Get-AdaptDomainComputer, and queries the domain for users of a specified group
(default 'Domain Admins') with Get-AdaptDomainGroupMember. Then for each server the
function enumerates any active user sessions with Get-AdaptNetSession/Get-AdaptNetLoggedon
The found user list is compared against the target list, and any matches are
displayed. If -ShowAll is specified, all results are displayed instead of
the filtered set. If -Stealth is specified, then likely highly-trafficed servers
are enumerated with Get-AdaptDomainFileServer/Get-AdaptDomainController, and session
enumeration is executed only against those servers. If -Credential is passed,
then Invoke-UserImpersonation is used to impersonate the specified user
before enumeration, reverting after with Invoke-RevertToSelf.

.PARAMETER ComputerName

Specifies an array of one or more hosts to enumerate, passable on the pipeline.
If -ComputerName is not passed, the default behavior is to enumerate all machines
in the domain returned by Get-AdaptDomainComputer.

.PARAMETER Domain

Specifies the domain to query for computers AND users, defaults to the current domain.

.PARAMETER ComputerDomain

Specifies the domain to query for computers, defaults to the current domain.

.PARAMETER ComputerLDAPFilter

Specifies an LDAP query string that is used to search for computer objects.

.PARAMETER ComputerSearchBase

Specifies the LDAP source to search through for computers,
e.g. "LDAP://OU=secret,DC=testlab,DC=local". Useful for OU queries.

.PARAMETER ComputerUnconstrained

Switch. Search computer objects that have unconstrained delegation.

.PARAMETER ComputerOperatingSystem

Search computers with a specific operating system, wildcards accepted.

.PARAMETER ComputerServicePack

Search computers with a specific service pack, wildcards accepted.

.PARAMETER ComputerSiteName

Search computers in the specific AD Site name, wildcards accepted.

.PARAMETER UserIdentity

Specifies one or more user identities to search for.

.PARAMETER UserDomain

Specifies the domain to query for users to search for, defaults to the current domain.

.PARAMETER UserLDAPFilter

Specifies an LDAP query string that is used to search for target users.

.PARAMETER UserSearchBase

Specifies the LDAP source to search through for target users.
e.g. "LDAP://OU=secret,DC=testlab,DC=local". Useful for OU queries.

.PARAMETER UserGroupIdentity

Specifies a group identity to query for target users, defaults to 'Domain Admins.
If any other user specifications are set, then UserGroupIdentity is ignored.

.PARAMETER UserAdminCount

Switch. Search for users users with '(adminCount=1)' (meaning are/were privileged).

.PARAMETER UserAllowDelegation

Switch. Search for user accounts that are not marked as 'sensitive and not allowed for delegation'.

.PARAMETER CheckAccess

Switch. Check if the current user has local admin access to computers where target users are found.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under for computers, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain and target systems.

.PARAMETER StopOnSuccess

Switch. Stop hunting after finding after finding a target user.

.PARAMETER Delay

Specifies the delay (in seconds) between enumerating hosts, defaults to 0.

.PARAMETER Jitter

Specifies the jitter (0-1.0) to apply to any specified -Delay, defaults to +/- 0.3

.PARAMETER ShowAll

Switch. Return all user location results instead of filtering based on target
specifications.

.PARAMETER Stealth

Switch. Only enumerate sessions from connonly used target servers.

.PARAMETER StealthSource

The source of target servers to use, 'DFS' (distributed file servers),
'DC' (domain controllers), 'File' (file servers), or 'All' (the default).

.PARAMETER Threads

The number of threads to use for user searching, defaults to 20.

.EXAMPLE

Find-AdaptDomainUserLocation

Searches for 'Domain Admins' by enumerating every computer in the domain.

.EXAMPLE

Find-AdaptDomainUserLocation -Stealth -ShowAll

Enumerates likely highly-trafficked servers, performs just session enumeration
against each, and outputs all results.

.EXAMPLE

Find-AdaptDomainUserLocation -UserAdminCount -ComputerOperatingSystem 'Windows 7*' -Domain dev.testlab.local

Enumerates Windows 7 computers in dev.testlab.local and returns user results for privileged
users in dev.testlab.local.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Find-AdaptDomainUserLocation -Domain testlab.local -Credential $Cred

Searches for domain admin locations in the testlab.local using the specified alternate credentials.

.OUTPUTS

PowerView.UserLocation
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.UserLocation')]
    [CmdletBinding(DefaultParameterSetName = 'UserGroupIdentity')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DNSHostName')]
        [String[]]
        $ComputerName,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerDomain,

        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerLDAPFilter,

        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerSearchBase,

        [Alias('Unconstrained')]
        [Switch]
        $ComputerUnconstrained,

        [ValidateNotNullOrEmpty()]
        [Alias('OperatingSystem')]
        [String]
        $ComputerOperatingSystem,

        [ValidateNotNullOrEmpty()]
        [Alias('ServicePack')]
        [String]
        $ComputerServicePack,

        [ValidateNotNullOrEmpty()]
        [Alias('SiteName')]
        [String]
        $ComputerSiteName,

        [Parameter(ParameterSetName = 'UserIdentity')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $UserIdentity,

        [ValidateNotNullOrEmpty()]
        [String]
        $UserDomain,

        [ValidateNotNullOrEmpty()]
        [String]
        $UserLDAPFilter,

        [ValidateNotNullOrEmpty()]
        [String]
        $UserSearchBase,

        [Parameter(ParameterSetName = 'UserGroupIdentity')]
        [ValidateNotNullOrEmpty()]
        [Alias('GroupName', 'Group')]
        [String[]]
        $UserGroupIdentity = 'Domain Admins',

        [Alias('AdminCount')]
        [Switch]
        $UserAdminCount,

        [Alias('AllowDelegation')]
        [Switch]
        $UserAllowDelegation,

        [Switch]
        $CheckAccess,

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
        $Credential = [Management.Automation.PSCredential]::Empty,

        [Switch]
        $StopOnSuccess,

        [ValidateRange(1, 10000)]
        [Int]
        $Delay = 0,

        [ValidateRange(0.0, 1.0)]
        [Double]
        $Jitter = .3,

        [Parameter(ParameterSetName = 'ShowAll')]
        [Switch]
        $ShowAll,

        [Switch]
        $Stealth,

        [String]
        [ValidateSet('DFS', 'DC', 'File', 'All')]
        $StealthSource = 'All',

        [Int]
        [ValidateRange(1, 100)]
        $Threads = 20
    )

    BEGIN {

        $ComputerSearcherArguments = @{
            'Properties' = 'dnshostname'
        }
        if ($PSBoundParameters['Domain']) { $ComputerSearcherArguments['Domain'] = $Domain }
        if ($PSBoundParameters['ComputerDomain']) { $ComputerSearcherArguments['Domain'] = $ComputerDomain }
        if ($PSBoundParameters['ComputerLDAPFilter']) { $ComputerSearcherArguments['LDAPFilter'] = $ComputerLDAPFilter }
        if ($PSBoundParameters['ComputerSearchBase']) { $ComputerSearcherArguments['SearchBase'] = $ComputerSearchBase }
        if ($PSBoundParameters['Unconstrained']) { $ComputerSearcherArguments['Unconstrained'] = $Unconstrained }
        if ($PSBoundParameters['ComputerOperatingSystem']) { $ComputerSearcherArguments['OperatingSystem'] = $OperatingSystem }
        if ($PSBoundParameters['ComputerServicePack']) { $ComputerSearcherArguments['ServicePack'] = $ServicePack }
        if ($PSBoundParameters['ComputerSiteName']) { $ComputerSearcherArguments['SiteName'] = $SiteName }
        if ($PSBoundParameters['Server']) { $ComputerSearcherArguments['Server'] = $Server }
        if ($PSBoundParameters['SearchScope']) { $ComputerSearcherArguments['SearchScope'] = $SearchScope }
        if ($PSBoundParameters['ResultPageSize']) { $ComputerSearcherArguments['ResultPageSize'] = $ResultPageSize }
        if ($PSBoundParameters['ServerTimeLimit']) { $ComputerSearcherArguments['ServerTimeLimit'] = $ServerTimeLimit }
        if ($PSBoundParameters['Tombstone']) { $ComputerSearcherArguments['Tombstone'] = $Tombstone }
        if ($PSBoundParameters['Credential']) { $ComputerSearcherArguments['Credential'] = $Credential }

        $UserSearcherArguments = @{
            'Properties' = 'samaccountname'
        }
        if ($PSBoundParameters['UserIdentity']) { $UserSearcherArguments['Identity'] = $UserIdentity }
        if ($PSBoundParameters['Domain']) { $UserSearcherArguments['Domain'] = $Domain }
        if ($PSBoundParameters['UserDomain']) { $UserSearcherArguments['Domain'] = $UserDomain }
        if ($PSBoundParameters['UserLDAPFilter']) { $UserSearcherArguments['LDAPFilter'] = $UserLDAPFilter }
        if ($PSBoundParameters['UserSearchBase']) { $UserSearcherArguments['SearchBase'] = $UserSearchBase }
        if ($PSBoundParameters['UserAdminCount']) { $UserSearcherArguments['AdminCount'] = $UserAdminCount }
        if ($PSBoundParameters['UserAllowDelegation']) { $UserSearcherArguments['AllowDelegation'] = $UserAllowDelegation }
        if ($PSBoundParameters['Server']) { $UserSearcherArguments['Server'] = $Server }
        if ($PSBoundParameters['SearchScope']) { $UserSearcherArguments['SearchScope'] = $SearchScope }
        if ($PSBoundParameters['ResultPageSize']) { $UserSearcherArguments['ResultPageSize'] = $ResultPageSize }
        if ($PSBoundParameters['ServerTimeLimit']) { $UserSearcherArguments['ServerTimeLimit'] = $ServerTimeLimit }
        if ($PSBoundParameters['Tombstone']) { $UserSearcherArguments['Tombstone'] = $Tombstone }
        if ($PSBoundParameters['Credential']) { $UserSearcherArguments['Credential'] = $Credential }

        $TargetComputers = @()

        # first, build the set of computers to enumerate
        if ($PSBoundParameters['ComputerName']) {
            $TargetComputers = @($ComputerName)
        }
        else {
            if ($PSBoundParameters['Stealth']) {
                Write-Verbose "[Find-AdaptDomainUserLocation] Stealth enumeration using source: $StealthSource"
                $TargetComputerArrayList = New-Object System.Collections.ArrayList

                if ($StealthSource -match 'File|All') {
                    Write-Verbose '[Find-AdaptDomainUserLocation] Querying for file servers'
                    $FileServerSearcherArguments = @{}
                    if ($PSBoundParameters['Domain']) { $FileServerSearcherArguments['Domain'] = $Domain }
                    if ($PSBoundParameters['ComputerDomain']) { $FileServerSearcherArguments['Domain'] = $ComputerDomain }
                    if ($PSBoundParameters['ComputerSearchBase']) { $FileServerSearcherArguments['SearchBase'] = $ComputerSearchBase }
                    if ($PSBoundParameters['Server']) { $FileServerSearcherArguments['Server'] = $Server }
                    if ($PSBoundParameters['SearchScope']) { $FileServerSearcherArguments['SearchScope'] = $SearchScope }
                    if ($PSBoundParameters['ResultPageSize']) { $FileServerSearcherArguments['ResultPageSize'] = $ResultPageSize }
                    if ($PSBoundParameters['ServerTimeLimit']) { $FileServerSearcherArguments['ServerTimeLimit'] = $ServerTimeLimit }
                    if ($PSBoundParameters['Tombstone']) { $FileServerSearcherArguments['Tombstone'] = $Tombstone }
                    if ($PSBoundParameters['Credential']) { $FileServerSearcherArguments['Credential'] = $Credential }
                    $FileServers = Get-AdaptDomainFileServer @FileServerSearcherArguments
                    if ($FileServers -isnot [System.Array]) { $FileServers = @($FileServers) }
                    $TargetComputerArrayList.AddRange( $FileServers )
                }
                if ($StealthSource -match 'DFS|All') {
                    Write-Verbose '[Find-AdaptDomainUserLocation] Querying for DFS servers'
                    # # TODO: fix the passed parameters to Get-AdaptDomainDFSShare
                    # $ComputerName += Get-AdaptDomainDFSShare -Domain $Domain -Server $DomainController | ForEach-Object {$_.RemoteServerName}
                }
                if ($StealthSource -match 'DC|All') {
                    Write-Verbose '[Find-AdaptDomainUserLocation] Querying for domain controllers'
                    $DCSearcherArguments = @{
                        'LDAP' = $True
                    }
                    if ($PSBoundParameters['Domain']) { $DCSearcherArguments['Domain'] = $Domain }
                    if ($PSBoundParameters['ComputerDomain']) { $DCSearcherArguments['Domain'] = $ComputerDomain }
                    if ($PSBoundParameters['Server']) { $DCSearcherArguments['Server'] = $Server }
                    if ($PSBoundParameters['Credential']) { $DCSearcherArguments['Credential'] = $Credential }
                    $DomainControllers = Get-AdaptDomainController @DCSearcherArguments | Select-Object -ExpandProperty dnshostname
                    if ($DomainControllers -isnot [System.Array]) { $DomainControllers = @($DomainControllers) }
                    $TargetComputerArrayList.AddRange( $DomainControllers )
                }
                $TargetComputers = $TargetComputerArrayList.ToArray()
            }
            else {
                Write-Verbose '[Find-AdaptDomainUserLocation] Querying for all computers in the domain'
                $TargetComputers = Get-AdaptDomainComputer @ComputerSearcherArguments | Select-Object -ExpandProperty dnshostname
            }
        }
        Write-Verbose "[Find-AdaptDomainUserLocation] TargetComputers length: $($TargetComputers.Length)"
        if ($TargetComputers.Length -eq 0) {
            throw '[Find-AdaptDomainUserLocation] No hosts found to enumerate'
        }

        # get the current user so we can ignore it in the results
        if ($PSBoundParameters['Credential']) {
            $CurrentUser = $Credential.GetNetworkCredential().UserName
        }
        else {
            $CurrentUser = ([Environment]::UserName).ToLower()
        }

        # now build the user target set
        if ($PSBoundParameters['ShowAll']) {
            $TargetUsers = @()
        }
        elseif ($PSBoundParameters['UserIdentity'] -or $PSBoundParameters['UserLDAPFilter'] -or $PSBoundParameters['UserSearchBase'] -or $PSBoundParameters['UserAdminCount'] -or $PSBoundParameters['UserAllowDelegation']) {
            $TargetUsers = Get-AdaptDomainUser @UserSearcherArguments | Select-Object -ExpandProperty samaccountname
        }
        else {
            $GroupSearcherArguments = @{
                'Identity' = $UserGroupIdentity
                'Recurse' = $True
            }
            if ($PSBoundParameters['UserDomain']) { $GroupSearcherArguments['Domain'] = $UserDomain }
            if ($PSBoundParameters['UserSearchBase']) { $GroupSearcherArguments['SearchBase'] = $UserSearchBase }
            if ($PSBoundParameters['Server']) { $GroupSearcherArguments['Server'] = $Server }
            if ($PSBoundParameters['SearchScope']) { $GroupSearcherArguments['SearchScope'] = $SearchScope }
            if ($PSBoundParameters['ResultPageSize']) { $GroupSearcherArguments['ResultPageSize'] = $ResultPageSize }
            if ($PSBoundParameters['ServerTimeLimit']) { $GroupSearcherArguments['ServerTimeLimit'] = $ServerTimeLimit }
            if ($PSBoundParameters['Tombstone']) { $GroupSearcherArguments['Tombstone'] = $Tombstone }
            if ($PSBoundParameters['Credential']) { $GroupSearcherArguments['Credential'] = $Credential }
            $TargetUsers = Get-AdaptDomainGroupMember @GroupSearcherArguments | Select-Object -ExpandProperty MemberName
        }

        Write-Verbose "[Find-AdaptDomainUserLocation] TargetUsers length: $($TargetUsers.Length)"
        if ((-not $ShowAll) -and ($TargetUsers.Length -eq 0)) {
            throw '[Find-AdaptDomainUserLocation] No users found to target'
        }

        # the host enumeration block we're using to enumerate all servers
        $HostEnumBlock = {
            Param($ComputerName, $TargetUsers, $CurrentUser, $Stealth, $TokenHandle)

            if ($TokenHandle) {
                # impersonate the the token produced by LogonUser()/Invoke-UserImpersonation
                $Null = Invoke-UserImpersonation -TokenHandle $TokenHandle -Quiet
            }

            ForEach ($TargetComputer in $ComputerName) {
                $Up = Test-Connection -Count 1 -Quiet -ComputerName $TargetComputer
                if ($Up) {
                    $Sessions = Get-AdaptNetSession -ComputerName $TargetComputer
                    ForEach ($Session in $Sessions) {
                        $UserName = $Session.UserName
                        $CName = $Session.CName

                        if ($CName -and $CName.StartsWith('\\')) {
                            $CName = $CName.TrimStart('\')
                        }

                        # make sure we have a result, and ignore computer$ sessions
                        if (($UserName) -and ($UserName.Trim() -ne '') -and ($UserName -notmatch $CurrentUser) -and ($UserName -notmatch '\$$')) {

                            if ( (-not $TargetUsers) -or ($TargetUsers -contains $UserName)) {
                                $UserLocation = New-Object PSObject
                                $UserLocation | Add-Member Noteproperty 'UserDomain' $Null
                                $UserLocation | Add-Member Noteproperty 'UserName' $UserName
                                $UserLocation | Add-Member Noteproperty 'ComputerName' $TargetComputer
                                $UserLocation | Add-Member Noteproperty 'SessionFrom' $CName

                                # try to resolve the DNS hostname of $Cname
                                try {
                                    $CNameDNSName = [System.Net.Dns]::GetHostEntry($CName) | Select-Object -ExpandProperty HostName
                                    $UserLocation | Add-Member NoteProperty 'SessionFromName' $CnameDNSName
                                }
                                catch {
                                    $UserLocation | Add-Member NoteProperty 'SessionFromName' $Null
                                }

                                # see if we're checking to see if we have local admin access on this machine
                                if ($CheckAccess) {
                                    $Admin = (Test-AdaptAdminAccess -ComputerName $CName).IsAdmin
                                    $UserLocation | Add-Member Noteproperty 'LocalAdmin' $Admin.IsAdmin
                                }
                                else {
                                    $UserLocation | Add-Member Noteproperty 'LocalAdmin' $Null
                                }
                                $UserLocation.PSObject.TypeNames.Insert(0, 'PowerView.UserLocation')
                                $UserLocation
                            }
                        }
                    }
                    if (-not $Stealth) {
                        # if we're not 'stealthy', enumerate loggedon users as well
                        $LoggedOn = Get-AdaptNetLoggedon -ComputerName $TargetComputer
                        ForEach ($User in $LoggedOn) {
                            $UserName = $User.UserName
                            $UserDomain = $User.LogonDomain

                            # make sure wet have a result
                            if (($UserName) -and ($UserName.trim() -ne '')) {
                                if ( (-not $TargetUsers) -or ($TargetUsers -contains $UserName) -and ($UserName -notmatch '\$$')) {
                                    $IPAddress = @(Resolve-IPAddress -ComputerName $TargetComputer)[0].IPAddress
                                    $UserLocation = New-Object PSObject
                                    $UserLocation | Add-Member Noteproperty 'UserDomain' $UserDomain
                                    $UserLocation | Add-Member Noteproperty 'UserName' $UserName
                                    $UserLocation | Add-Member Noteproperty 'ComputerName' $TargetComputer
                                    $UserLocation | Add-Member Noteproperty 'IPAddress' $IPAddress
                                    $UserLocation | Add-Member Noteproperty 'SessionFrom' $Null
                                    $UserLocation | Add-Member Noteproperty 'SessionFromName' $Null

                                    # see if we're checking to see if we have local admin access on this machine
                                    if ($CheckAccess) {
                                        $Admin = Test-AdaptAdminAccess -ComputerName $TargetComputer
                                        $UserLocation | Add-Member Noteproperty 'LocalAdmin' $Admin.IsAdmin
                                    }
                                    else {
                                        $UserLocation | Add-Member Noteproperty 'LocalAdmin' $Null
                                    }
                                    $UserLocation.PSObject.TypeNames.Insert(0, 'PowerView.UserLocation')
                                    $UserLocation
                                }
                            }
                        }
                    }
                }
            }

            if ($TokenHandle) {
                Invoke-RevertToSelf
            }
        }

        $LogonToken = $Null
        if ($PSBoundParameters['Credential']) {
            if ($PSBoundParameters['Delay'] -or $PSBoundParameters['StopOnSuccess']) {
                $LogonToken = Invoke-UserImpersonation -Credential $Credential
            }
            else {
                $LogonToken = Invoke-UserImpersonation -Credential $Credential -Quiet
            }
        }
    }

    PROCESS {
        # only ignore threading if -Delay is passed
        if ($PSBoundParameters['Delay'] -or $PSBoundParameters['StopOnSuccess']) {

            Write-Verbose "[Find-AdaptDomainUserLocation] Total number of hosts: $($TargetComputers.count)"
            Write-Verbose "[Find-AdaptDomainUserLocation] Delay: $Delay, Jitter: $Jitter"
            $Counter = 0
            $RandNo = New-Object System.Random

            ForEach ($TargetComputer in $TargetComputers) {
                $Counter = $Counter + 1

                # sleep for our semi-randomized interval
                Start-Sleep -Seconds $RandNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)

                Write-Verbose "[Find-AdaptDomainUserLocation] Enumerating server $Computer ($Counter of $($TargetComputers.Count))"
                Invoke-Command -ScriptBlock $HostEnumBlock -ArgumentList $TargetComputer, $TargetUsers, $CurrentUser, $Stealth, $LogonToken

                if ($Result -and $StopOnSuccess) {
                    Write-Verbose "[Find-AdaptDomainUserLocation] Target user found, returning early"
                    return
                }
            }
        }
        else {
            Write-Verbose "[Find-AdaptDomainUserLocation] Using threading with threads: $Threads"
            Write-Verbose "[Find-AdaptDomainUserLocation] TargetComputers length: $($TargetComputers.Length)"

            # if we're using threading, kick off the script block with New-AdaptThreadedFunction
            $ScriptParams = @{
                'TargetUsers' = $TargetUsers
                'CurrentUser' = $CurrentUser
                'Stealth' = $Stealth
                'TokenHandle' = $LogonToken
            }

            # if we're using threading, kick off the script block with New-AdaptThreadedFunction using the $HostEnumBlock + params
            New-AdaptThreadedFunction -ComputerName $TargetComputers -ScriptBlock $HostEnumBlock -ScriptParameters $ScriptParams -Threads $Threads
        }
    }

    END {
        if ($LogonToken) {
            Invoke-RevertToSelf -TokenHandle $LogonToken
        }
    }
}
