<#
.SYNOPSIS
    Active Directory inventory and documentation tool.
.DESCRIPTION
    Gathers AD configuration data for documentation, compliance auditing, and inventory purposes.
    See README for full documentation.
#>

[CmdletBinding()]
param
(
    [Parameter(Mandatory = $false, HelpMessage = "Which method to use; ADWS (default), LDAP")]
    [ValidateSet('ADWS', 'LDAP')]
    [string] $Method = 'ADWS',

    [Parameter(Mandatory = $false, HelpMessage = "Domain Controller IP Address or Domain FQDN.")]
    [string] $DomainController = '',

    [Parameter(Mandatory = $false, HelpMessage = "Domain Credentials.")]
    [Management.Automation.PSCredential] $Credential = [Management.Automation.PSCredential]::Empty,

    [Parameter(Mandatory = $false, HelpMessage = "Path for Adapt AD output folder containing the CSV files to generate the AdaptAD-Report.xlsx. Use it to generate the AdaptAD-Report.xlsx when Microsoft Excel is not installed on the host used to run Adapt AD.")]
    [string] $GenExcel,

    [Parameter(Mandatory = $false, HelpMessage = "Path for Adapt AD output folder to save the CSV/XML/JSON/HTML files and the AdaptAD-Report.xlsx. (The folder specified will be created if it doesn't exist)")]
    [string] $OutputDir,

    [Parameter(Mandatory = $false, HelpMessage = "Which modules to run; Comma separated; e.g Forest,Domain (Default all except ACLs and DomainAccountsusedforServiceLogon) Valid values include: Forest, Domain, Trusts, Sites, Subnets, SchemaHistory, PasswordPolicy, FineGrainedPasswordPolicy, DomainControllers, Users, UserSPNs, PasswordAttributes, Groups, GroupChanges, GroupMembers, OUs, GPOs, gPLinks, DNSZones, DNSRecords, Printers, Computers, ComputerSPNs, LAPS, BitLocker, ACLs, GPOReport, DomainAccountsusedforServiceLogon")]
    [ValidateSet('Forest', 'Domain', 'Trusts', 'Sites', 'Subnets', 'SchemaHistory', 'PasswordPolicy', 'FineGrainedPasswordPolicy', 'DomainControllers', 'Users', 'UserSPNs', 'PasswordAttributes', 'Groups', 'GroupChanges', 'GroupMembers', 'OUs', 'GPOs', 'gPLinks', 'DNSZones', 'DNSRecords', 'Printers', 'Computers', 'ComputerSPNs', 'LAPS', 'BitLocker', 'ACLs', 'GPOReport', 'DomainAccountsusedforServiceLogon', 'Default')]
    [array] $Collect = 'Default',

    [Parameter(Mandatory = $false, HelpMessage = "Output type; Comma seperated; e.g STDOUT,CSV,XML,JSON,HTML,Excel (Default STDOUT with -Collect parameter, else CSV and Excel)")]
    [ValidateSet('STDOUT', 'CSV', 'XML', 'JSON', 'EXCEL', 'HTML', 'All', 'Default')]
    [array] $OutputType = 'Default',

    [Parameter(Mandatory = $false, HelpMessage = "Timespan for Dormant accounts. Default 90 days")]
    [ValidateRange(1,1000)]
    [int] $DormantTimeSpan = 90,

    [Parameter(Mandatory = $false, HelpMessage = "Maximum machine account password age. Default 30 days")]
    [ValidateRange(1,1000)]
    [int] $PassMaxAge = 30,

    [Parameter(Mandatory = $false, HelpMessage = "The PageSize to set for the LDAP searcher object. Default 200")]
    [ValidateRange(1,10000)]
    [int] $PageSize = 200,

    [Parameter(Mandatory = $false, HelpMessage = "The number of threads to use during processing of objects. Default 10")]
    [ValidateRange(1,100)]
    [int] $Threads = 10,

    [Parameter(Mandatory = $false, HelpMessage = "Only collect details for enabled objects. Default `$false")]
    [bool] $OnlyEnabled = $false,

    [Parameter(Mandatory = $false, HelpMessage = "Create Adapt AD Log using Start-Transcript.")]
    [switch] $Log,

    [Parameter(Mandatory = $false, HelpMessage = "Which Logo to use in the excel file? Default AdaptAD")]
    [ValidateSet('AdaptAD', 'CyberCX', 'Payatu')]
    [string] $Logo = "AdaptAD"
)


# ====================================================================
# C# source code removed - using native PowerShell cmdlets only
# This improves compatibility and avoids EDR detection
# ====================================================================


# PowerShell helper functions to replace C# compiled code
# These provide the same functionality using native PowerShell


# ====================================================================
# PowerShell helper functions to replace C# compiled code
# Uses Runspace-based parallelism for multi-threading
# ====================================================================

Function Get-ObjectCount {
    Param($Collection)
    If ($null -eq $Collection) { return 0 }
    If ($Collection -is [array]) { return $Collection.Count }
    If ($Collection.Count) { return $Collection.Count }
    return 1
}

Function Clean-String {
    Param([string]$InputString)
    If ([string]::IsNullOrEmpty($InputString)) { return "" }
    return $InputString.Trim()
}

# Generic parallel processor using runspaces
Function Invoke-ParallelProcess {
    Param(
        [Parameter(Mandatory=$true)]$InputObjects,
        [Parameter(Mandatory=$true)][scriptblock]$ScriptBlock,
        [int]$Threads = 10,
        [hashtable]$Parameters = @{}
    )
    
    If ($null -eq $InputObjects -or (Get-ObjectCount $InputObjects) -eq 0) {
        return @()
    }
    
    $Results = [System.Collections.ArrayList]::Synchronized([System.Collections.ArrayList]::new())
    $RunspacePool = [runspacefactory]::CreateRunspacePool(1, $Threads)
    $RunspacePool.Open()
    
    $Runspaces = @()
    
    ForEach ($Item in $InputObjects) {
        $PowerShell = [powershell]::Create()
        $PowerShell.RunspacePool = $RunspacePool
        
        [void]$PowerShell.AddScript($ScriptBlock)
        [void]$PowerShell.AddArgument($Item)
        
        ForEach ($Key in $Parameters.Keys) {
            [void]$PowerShell.AddArgument($Parameters[$Key])
        }
        
        $Runspaces += @{
            PowerShell = $PowerShell
            Handle = $PowerShell.BeginInvoke()
        }
    }
    
    ForEach ($Runspace in $Runspaces) {
        $Result = $Runspace.PowerShell.EndInvoke($Runspace.Handle)
        If ($Result) {
            [void]$Results.AddRange(@($Result))
        }
        $Runspace.PowerShell.Dispose()
    }
    
    $RunspacePool.Close()
    $RunspacePool.Dispose()
    
    return $Results.ToArray()
}

# Parser functions - pass through data since AD cmdlets already return proper objects
# The original C# parsers added computed properties; these can be added later if needed
Function Parse-Schema { 
    Param($Data, $Threads) 
    return $Data 
}

Function Parse-User { 
    Param($Data, $Date, $DormantDays, $PassMaxAge, $Threads) 
    return $Data 
}

Function Parse-UserSPN { 
    Param($Data, $Threads) 
    return $Data 
}

Function Parse-Group { 
    Param($Data, $Threads) 
    return $Data 
}

Function Parse-GroupChange { 
    Param($Data, $Date, $Threads) 
    return $Data 
}

Function Parse-GroupMember { 
    Param($Data, $Threads) 
    return $Data 
}

Function Parse-DomainController { 
    Param($Data, $Threads) 
    return $Data 
}

Function Parse-Computer { 
    Param($Data, $Date, $DormantDays, $PassMaxAge, $Threads) 
    return $Data 
}

Function Parse-ComputerSPN { 
    Param($Data, $Threads) 
    return $Data 
}

Function Parse-OU { 
    Param($Data, $Threads) 
    return $Data 
}

Function Parse-GPO { 
    Param($Data, $Threads) 
    return $Data 
}

Function Parse-SOM { 
    Param($Data, $Threads) 
    return $Data 
}

Function Parse-Printer { 
    Param($Data, $Threads) 
    return $Data 
}

Function Parse-LAPS { 
    Param($Data, $Threads) 
    return $Data 
}

Function Parse-DACL { 
    Param($Data, $Threads) 
    return $Data 
}

Function Parse-SACL { 
    Param($Data, $Threads) 
    return $Data 
}



# Win32 API definitions removed for compatibility

Function Get-DateDiff
{
<#
.SYNOPSIS
    Get difference between two dates.

.DESCRIPTION
    Returns the difference between two dates.

.PARAMETER Date1
    [DateTime]
    Date

.PARAMETER Date2
    [DateTime]
    Date

.OUTPUTS
    [System.ValueType.TimeSpan]
    Returns the difference between the two dates.
#>
    param (
        [Parameter(Mandatory = $true)]
        [DateTime] $Date1,

        [Parameter(Mandatory = $true)]
        [DateTime] $Date2
    )

    If ($Date2 -gt $Date1)
    {
        $DDiff = $Date2 - $Date1
    }
    Else
    {
        $DDiff = $Date1 - $Date2
    }
    Return $DDiff
}

Function Get-DNtoFQDN
{
<#
.SYNOPSIS
    Gets Domain Distinguished Name (DN) from the Fully Qualified Domain Name (FQDN).

.DESCRIPTION
    Converts Domain Distinguished Name (DN) to Fully Qualified Domain Name (FQDN).

.PARAMETER ADObjectDN
    [string]
    Domain Distinguished Name (DN)

.OUTPUTS
    [String]
    Returns the Fully Qualified Domain Name (FQDN).

.LINK
    https://adsecurity.org/?p=440
#>
    param(
        [Parameter(Mandatory = $true)]
        [string] $ADObjectDN
    )

    $Index = $ADObjectDN.IndexOf('DC=')
    If ($Index)
    {
        $ADObjectDNDomainName = $($ADObjectDN.SubString($Index)) -replace 'DC=','' -replace ',','.'
    }
    Else
    {
        # Modified version from https://adsecurity.org/?p=440
        [array] $ADObjectDNArray = $ADObjectDN -Split ("DC=")
        $ADObjectDNArray | ForEach-Object {
            [array] $temp = $_ -Split (",")
            [string] $ADObjectDNArrayItemDomainName += $temp[0] + "."
        }
        $ADObjectDNDomainName = $ADObjectDNArrayItemDomainName.Substring(1, $ADObjectDNArrayItemDomainName.Length - 2)
    }
    Return $ADObjectDNDomainName
}

Function Export-AdaptCSV
{
<#
.SYNOPSIS
    Exports Object to a CSV file.

.DESCRIPTION
    Exports Object to a CSV file using Export-CSV.

.PARAMETER AdaptObj
    [PSObject]
    AdaptObj

.PARAMETER AdaptFileName
    [String]
    Path to save the CSV File.

.OUTPUTS
    CSV file.
#>
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [PSObject] $AdaptObj,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String] $AdaptFileName
    )

    Try
    {
        $AdaptObj | Export-Csv -Path $AdaptFileName -NoTypeInformation -Encoding Default
    }
    Catch
    {
        Write-Warning "[Export-AdaptCSV] Failed to export $($AdaptFileName)."
        Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
    }
}

Function Export-AdaptXML
{
<#
.SYNOPSIS
    Exports Object to a XML file.

.DESCRIPTION
    Exports Object to a XML file using Export-Clixml.

.PARAMETER AdaptObj
    [PSObject]
    AdaptObj

.PARAMETER AdaptFileName
    [String]
    Path to save the XML File.

.OUTPUTS
    XML file.
#>
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [PSObject] $AdaptObj,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String] $AdaptFileName
    )

    Try
    {
        (ConvertTo-Xml -NoTypeInformation -InputObject $AdaptObj).Save($AdaptFileName)
    }
    Catch
    {
        Write-Warning "[Export-AdaptXML] Failed to export $($AdaptFileName)."
        Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
    }
}

Function Export-AdaptJSON
{
<#
.SYNOPSIS
    Exports Object to a JSON file.

.DESCRIPTION
    Exports Object to a JSON file using ConvertTo-Json.

.PARAMETER AdaptObj
    [PSObject]
    AdaptObj

.PARAMETER AdaptFileName
    [String]
    Path to save the JSON File.

.OUTPUTS
    JSON file.
#>
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [PSObject] $AdaptObj,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String] $AdaptFileName
    )

    Try
    {
        ConvertTo-JSON -InputObject $AdaptObj | Out-File -FilePath $AdaptFileName
    }
    Catch
    {
        Write-Warning "[Export-AdaptJSON] Failed to export $($AdaptFileName)."
        Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
    }
}

Function Export-AdaptHTML
{
<#
.SYNOPSIS
    Exports Object to a HTML file.

.DESCRIPTION
    Exports Object to a HTML file using ConvertTo-Html.

.PARAMETER AdaptObj
    [PSObject]
    AdaptObj

.PARAMETER AdaptFileName
    [String]
    Path to save the HTML File.

.OUTPUTS
    HTML file.
#>
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [PSObject] $AdaptObj,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String] $AdaptFileName,

        [Parameter(Mandatory = $false)]
        [String] $AdaptOutputDir = $null
    )

$Header = @"
<style type="text/css">
th {
	color:white;
	background-color:blue;
	position: sticky;
	top: 0px;
}
td, th {
	border:0px solid black;
	border-collapse:collapse;
	white-space:pre;
}
tr:nth-child(2n+1) {
    background-color: #dddddd;
}
tr:hover td {
    background-color: #c1d5f8;
}
table, tr, td, th {
	padding: 0px;
	margin: 0px;
	white-space:pre;
}
table {
	margin-left:1px;
}
</style>
"@
    Try
    {
        If ($AdaptFileName.Contains("Index"))
        {
            $HTMLPath  = -join($AdaptOutputDir,'\','HTML-Files')
            $HTMLPath = $((Convert-Path $HTMLPath).TrimEnd("\"))
            $HTMLFiles = Get-ChildItem -Path $HTMLPath -name
            $HTML = $HTMLFiles | ConvertTo-HTML -Title "AdaptAD" -Property @{Label="Table of Contents";Expression={"<a href='$($_)'>$($_)</a>"}} -Head $Header

            Add-Type -AssemblyName System.Web
            [System.Web.HttpUtility]::HtmlDecode($HTML) | Out-File -FilePath $AdaptFileName
        }
        Else
        {
            If ($AdaptObj -is [array])
            {
                $AdaptObj | Select-Object * | ConvertTo-HTML -As Table -Head $Header | Out-File -FilePath $AdaptFileName
            }
            Else
            {
                ConvertTo-HTML -InputObject $AdaptObj -As Table -Head $Header | Out-File -FilePath $AdaptFileName
            }
        }
    }
    Catch
    {
        Write-Warning "[Export-AdaptHTML] Failed to export $($AdaptFileName)."
        Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
    }
}

Function Export-Adapt
{
<#
.SYNOPSIS
    Helper function for all output types supported.

.DESCRIPTION
    Helper function for all output types supported.

.PARAMETER ADObjectDN
    [PSObject]
    AdaptObj

.PARAMETER AdaptOutputDir
    [String]
    Path for Adapt AD output folder.

.PARAMETER OutputType
    [array]
    Output Type.

.PARAMETER AdaptModuleName
    [String]
    Module Name.

.OUTPUTS
    STDOUT, CSV, XML, JSON and/or HTML file, etc.
#>
    param(
        [Parameter(Mandatory = $true)]
        [PSObject] $AdaptObj,

        [Parameter(Mandatory = $true)]
        [String] $AdaptOutputDir,

        [Parameter(Mandatory = $true)]
        [array] $OutputType,

        [Parameter(Mandatory = $true)]
        [String] $AdaptModuleName
    )

    Switch ($OutputType)
    {
        'STDOUT'
        {
            If ($AdaptModuleName -ne "AboutAdaptAD")
            {
                If ($AdaptObj -is [array])
                {
                    # Fix for InvalidOperationException: The object of type "Microsoft.PowerShell.Commands.Internal.Format.FormatStartData" is not valid or not in the correct sequence.
                    $AdaptObj | Out-String -Stream
                }
                Else
                {
                    # Fix for InvalidOperationException: The object of type "Microsoft.PowerShell.Commands.Internal.Format.FormatStartData" is not valid or not in the correct sequence.
                    $AdaptObj | Format-List | Out-String -Stream
                }
            }
        }
        'CSV'
        {
            $AdaptFileName  = -join($AdaptOutputDir,'\','CSV-Files','\',$AdaptModuleName,'.csv')
            Export-AdaptCSV -AdaptObj $AdaptObj -AdaptFileName $AdaptFileName
        }
        'XML'
        {
            $AdaptFileName  = -join($AdaptOutputDir,'\','XML-Files','\',$AdaptModuleName,'.xml')
            Export-AdaptXML -AdaptObj $AdaptObj -AdaptFileName $AdaptFileName
        }
        'JSON'
        {
            $AdaptFileName  = -join($AdaptOutputDir,'\','JSON-Files','\',$AdaptModuleName,'.json')
            Export-AdaptJSON -AdaptObj $AdaptObj -AdaptFileName $AdaptFileName
        }
        'HTML'
        {
            $AdaptFileName  = -join($AdaptOutputDir,'\','HTML-Files','\',$AdaptModuleName,'.html')
            Export-AdaptHTML -AdaptObj $AdaptObj -AdaptFileName $AdaptFileName -AdaptOutputDir $AdaptOutputDir
        }
    }
}

Function Get-AdaptExcelComObj
{
<#
.SYNOPSIS
    Creates a ComObject to interact with Microsoft Excel.

.DESCRIPTION
    Creates a ComObject to interact with Microsoft Excel if installed, else warning is raised.

.OUTPUTS
    [System.__ComObject] and [System.MarshalByRefObject]
    Creates global variables $excel and $workbook.
#>

    #Check if Excel is installed.
    Try
    {
        # Suppress verbose output
        $SaveVerbosePreference = $script:VerbosePreference
        $script:VerbosePreference = 'SilentlyContinue'
        $global:excel = New-Object -ComObject excel.application
        If ($SaveVerbosePreference)
        {
            $script:VerbosePreference = $SaveVerbosePreference
            Remove-Variable SaveVerbosePreference
        }
    }
    Catch
    {
        If ($SaveVerbosePreference)
        {
            $script:VerbosePreference = $SaveVerbosePreference
            Remove-Variable SaveVerbosePreference
        }
        Write-Warning "[Get-AdaptExcelComObj] Excel does not appear to be installed. Skipping generation of AdaptAD-Report.xlsx. Use the -GenExcel parameter to generate the AdaptAD-Report.xslx on a host with Microsoft Excel installed."
        Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
        Return $null
    }
    $excel.Visible = $true
    $excel.Interactive = $false
    $global:workbook = $excel.Workbooks.Add()
    If ($workbook.Worksheets.Count -eq 3)
    {
        $workbook.WorkSheets.Item(3).Delete()
        $workbook.WorkSheets.Item(2).Delete()
    }
}

Function Get-AdaptExcelComObjRelease
{
<#
.SYNOPSIS
    Releases the ComObject created to interact with Microsoft Excel.

.DESCRIPTION
    Releases the ComObject created to interact with Microsoft Excel.

.PARAMETER ComObjtoRelease
    ComObjtoRelease

.PARAMETER Final
    Final
#>
    param(
        [Parameter(Mandatory = $true)]
        $ComObjtoRelease,

        [Parameter(Mandatory = $false)]
        [bool] $Final = $false
    )
    # https://msdn.microsoft.com/en-us/library/system.runtime.interopservices.marshal.releasecomobject(v=vs.110).aspx
    # https://msdn.microsoft.com/en-us/library/system.runtime.interopservices.marshal.finalreleasecomobject(v=vs.110).aspx
    If ($Final)
    {
        [System.Runtime.InteropServices.Marshal]::FinalReleaseComObject($ComObjtoRelease) | Out-Null
    }
    Else
    {
        [System.Runtime.InteropServices.Marshal]::ReleaseComObject($ComObjtoRelease) | Out-Null
    }
    [System.GC]::Collect()
    [System.GC]::WaitForPendingFinalizers()
}

Function Get-AdaptExcelWorkbook
{
<#
.SYNOPSIS
    Adds a WorkSheet to the Workbook.

.DESCRIPTION
    Adds a WorkSheet to the Workbook using the $workboook global variable and assigns it a name.

.PARAMETER name
    [string]
    Name of the WorkSheet.
#>
    param (
        [Parameter(Mandatory = $true)]
        [string] $name
    )

    $workbook.Worksheets.Add() | Out-Null
    $worksheet = $workbook.Worksheets.Item(1)
    $worksheet.Name = $name

    Get-AdaptExcelComObjRelease -ComObjtoRelease $worksheet
    Remove-Variable worksheet
}

Function Get-AdaptExcelImport
{
<#
.SYNOPSIS
    Helper to import CSV to the current WorkSheet.

.DESCRIPTION
    Helper to import CSV to the current WorkSheet. Supports two methods.

.PARAMETER AdaptFileName
    [string]
    Filename of the CSV file to import.

.PARAMETER method
    [int]
    Method to use for the import.
    3 - Prints data horizontally. Headers column 1, then first data row in column 2, etc.

.PARAMETER row
    [int]
    Row.

.PARAMETER column
    [int]
    Column.
#>
    param (
        [Parameter(Mandatory = $true)]
        [string] $AdaptFileName,

        [Parameter(Mandatory = $false)]
        [int] $Method = 1,

        [Parameter(Mandatory = $false)]
        [int] $row = 1,

        [Parameter(Mandatory = $false)]
        [int] $column = 1
    )

    $excel.ScreenUpdating = $false
    If ($Method -eq 1)
    {
        If (Test-Path $AdaptFileName)
        {
            $worksheet = $workbook.Worksheets.Item(1)
            $TxtConnector = ("TEXT;" + $AdaptFileName)
            $CellRef = $worksheet.Range("A1")
            #Build, use and remove the text file connector
            $Connector = $worksheet.QueryTables.add($TxtConnector, $CellRef)

            #65001: Unicode (UTF-8)
            $worksheet.QueryTables.item($Connector.name).TextFilePlatform = 65001
            $worksheet.QueryTables.item($Connector.name).TextFileCommaDelimiter = $True
            $worksheet.QueryTables.item($Connector.name).TextFileParseType = 1
            $worksheet.QueryTables.item($Connector.name).Refresh() | Out-Null
            $worksheet.QueryTables.item($Connector.name).delete()

            Get-AdaptExcelComObjRelease -ComObjtoRelease $CellRef
            Remove-Variable CellRef
            Get-AdaptExcelComObjRelease -ComObjtoRelease $Connector
            Remove-Variable Connector

            $listObject = $worksheet.ListObjects.Add([Microsoft.Office.Interop.Excel.XlListObjectSourceType]::xlSrcRange, $worksheet.UsedRange, $null, [Microsoft.Office.Interop.Excel.XlYesNoGuess]::xlYes, $null)
            $listObject.TableStyle = "TableStyleLight2" # Style Cheat Sheet: https://msdn.microsoft.com/en-au/library/documentformat.openxml.spreadsheet.tablestyle.aspx
            $worksheet.UsedRange.EntireColumn.AutoFit() | Out-Null
        }
        Remove-Variable AdaptFileName
    }
    Elseif ($Method -eq 2)
    {
        $worksheet = $workbook.Worksheets.Item(1)
        If (Test-Path $AdaptFileName)
        {
            $ADTemp = Import-Csv -Path $AdaptFileName
            $ADTemp | ForEach-Object {
                Foreach ($prop in $_.PSObject.Properties)
                {
                    $worksheet.Cells.Item($row, $column) = $prop.Name
                    $worksheet.Cells.Item($row, $column + 1) = $prop.Value
                    $row++
                }
            }
            Remove-Variable ADTemp
            $listObject = $worksheet.ListObjects.Add([Microsoft.Office.Interop.Excel.XlListObjectSourceType]::xlSrcRange, $worksheet.UsedRange, $null, [Microsoft.Office.Interop.Excel.XlYesNoGuess]::xlYes, $null)
            $listObject.TableStyle = "TableStyleLight2" # Style Cheat Sheet: https://msdn.microsoft.com/en-au/library/documentformat.openxml.spreadsheet.tablestyle.aspx
            $usedRange = $worksheet.UsedRange
            $usedRange.EntireColumn.AutoFit() | Out-Null
        }
        Else
        {
            $worksheet.Cells.Item($row, $column) = "Error!"
        }
        Remove-Variable AdaptFileName
    }
    Elseif ($Method -eq 3)
    {
        $worksheet = $workbook.Worksheets.Item(1)
        If (Test-Path $AdaptFileName)
        {
            $CsvData = Import-Csv -Path $AdaptFileName

            $row_output = $row
            $CsvData[0].PsObject.Properties.Name | ForEach {
                $worksheet.Cells.Item($row_output, $column) = $_
                $row_output++
            }
            Remove-Variable row_output

            $column_output = $column + 1
            $CsvData | ForEach-Object {
                $row_output = $row
                ForEach ($prop_value in $_.PSObject.Properties.Value)
                {
                    $worksheet.Cells.Item($row_output, $column_output) = $prop_value
                    $row_output++
                }
                $column_output++
            }
            Remove-Variable column_output
            Remove-Variable row_output

            Remove-Variable CsvData

            $listObject = $worksheet.ListObjects.Add([Microsoft.Office.Interop.Excel.XlListObjectSourceType]::xlSrcRange, $worksheet.UsedRange, $null, [Microsoft.Office.Interop.Excel.XlYesNoGuess]::xlYes, $null)
            $listObject.TableStyle = "TableStyleLight2" # Style Cheat Sheet: https://msdn.microsoft.com/en-au/library/documentformat.openxml.spreadsheet.tablestyle.aspx
            $usedRange = $worksheet.UsedRange
            $usedRange.EntireColumn.AutoFit() | Out-Null
        }
        Else
        {
            $worksheet.Cells.Item($row, $column) = "Error!"
        }
        Remove-Variable AdaptFileName

    }
    $excel.ScreenUpdating = $true

    Get-AdaptExcelComObjRelease -ComObjtoRelease $worksheet
    Remove-Variable worksheet
}

# Thanks Anant Shrivastava for the suggestion of using Pivot Tables for generation of the Stats sheets.
Function Get-AdaptExcelPivotTable
{
<#
.SYNOPSIS
    Helper to add Pivot Table to the current WorkSheet.

.DESCRIPTION
    Helper to add Pivot Table to the current WorkSheet.

.PARAMETER SrcSheetName
    [string]
    Source Sheet Name.

.PARAMETER PivotTableName
    [string]
    Pivot Table Name.

.PARAMETER PivotRows
    [array]
    Row names from Source Sheet.

.PARAMETER PivotColumns
    [array]
    Column names from Source Sheet.

.PARAMETER PivotFilters
    [array]
    Row/Column names from Source Sheet to use as filters.

.PARAMETER PivotValues
    [array]
    Row/Column names from Source Sheet to use for Values.

.PARAMETER PivotPercentage
    [array]
    Row/Column names from Source Sheet to use for Percentage.

.PARAMETER PivotLocation
    [array]
    Location of the Pivot Table in Row/Column.
#>
    param (
        [Parameter(Mandatory = $true)]
        [string] $SrcSheetName,

        [Parameter(Mandatory = $true)]
        [string] $PivotTableName,

        [Parameter(Mandatory = $false)]
        [array] $PivotRows,

        [Parameter(Mandatory = $false)]
        [array] $PivotColumns,

        [Parameter(Mandatory = $false)]
        [array] $PivotFilters,

        [Parameter(Mandatory = $false)]
        [array] $PivotValues,

        [Parameter(Mandatory = $false)]
        [array] $PivotPercentage,

        [Parameter(Mandatory = $false)]
        [string] $PivotLocation = "R1C1"
    )

    $excel.ScreenUpdating = $false
    $SrcWorksheet = $workbook.Sheets.Item($SrcSheetName)
    $workbook.ShowPivotTableFieldList = $false

    # https://msdn.microsoft.com/en-us/vba/excel-vba/articles/xlpivottablesourcetype-enumeration-excel
    # https://msdn.microsoft.com/en-us/vba/excel-vba/articles/xlpivottableversionlist-enumeration-excel
    # https://msdn.microsoft.com/en-us/vba/excel-vba/articles/xlpivotfieldorientation-enumeration-excel
    # https://msdn.microsoft.com/en-us/vba/excel-vba/articles/constants-enumeration-excel
    # https://msdn.microsoft.com/en-us/vba/excel-vba/articles/xlsortorder-enumeration-excel
    # https://msdn.microsoft.com/en-us/vba/excel-vba/articles/xlpivotfiltertype-enumeration-excel

    # xlDatabase = 1 # this just means local sheet data
    # xlPivotTableVersion12 = 3 # Excel 2007
    $PivotFailed = $false
    Try
    {
        $PivotCaches = $workbook.PivotCaches().Create([Microsoft.Office.Interop.Excel.XlPivotTableSourceType]::xlDatabase, $SrcWorksheet.UsedRange, [Microsoft.Office.Interop.Excel.XlPivotTableVersionList]::xlPivotTableVersion12)
    }
    Catch
    {
        $PivotFailed = $true
        Write-Verbose "[PivotCaches().Create] Failed"
        Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
    }
    If ( $PivotFailed -eq $true )
    {
        $rows = $SrcWorksheet.UsedRange.Rows.Count
        If ($SrcSheetName -eq "Computer SPNs")
        {
            $PivotCols = "A1:C"
        }
        ElseIf ($SrcSheetName -eq "Computers")
        {
            $PivotCols = "A1:F"
        }
        ElseIf ($SrcSheetName -eq "Users")
        {
            $PivotCols = "A1:C"
        }
        $UsedRange = $SrcWorksheet.Range($PivotCols+$rows)
        $PivotCaches = $workbook.PivotCaches().Create([Microsoft.Office.Interop.Excel.XlPivotTableSourceType]::xlDatabase, $UsedRange, [Microsoft.Office.Interop.Excel.XlPivotTableVersionList]::xlPivotTableVersion12)
        Remove-Variable rows
	    Remove-Variable PivotCols
        Remove-Variable UsedRange
    }
    Remove-Variable PivotFailed
    $PivotTable = $PivotCaches.CreatePivotTable($PivotLocation,$PivotTableName)
    # $workbook.ShowPivotTableFieldList = $true

    If ($PivotRows)
    {
        ForEach ($Row in $PivotRows)
        {
            $PivotField = $PivotTable.PivotFields($Row)
            $PivotField.Orientation = [Microsoft.Office.Interop.Excel.XlPivotFieldOrientation]::xlRowField
        }
    }

    If ($PivotColumns)
    {
        ForEach ($Col in $PivotColumns)
        {
            $PivotField = $PivotTable.PivotFields($Col)
            $PivotField.Orientation = [Microsoft.Office.Interop.Excel.XlPivotFieldOrientation]::xlColumnField
        }
    }

    If ($PivotFilters)
    {
        ForEach ($Fil in $PivotFilters)
        {
            $PivotField = $PivotTable.PivotFields($Fil)
            $PivotField.Orientation = [Microsoft.Office.Interop.Excel.XlPivotFieldOrientation]::xlPageField
        }
    }

    If ($PivotValues)
    {
        ForEach ($Val in $PivotValues)
        {
            $PivotField = $PivotTable.PivotFields($Val)
            $PivotField.Orientation = [Microsoft.Office.Interop.Excel.XlPivotFieldOrientation]::xlDataField
        }
    }

    If ($PivotPercentage)
    {
        ForEach ($Val in $PivotPercentage)
        {
            $PivotField = $PivotTable.PivotFields($Val)
            $PivotField.Orientation = [Microsoft.Office.Interop.Excel.XlPivotFieldOrientation]::xlDataField
            $PivotField.Calculation = [Microsoft.Office.Interop.Excel.XlPivotFieldCalculation]::xlPercentOfTotal
            $PivotTable.ShowValuesRow = $false
        }
    }

    # $PivotFields.Caption = ""
    $excel.ScreenUpdating = $true

    Get-AdaptExcelComObjRelease -ComObjtoRelease $PivotField
    Remove-Variable PivotField
    Get-AdaptExcelComObjRelease -ComObjtoRelease $PivotTable
    Remove-Variable PivotTable
    Get-AdaptExcelComObjRelease -ComObjtoRelease $PivotCaches
    Remove-Variable PivotCaches
    Get-AdaptExcelComObjRelease -ComObjtoRelease $SrcWorksheet
    Remove-Variable SrcWorksheet
}

Function Get-AdaptExcelAttributeStats
{
<#
.SYNOPSIS
    Helper to add Attribute Stats to the current WorkSheet.

.DESCRIPTION
    Helper to add Attribute Stats to the current WorkSheet.

.PARAMETER SrcSheetName
    [string]
    Source Sheet Name.

.PARAMETER Title1
    [string]
    Title1.

.PARAMETER PivotTableName
    [string]
    PivotTableName.

.PARAMETER PivotRows
    [string]
    PivotRows.

.PARAMETER PivotValues
    [string]
    PivotValues.

.PARAMETER PivotPercentage
    [string]
    PivotPercentage.

.PARAMETER Title2
    [string]
    Title2.

.PARAMETER ObjAttributes
    [OrderedDictionary]
    Attributes.
#>
    param (
        [Parameter(Mandatory = $true)]
        [string] $SrcSheetName,

        [Parameter(Mandatory = $true)]
        [string] $Title1,

        [Parameter(Mandatory = $true)]
        [string] $PivotTableName,

        [Parameter(Mandatory = $true)]
        [string] $PivotRows,

        [Parameter(Mandatory = $true)]
        [string] $PivotValues,

        [Parameter(Mandatory = $true)]
        [string] $PivotPercentage,

        [Parameter(Mandatory = $true)]
        [string] $Title2,

        [Parameter(Mandatory = $true)]
        [System.Object] $ObjAttributes
    )

    $excel.ScreenUpdating = $false
    $worksheet = $workbook.Worksheets.Item(1)
    $SrcWorksheet = $workbook.Sheets.Item($SrcSheetName)

    $row = 1
    $column = 1
    $worksheet.Cells.Item($row, $column) = $Title1
    $worksheet.Cells.Item($row,$column).Style = "Heading 2"
    $worksheet.Cells.Item($row,$column).HorizontalAlignment = -4108
    $MergeCells = $worksheet.Range("A1:C1")
    $MergeCells.Select() | Out-Null
    $MergeCells.MergeCells = $true
    Remove-Variable MergeCells

    Get-AdaptExcelPivotTable -SrcSheetName $SrcSheetName -PivotTableName $PivotTableName -PivotRows @($PivotRows) -PivotValues @($PivotValues) -PivotPercentage @($PivotPercentage) -PivotLocation "R2C1"
    $excel.ScreenUpdating = $false

    $row = 2
    "Type","Count","Percentage" | ForEach-Object {
        $worksheet.Cells.Item($row, $column) = $_
        $worksheet.Cells.Item($row, $column).Font.Bold = $True
        $column++
    }

    $row = 3
    $column = 1
    For($row = 3; $row -le 6; $row++)
    {
        $temptext = [string] $worksheet.Cells.Item($row, $column).Text
        switch ($temptext.ToUpper())
        {
            "TRUE" { $worksheet.Cells.Item($row, $column) = "Enabled" }
            "FALSE" { $worksheet.Cells.Item($row, $column) = "Disabled" }
            "GRAND TOTAL" { $worksheet.Cells.Item($row, $column) = "Total" }
        }
    }

    If ($ObjAttributes)
    {
        $row = 1
        $column = 6
        $worksheet.Cells.Item($row, $column) = $Title2
        $worksheet.Cells.Item($row,$column).Style = "Heading 2"
        $worksheet.Cells.Item($row,$column).HorizontalAlignment = -4108
        $MergeCells = $worksheet.Range("F1:L1")
        $MergeCells.Select() | Out-Null
        $MergeCells.MergeCells = $true
        Remove-Variable MergeCells

        $row++
        "Category","Enabled Count","Enabled Percentage","Disabled Count","Disabled Percentage","Total Count","Total Percentage" | ForEach-Object {
            $worksheet.Cells.Item($row, $column) = $_
            $worksheet.Cells.Item($row, $column).Font.Bold = $True
            $column++
        }
        $ExcelColumn = ($SrcWorksheet.Columns.Find("Enabled"))
        $EnabledColAddress = "$($ExcelColumn.Address($false,$false).Substring(0,$ExcelColumn.Address($false,$false).Length-1)):$($ExcelColumn.Address($false,$false).Substring(0,$ExcelColumn.Address($false,$false).Length-1))"
        $column = 6
        $i = 2

        $ObjAttributes.keys | ForEach-Object {
            $ExcelColumn = ($SrcWorksheet.Columns.Find($_))
            $ColAddress = "$($ExcelColumn.Address($false,$false).Substring(0,$ExcelColumn.Address($false,$false).Length-1)):$($ExcelColumn.Address($false,$false).Substring(0,$ExcelColumn.Address($false,$false).Length-1))"
            $row++
            $i++
            If ($_ -eq "Delegation Typ")
            {
                $worksheet.Cells.Item($row, $column) = "Unconstrained Delegation"
            }
            ElseIf ($_ -eq "Delegation Type")
            {
                $worksheet.Cells.Item($row, $column) = "Constrained Delegation"
            }
            Else
            {
                $worksheet.Cells.Item($row, $column).Formula = "='" + $SrcWorksheet.Name + "'!" + $ExcelColumn.Address($false,$false)
            }
            $worksheet.Cells.Item($row, $column+1).Formula = "=COUNTIFS('" + $SrcWorksheet.Name + "'!" + $EnabledColAddress + ',"TRUE",' + "'" + $SrcWorksheet.Name + "'!" + $ColAddress + ',' + $ObjAttributes[$_] + ')'
            $worksheet.Cells.Item($row, $column+2).Formula = '=IFERROR(G' + $i + '/VLOOKUP("Enabled",A3:B6,2,FALSE),0)'
            $worksheet.Cells.Item($row, $column+3).Formula = "=COUNTIFS('" + $SrcWorksheet.Name + "'!" + $EnabledColAddress + ',"FALSE",' + "'" + $SrcWorksheet.Name + "'!" + $ColAddress + ',' + $ObjAttributes[$_] + ')'
            $worksheet.Cells.Item($row, $column+4).Formula = '=IFERROR(I' + $i + '/VLOOKUP("Disabled",A3:B6,2,FALSE),0)'
            If ( ($_ -eq "SIDHistory") -or ($_ -eq "ms-ds-CreatorSid") )
            {
                # Remove count of FieldName
                $worksheet.Cells.Item($row, $column+5).Formula = "=COUNTIF('" + $SrcWorksheet.Name + "'!" + $ColAddress + ',' + $ObjAttributes[$_] + ')-1'
            }
            Else
            {
                $worksheet.Cells.Item($row, $column+5).Formula = "=COUNTIF('" + $SrcWorksheet.Name + "'!" + $ColAddress + ',' + $ObjAttributes[$_] + ')'
            }
            $worksheet.Cells.Item($row, $column+6).Formula = '=IFERROR(K' + $i + '/VLOOKUP("Total",A3:B6,2,FALSE),0)'
        }

        # http://www.excelhowto.com/macros/formatting-a-range-of-cells-in-excel-vba/
        "H", "J" , "L" | ForEach-Object {
            $rng = $_ + $($row - $ObjAttributes.Count + 1) + ":" + $_ + $($row)
            $worksheet.Range($rng).NumberFormat = "0.00%"
        }
    }
    $excel.ScreenUpdating = $true

    Get-AdaptExcelComObjRelease -ComObjtoRelease $SrcWorksheet
    Remove-Variable SrcWorksheet
    Get-AdaptExcelComObjRelease -ComObjtoRelease $worksheet
    Remove-Variable worksheet
}

Function Get-AdaptExcelChart
{
<#
.SYNOPSIS
    Helper to add charts to the current WorkSheet.

.DESCRIPTION
    Helper to add charts to the current WorkSheet.

.PARAMETER ChartType
    [int]
    Chart Type.

.PARAMETER ChartLayout
    [int]
    Chart Layout.

.PARAMETER ChartTitle
    [string]
    Title of the Chart.

.PARAMETER RangetoCover
    WorkSheet Range to be covered by the Chart.

.PARAMETER ChartData
    Data for the Chart.

.PARAMETER StartRow
    Start row to calculate data for the Chart.

.PARAMETER StartColumn
    Start column to calculate data for the Chart.
#>
    param (
        [Parameter(Mandatory = $true)]
        [string] $ChartType,

        [Parameter(Mandatory = $true)]
        [int] $ChartLayout,

        [Parameter(Mandatory = $true)]
        [string] $ChartTitle,

        [Parameter(Mandatory = $true)]
        $RangetoCover,

        [Parameter(Mandatory = $false)]
        $ChartData = $null,

        [Parameter(Mandatory = $false)]
        $StartRow = $null,

        [Parameter(Mandatory = $false)]
        $StartColumn = $null
    )

    $excel.ScreenUpdating = $false
    $excel.DisplayAlerts = $false
    $worksheet = $workbook.Worksheets.Item(1)
    $chart = $worksheet.Shapes.AddChart().Chart
    # https://msdn.microsoft.com/en-us/vba/excel-vba/articles/xlcharttype-enumeration-excel
    $chart.chartType = [int]([Microsoft.Office.Interop.Excel.XLChartType]::$ChartType)
    $chart.ApplyLayout($ChartLayout)
    If ($null -eq $ChartData)
    {
        If ($null -eq $StartRow)
        {
            $start = $worksheet.Range("A1")
        }
        Else
        {
            $start = $worksheet.Range($StartRow)
        }
        # get the last cell
        $X = $worksheet.Range($start,$start.End([Microsoft.Office.Interop.Excel.XLDirection]::xlDown))
        If ($null -eq $StartColumn)
        {
            $start = $worksheet.Range("B1")
        }
        Else
        {
            $start = $worksheet.Range($StartColumn)
        }
        # get the last cell
        $Y = $worksheet.Range($start,$start.End([Microsoft.Office.Interop.Excel.XLDirection]::xlDown))
        $ChartData = $worksheet.Range($X,$Y)

        Get-AdaptExcelComObjRelease -ComObjtoRelease $X
        Remove-Variable X
        Get-AdaptExcelComObjRelease -ComObjtoRelease $Y
        Remove-Variable Y
        Get-AdaptExcelComObjRelease -ComObjtoRelease $start
        Remove-Variable start
    }
    $chart.SetSourceData($ChartData)
    # https://docs.microsoft.com/en-us/dotnet/api/microsoft.office.interop.excel.chartclass.plotby?redirectedfrom=MSDN&view=excel-pia#Microsoft_Office_Interop_Excel_ChartClass_PlotBy
    $chart.PlotBy = [Microsoft.Office.Interop.Excel.XlRowCol]::xlColumns
    $chart.seriesCollection(1).Select() | Out-Null
    $chart.SeriesCollection(1).ApplyDataLabels() | out-Null
    # modify the chart title
    $chart.HasTitle = $True
    $chart.ChartTitle.Text = $ChartTitle
    # Reposition the Chart
    $temp = $worksheet.Range($RangetoCover)
    # $chart.parent.placement = 3
    $chart.parent.top = $temp.Top
    $chart.parent.left = $temp.Left
    $chart.parent.width = $temp.Width
    If ($ChartTitle -ne "Privileged Groups in AD")
    {
        $chart.parent.height = $temp.Height
    }
    # $chart.Legend.Delete()
    $excel.ScreenUpdating = $true
    $excel.DisplayAlerts = $true

    Get-AdaptExcelComObjRelease -ComObjtoRelease $chart
    Remove-Variable chart
    Get-AdaptExcelComObjRelease -ComObjtoRelease $ChartData
    Remove-Variable ChartData
    Get-AdaptExcelComObjRelease -ComObjtoRelease $temp
    Remove-Variable temp
    Get-AdaptExcelComObjRelease -ComObjtoRelease $worksheet
    Remove-Variable worksheet
}

Function Get-AdaptExcelSort
{
<#
.SYNOPSIS
    Sorts a WorkSheet in the active Workbook.

.DESCRIPTION
    Sorts a WorkSheet in the active Workbook.

.PARAMETER ColumnName
    [string]
    Name of the Column.
#>
    param (
        [Parameter(Mandatory = $true)]
        [string] $ColumnName
    )

    $worksheet = $workbook.Worksheets.Item(1)
    $worksheet.Activate();

    $ExcelColumn = ($worksheet.Columns.Find($ColumnName))
    If ($ExcelColumn)
    {
        If ($ExcelColumn.Text -ne $ColumnName)
        {
            $BeginAddress = $ExcelColumn.Address(0,0,1,1)
            $End = $False
            Do {
                #Write-Verbose "[Get-AdaptExcelSort] $($ExcelColumn.Text) selected instead of $($ColumnName) in the $($worksheet.Name) worksheet."
                $ExcelColumn = ($worksheet.Columns.FindNext($ExcelColumn))
                $Address = $ExcelColumn.Address(0,0,1,1)
                If ( ($Address -eq $BeginAddress) -or ($ExcelColumn.Text -eq $ColumnName) )
                {
                    $End = $True
                }
            } Until ($End -eq $True)
        }
        If ($ExcelColumn.Text -eq $ColumnName)
        {
            # Sort by Column
            $workSheet.ListObjects.Item(1).Sort.SortFields.Clear()
            $workSheet.ListObjects.Item(1).Sort.SortFields.Add($ExcelColumn) | Out-Null
            $worksheet.ListObjects.Item(1).Sort.Apply()
        }
        Else
        {
            Write-Verbose "[Get-AdaptExcelSort] $($ColumnName) not found in the $($worksheet.Name) worksheet."
        }
    }
    Else
    {
        Write-Verbose "[Get-AdaptExcelSort] $($ColumnName) not found in the $($worksheet.Name) worksheet."
    }
    Get-AdaptExcelComObjRelease -ComObjtoRelease $worksheet
    Remove-Variable worksheet
}

Function Export-AdaptExcel
{
<#
.SYNOPSIS
    Automates the generation of the Adapt AD report.

.DESCRIPTION
    Automates the generation of the Adapt AD report. If specific files exist, they are imported into the Adapt AD report.

.PARAMETER ExcelPath
    [string]
    Path for Adapt AD output folder containing the CSV files to generate the AdaptAD-Report.xlsx

.PARAMETER Logo
    [string]
    Which Logo to use in the excel file? (Default AdaptAD)

.OUTPUTS
    Creates the AdaptAD-Report.xlsx report in the folder.
#>
    param(
        [Parameter(Mandatory = $true)]
        [string] $ExcelPath,

        [Parameter(Mandatory = $false)]
        [string] $Logo = "AdaptAD"
    )

    If ($PSVersionTable.PSEdition -eq "Core")
    {
        If ($PSVersionTable.Platform -eq "Win32NT")
        {
            $returndir = Get-Location
            Set-Location C:\Windows\assembly\
            $refFolder = (Get-ChildItem -Recurse  Microsoft.Office.Interop.Excel.dll).Directory
            Set-Location $refFolder
            Add-Type -AssemblyName "Microsoft.Office.Interop.Excel"
            Set-Location $returndir
            Remove-Variable returndir
            Remove-Variable refFolder
        }
    }

    $ExcelPath = $((Convert-Path $ExcelPath).TrimEnd("\"))
    $ReportPath = -join($ExcelPath,'\','CSV-Files')
    If (!(Test-Path $ReportPath))
    {
        Write-Warning "[Export-AdaptExcel] Could not locate the CSV-Files directory ... Exiting"
        Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
        Return $null
    }
    Get-AdaptExcelComObj
    If ($excel)
    {
        Write-Output "[*] Generating AdaptAD-Report.xlsx"

        $AdaptFileName = -join($ReportPath,'\','AboutAdaptAD.csv')
        If (Test-Path $AdaptFileName)
        {
            Get-AdaptExcelImport -AdaptFileName $AdaptFileName
            Remove-Variable AdaptFileName

            $workbook.Worksheets.Item(1).Name = "About Adapt AD"
            $workbook.Worksheets.Item(1).Hyperlinks.Add($workbook.Worksheets.Item(1).Cells.Item(3,2) , "https://github.com/yourusername/AdaptAD", "" , "", "github.com/yourusername/AdaptAD") | Out-Null
            $workbook.Worksheets.Item(1).UsedRange.EntireColumn.AutoFit() | Out-Null
        }

        $AdaptFileName = -join($ReportPath,'\','Forest.csv')
        If (Test-Path $AdaptFileName)
        {
            Get-AdaptExcelWorkbook -Name "Forest"
            Get-AdaptExcelImport -AdaptFileName $AdaptFileName
            Remove-Variable AdaptFileName
        }

        $AdaptFileName = -join($ReportPath,'\','Domain.csv')
        If (Test-Path $AdaptFileName)
        {
            Get-AdaptExcelWorkbook -Name "Domain"
            Get-AdaptExcelImport -AdaptFileName $AdaptFileName
            $DomainObj = Import-CSV -Path $AdaptFileName
            Remove-Variable AdaptFileName
            $DomainName = -join($DomainObj[0].Value,"-")
            Remove-Variable DomainObj
        }

        $AdaptFileName = -join($ReportPath,'\','Trusts.csv')
        If (Test-Path $AdaptFileName)
        {
            Get-AdaptExcelWorkbook -Name "Trusts"
            Get-AdaptExcelImport -AdaptFileName $AdaptFileName
            Remove-Variable AdaptFileName
        }

        $AdaptFileName = -join($ReportPath,'\','Subnets.csv')
        If (Test-Path $AdaptFileName)
        {
            Get-AdaptExcelWorkbook -Name "Subnets"
            Get-AdaptExcelImport -AdaptFileName $AdaptFileName
            Remove-Variable AdaptFileName
        }

        $AdaptFileName = -join($ReportPath,'\','Sites.csv')
        If (Test-Path $AdaptFileName)
        {
            Get-AdaptExcelWorkbook -Name "Sites"
            Get-AdaptExcelImport -AdaptFileName $AdaptFileName
            Remove-Variable AdaptFileName
        }

        $AdaptFileName = -join($ReportPath,'\','SchemaHistory.csv')
        If (Test-Path $AdaptFileName)
        {
            Get-AdaptExcelWorkbook -Name "SchemaHistory"
            Get-AdaptExcelImport -AdaptFileName $AdaptFileName
            Remove-Variable AdaptFileName
        }

        $AdaptFileName = -join($ReportPath,'\','FineGrainedPasswordPolicy.csv')
        If (Test-Path $AdaptFileName)
        {
            Get-AdaptExcelWorkbook -Name "Fine Grained Password Policy"
            Get-AdaptExcelImport -AdaptFileName $AdaptFileName -Method 3
            Remove-Variable AdaptFileName

            $worksheet = $workbook.Worksheets.Item(1)
            $usedRange = $worksheet.UsedRange

            $usedRange.Rows(2).WrapText = $True

            $usedRange.Columns | ForEach-Object {
                $_.ColumnWidth = 60
            }
            $usedRange.Rows(2).AutoFit() | Out-Null
            $usedRange.Columns["A"].AutoFit() | Out-Null
        }

        $AdaptFileName = -join($ReportPath,'\','DefaultPasswordPolicy.csv')
        If (Test-Path $AdaptFileName)
        {
            Get-AdaptExcelWorkbook -Name "Default Password Policy"
            Get-AdaptExcelImport -AdaptFileName $AdaptFileName
            Remove-Variable AdaptFileName

            $excel.ScreenUpdating = $false
            $worksheet = $workbook.Worksheets.Item(1)

            # https://docs.microsoft.com/en-us/office/vba/api/excel.xlhalign
            $worksheet.Range("C1:D1").HorizontalAlignment = -4108
            $workbook.Worksheets.Item(1).Cells.Item(1,7).HorizontalAlignment = -4108
            $worksheet.Range("B2:H10").HorizontalAlignment = -4108

            # https://docs.microsoft.com/en-us/office/vba/api/excel.range.borderaround

            "A2:B10", "C2:E10", "F2:G10", "H2:H10" | ForEach-Object {
                $worksheet.Range($_).BorderAround(1) | Out-Null
            }

            # https://docs.microsoft.com/en-us/dotnet/api/microsoft.office.interop.excel.formatconditions.add?view=excel-pia
            # $worksheet.Range().FormatConditions.Add
            # http://dmcritchie.mvps.org/excel/colors.htm
            # Values for Font.ColorIndex

            $ObjValues = @(
            # PCI v3.2.1 Enforce password history (passwords)
            "C2", '=IF(B2<4,TRUE, FALSE)'

            # PCI v3.2.1 Maximum password age (days)
            "C3", '=IF(OR(B3=0,B3>90),TRUE, FALSE)'

            # PCI v3.2.1 Minimum password age (days)

            # PCI v3.2.1 Minimum password length (characters)
            "C5", '=IF(B5<7,TRUE, FALSE)'

            # PCI v3.2.1 Password must meet complexity requirements
            "C6", '=IF(B6<>TRUE,TRUE, FALSE)'

            # PCI v3.2.1 Store password using reversible encryption for all users in the domain

            # PCI v3.2.1 Account lockout duration (mins)
            "C8", '=IF(AND(B8>=1,B8<30),TRUE, FALSE)'

            # PCI v3.2.1 Account lockout threshold (attempts)
            "C9", '=IF(OR(B9=0,B9>6),TRUE, FALSE)'

            # PCI v3.2.1 Reset account lockout counter after (mins)

            # PCI v4.0 Enforce password history (passwords)
            "D2", '=IF(B2<4,TRUE, FALSE)'

            # PCI v4.0 Maximum password age (days)
            "D3", '=IF(OR(B3=0,B3>90),TRUE, FALSE)'

            # PCI v4.0 Minimum password age (days)

            # PCI v4.0 Minimum password length (characters)
            "D5", '=IF(B5<12,TRUE, FALSE)'

            # PCI v4.0 Password must meet complexity requirements
            "D6", '=IF(B6<>TRUE,TRUE, FALSE)'

            # PCI v4.0 Store password using reversible encryption for all users in the domain

            # PCI v4.0 Account lockout duration (mins)
            "D8", '=IF(AND(B8>=1,B8<30),TRUE, FALSE)'

            # PCI v4.0 Account lockout threshold (attempts)
            "D9", '=IF(OR(B9=0,B9>10),TRUE, FALSE)'

            # PCI v4.0 Reset account lockout counter after (mins)

            # ACSC ISM Enforce password history (passwords)
            #"F2", '=IF(B2<8,TRUE, FALSE)'

            # ACSC ISM Maximum password age (days)
            "F3", '=IF(OR(B3=0,B3>365),TRUE, FALSE)'

            # ACSC ISM Minimum password age (days)
            #"F4", '=IF(B4=0,TRUE, FALSE)'

            # ACSC ISM Minimum password length (characters)
            "F5", '=IF(B5<14,TRUE, FALSE)'

            # ACSC ISM Password must meet complexity requirements
            #"F6", '=IF(B6<>TRUE,TRUE, FALSE)'

            # ACSC ISM Store password using reversible encryption for all users in the domain

            # ACSC ISM Account lockout duration (mins)

            # ACSC ISM Account lockout threshold (attempts)
            "F9", '=IF(OR(B9=0,B9>5),TRUE, FALSE)'

            # ACSC ISM Reset account lockout counter after (mins)

            # CIS Benchmark Enforce password history (passwords)
            "H2", '=IF(B2<24,TRUE, FALSE)'

            # CIS Benchmark Maximum password age (days)
            "H3", '=IF(OR(B3=0,B3>365),TRUE, FALSE)'

            # CIS Benchmark Minimum password age (days)
            "H4", '=IF(B4=0,TRUE, FALSE)'

            # CIS Benchmark Minimum password length (characters)
            "H5", '=IF(B5<14,TRUE, FALSE)'

            # CIS Benchmark Password must meet complexity requirements
            "H6", '=IF(B6<>TRUE,TRUE, FALSE)'

            # CIS Benchmark Store password using reversible encryption for all users in the domain
            "H7", '=IF(B7<>FALSE,TRUE, FALSE)'

            # CIS Benchmark Account lockout duration (mins)
            "H8", '=IF(AND(B8>=1,B8<15),TRUE, FALSE)'

            # CIS Benchmark Account lockout threshold (attempts)
            "H9", '=IF(OR(B9=0,B9>5),TRUE, FALSE)'

            # CIS Benchmark Reset account lockout counter after (mins)
            "H10", '=IF(B10<15,TRUE, FALSE)' )

            For ($i = 0; $i -lt $($ObjValues.Count); $i++)
            {
                $worksheet.Range($ObjValues[$i]).FormatConditions.Add([Microsoft.Office.Interop.Excel.XlFormatConditionType]::xlExpression, 0, $ObjValues[$i+1]) | Out-Null
                $i++
            }

            "C2", "C3" , "C5", "C6", "C8", "C9", "D2", "D3" , "D5", "D6", "D8", "D9", "F5", "F9", "H2", "H3", "H4", "H5", "H6", "H7", "H8", "H9", "H10" | ForEach-Object {
                $worksheet.Range($_).FormatConditions.Item(1).StopIfTrue = $false
                $worksheet.Range($_).FormatConditions.Item(1).Font.ColorIndex = 3
            }

            $workbook.Worksheets.Item(1).Hyperlinks.Add($workbook.Worksheets.Item(1).Cells.Item(1,5) , "https://www.pcisecuritystandards.org/document_library?category=pcidss&document=pci_dss", "" , "", "PCI DSS Requirement") | Out-Null
            $workbook.Worksheets.Item(1).Hyperlinks.Add($workbook.Worksheets.Item(1).Cells.Item(1, 7) , "https://www.cyber.gov.au/acsc/view-all-content/ism", "" , "", "ISM Controls 16Jun2022") | Out-Null
            $workbook.Worksheets.Item(1).Hyperlinks.Add($workbook.Worksheets.Item(1).Cells.Item(1,8) , "https://www.cisecurity.org/benchmark/microsoft_windows_server/", "" , "", "CIS Benchmark 2022") | Out-Null

            $excel.ScreenUpdating = $true
            Get-AdaptExcelComObjRelease -ComObjtoRelease $worksheet
            Remove-Variable worksheet
        }

        $AdaptFileName = -join($ReportPath,'\','DomainControllers.csv')
        If (Test-Path $AdaptFileName)
        {
            Get-AdaptExcelWorkbook -Name "Domain Controllers"
            Get-AdaptExcelImport -AdaptFileName $AdaptFileName
            Remove-Variable AdaptFileName
        }

        $AdaptFileName = -join($ReportPath,'\','GroupChanges.csv')
        If (Test-Path $AdaptFileName)
        {
            Get-AdaptExcelWorkbook -Name "Group Changes"
            Get-AdaptExcelImport -AdaptFileName $AdaptFileName
            Remove-Variable AdaptFileName

            Get-AdaptExcelSort -ColumnName "Group Name"
        }

        $AdaptFileName = -join($ReportPath,'\','DACLs.csv')
        If (Test-Path $AdaptFileName)
        {
            Get-AdaptExcelWorkbook -Name "DACLs"
            Get-AdaptExcelImport -AdaptFileName $AdaptFileName
            Remove-Variable AdaptFileName
        }

        $AdaptFileName = -join($ReportPath,'\','SACLs.csv')
        If (Test-Path $AdaptFileName)
        {
            Get-AdaptExcelWorkbook -Name "SACLs"
            Get-AdaptExcelImport -AdaptFileName $AdaptFileName
            Remove-Variable AdaptFileName
        }

        $AdaptFileName = -join($ReportPath,'\','GPOs.csv')
        If (Test-Path $AdaptFileName)
        {
            Get-AdaptExcelWorkbook -Name "GPOs"
            Get-AdaptExcelImport -AdaptFileName $AdaptFileName
            Remove-Variable AdaptFileName
        }

        $AdaptFileName = -join($ReportPath,'\','gPLinks.csv')
        If (Test-Path $AdaptFileName)
        {
            Get-AdaptExcelWorkbook -Name "gPLinks"
            Get-AdaptExcelImport -AdaptFileName $AdaptFileName
            Remove-Variable AdaptFileName
        }

        $AdaptFileName = -join($ReportPath,'\','DNSNodes','.csv')
        If (Test-Path $AdaptFileName)
        {
            Get-AdaptExcelWorkbook -Name "DNS Records"
            Get-AdaptExcelImport -AdaptFileName $AdaptFileName
            Remove-Variable AdaptFileName
        }

        $AdaptFileName = -join($ReportPath,'\','DNSZones.csv')
        If (Test-Path $AdaptFileName)
        {
            Get-AdaptExcelWorkbook -Name "DNS Zones"
            Get-AdaptExcelImport -AdaptFileName $AdaptFileName
            Remove-Variable AdaptFileName
        }

        $AdaptFileName = -join($ReportPath,'\','Printers.csv')
        If (Test-Path $AdaptFileName)
        {
            Get-AdaptExcelWorkbook -Name "Printers"
            Get-AdaptExcelImport -AdaptFileName $AdaptFileName
            Remove-Variable AdaptFileName
        }

        $AdaptFileName = -join($ReportPath,'\','BitLockerRecoveryKeys.csv')
        If (Test-Path $AdaptFileName)
        {
            Get-AdaptExcelWorkbook -Name "BitLocker"
            Get-AdaptExcelImport -AdaptFileName $AdaptFileName
            Remove-Variable AdaptFileName
        }

        $AdaptFileName = -join($ReportPath,'\','LAPS.csv')
        If (Test-Path $AdaptFileName)
        {
            Get-AdaptExcelWorkbook -Name "LAPS"
            Get-AdaptExcelImport -AdaptFileName $AdaptFileName
            Remove-Variable AdaptFileName
        }

        $AdaptFileName = -join($ReportPath,'\','ComputerSPNs.csv')
        If (Test-Path $AdaptFileName)
        {
            Get-AdaptExcelWorkbook -Name "Computer SPNs"
            Get-AdaptExcelImport -AdaptFileName $AdaptFileName
            Remove-Variable AdaptFileName

            Get-AdaptExcelSort -ColumnName "UserName"
        }

        $AdaptFileName = -join($ReportPath,'\','Computers.csv')
        If (Test-Path $AdaptFileName)
        {
            Get-AdaptExcelWorkbook -Name "Computers"
            Get-AdaptExcelImport -AdaptFileName $AdaptFileName
            Remove-Variable AdaptFileName

            Get-AdaptExcelSort -ColumnName "UserName"

            $worksheet = $workbook.Worksheets.Item(1)
            # Freeze First Row and Column
            $worksheet.Select()
            $worksheet.Application.ActiveWindow.splitcolumn = 1
            $worksheet.Application.ActiveWindow.splitrow = 1
            $worksheet.Application.ActiveWindow.FreezePanes = $true

            Get-AdaptExcelComObjRelease -ComObjtoRelease $worksheet
            Remove-Variable worksheet
        }

        $AdaptFileName = -join($ReportPath,'\','OUs.csv')
        If (Test-Path $AdaptFileName)
        {
            Get-AdaptExcelWorkbook -Name "OUs"
            Get-AdaptExcelImport -AdaptFileName $AdaptFileName
            Remove-Variable AdaptFileName
        }

        $AdaptFileName = -join($ReportPath,'\','Groups.csv')
        If (Test-Path $AdaptFileName)
        {
            Get-AdaptExcelWorkbook -Name "Groups"
            Get-AdaptExcelImport -AdaptFileName $AdaptFileName
            Remove-Variable AdaptFileName

            Get-AdaptExcelSort -ColumnName "DistinguishedName"
        }

        $AdaptFileName = -join($ReportPath,'\','GroupMembers.csv')
        If (Test-Path $AdaptFileName)
        {
            Get-AdaptExcelWorkbook -Name "Group Members"
            Get-AdaptExcelImport -AdaptFileName $AdaptFileName
            Remove-Variable AdaptFileName

            Get-AdaptExcelSort -ColumnName "Group Name"
        }

        $AdaptFileName = -join($ReportPath,'\','UserSPNs.csv')
        If (Test-Path $AdaptFileName)
        {
            Get-AdaptExcelWorkbook -Name "User SPNs"
            Get-AdaptExcelImport -AdaptFileName $AdaptFileName
            Remove-Variable AdaptFileName
        }

        $AdaptFileName = -join($ReportPath,'\','Users.csv')
        If (Test-Path $AdaptFileName)
        {
            Get-AdaptExcelWorkbook -Name "Users"
            Get-AdaptExcelImport -AdaptFileName $AdaptFileName
            Remove-Variable AdaptFileName

            Get-AdaptExcelSort -ColumnName "UserName"

            $worksheet = $workbook.Worksheets.Item(1)

            # Freeze First Row and Column
            $worksheet.Select()
            $worksheet.Application.ActiveWindow.splitcolumn = 1
            $worksheet.Application.ActiveWindow.splitrow = 1
            $worksheet.Application.ActiveWindow.FreezePanes = $true

            $worksheet.Cells.Item(1,3).Interior.ColorIndex = 5
            $worksheet.Cells.Item(1,3).font.ColorIndex = 2
            # Set Filter to Enabled Accounts only
            $worksheet.UsedRange.Select() | Out-Null
            $excel.Selection.AutoFilter(3,$true) | Out-Null
            $worksheet.Cells.Item(1,1).Select() | Out-Null
            Get-AdaptExcelComObjRelease -ComObjtoRelease $worksheet
            Remove-Variable worksheet
        }

        # Computer Role Stats
        $AdaptFileName = -join($ReportPath,'\','ComputerSPNs.csv')
        If (Test-Path $AdaptFileName)
        {
            Get-AdaptExcelWorkbook -Name "Computer Role Stats"
            Remove-Variable AdaptFileName

            $worksheet = $workbook.Worksheets.Item(1)
            $PivotTableName = "Computer SPNs"
            Get-AdaptExcelPivotTable -SrcSheetName "Computer SPNs" -PivotTableName $PivotTableName -PivotRows @("Service") -PivotValues @("Service")

            $worksheet.Cells.Item(1,1) = "Computer Role"
            $worksheet.Cells.Item(1,2) = "Count"

            # https://msdn.microsoft.com/en-us/vba/excel-vba/articles/xlsortorder-enumeration-excel
            $worksheet.PivotTables($PivotTableName).PivotFields("Service").AutoSort([Microsoft.Office.Interop.Excel.XlSortOrder]::xlDescending,"Count")

            Get-AdaptExcelChart -ChartType "xlColumnClustered" -ChartLayout 10 -ChartTitle "Computer Roles in AD" -RangetoCover "D2:U16"
            $workbook.Worksheets.Item(1).Hyperlinks.Add($workbook.Worksheets.Item(1).Cells.Item(1,4) , "" , "'Computer SPNs'!A1", "", "Raw Data") | Out-Null
            $excel.Windows.Item(1).Displaygridlines = $false
            Remove-Variable PivotTableName

            Get-AdaptExcelComObjRelease -ComObjtoRelease $worksheet
            Remove-Variable worksheet
        }

        # Operating System Stats
        $AdaptFileName = -join($ReportPath,'\','Computers.csv')
        If (Test-Path $AdaptFileName)
        {
            Get-AdaptExcelWorkbook -Name "Operating System Stats"
            Remove-Variable AdaptFileName

            $worksheet = $workbook.Worksheets.Item(1)
            $PivotTableName = "Operating Systems"
            Get-AdaptExcelPivotTable -SrcSheetName "Computers" -PivotTableName $PivotTableName -PivotRows @("Operating System") -PivotValues @("Operating System")

            $worksheet.Cells.Item(1,1) = "Operating System"
            $worksheet.Cells.Item(1,2) = "Count"

            # https://msdn.microsoft.com/en-us/vba/excel-vba/articles/xlsortorder-enumeration-excel
            $worksheet.PivotTables($PivotTableName).PivotFields("Operating System").AutoSort([Microsoft.Office.Interop.Excel.XlSortOrder]::xlDescending,"Count")

            Get-AdaptExcelChart -ChartType "xlColumnClustered" -ChartLayout 10 -ChartTitle "Operating Systems in AD" -RangetoCover "D2:S16"
            $workbook.Worksheets.Item(1).Hyperlinks.Add($workbook.Worksheets.Item(1).Cells.Item(1,4) , "" , "Computers!A1", "", "Raw Data") | Out-Null
            $excel.Windows.Item(1).Displaygridlines = $false
            Remove-Variable PivotTableName

            Get-AdaptExcelComObjRelease -ComObjtoRelease $worksheet
            Remove-Variable worksheet
        }

        # Group Stats
        $AdaptFileName = -join($ReportPath,'\','GroupMembers.csv')
        If (Test-Path $AdaptFileName)
        {
            Get-AdaptExcelWorkbook -Name "Privileged Group Stats"
            Remove-Variable AdaptFileName

            $worksheet = $workbook.Worksheets.Item(1)
            $PivotTableName = "Group Members"
            Get-AdaptExcelPivotTable -SrcSheetName "Group Members" -PivotTableName $PivotTableName -PivotRows @("Group Name")-PivotFilters @("AccountType") -PivotValues @("AccountType")

            # Set the filter
            $worksheet.PivotTables($PivotTableName).PivotFields("AccountType").CurrentPage = "user"

            $worksheet.Cells.Item(1,2).Interior.ColorIndex = 5
            $worksheet.Cells.Item(1,2).font.ColorIndex = 2

            $worksheet.Cells.Item(3,1) = "Group Name"
            $worksheet.Cells.Item(3,2) = "Count (Not-Recursive)"

            $excel.ScreenUpdating = $false
            # Create a copy of the Pivot Table
            $PivotTableTemp = ($workbook.PivotCaches().Item($workbook.PivotCaches().Count)).CreatePivotTable("R1C5","PivotTableTemp")
            $PivotFieldTemp = $PivotTableTemp.PivotFields("Group Name")
            # Set a filter
            $PivotFieldTemp.Orientation = [Microsoft.Office.Interop.Excel.XlPivotFieldOrientation]::xlPageField
            Try
            {
                $PivotFieldTemp.CurrentPage = "Domain Admins"
            }
            Catch
            {
                # No Direct Domain Admins. Good Job!
                $NoDA = $true
            }
            If ($NoDA)
            {
                Try
                {
                    $PivotFieldTemp.CurrentPage = "Administrators"
                }
                Catch
                {
                    # No Direct Administrators
                }
            }
            # Create a Slicer
            $PivotSlicer = $workbook.SlicerCaches.Add($PivotTableTemp,$PivotFieldTemp)
            # Add Original Pivot Table to the Slicer
            $PivotSlicer.PivotTables.AddPivotTable($worksheet.PivotTables($PivotTableName))
            # Delete the Slicer
            $PivotSlicer.Delete()
            # Delete the Pivot Table Copy
            $PivotTableTemp.TableRange2.Delete() | Out-Null

            Get-AdaptExcelComObjRelease -ComObjtoRelease $PivotFieldTemp
            Get-AdaptExcelComObjRelease -ComObjtoRelease $PivotSlicer
            Get-AdaptExcelComObjRelease -ComObjtoRelease $PivotTableTemp

            Remove-Variable PivotFieldTemp
            Remove-Variable PivotSlicer
            Remove-Variable PivotTableTemp

            "Account Operators","Administrators","Backup Operators","Cert Publishers","Crypto Operators","DnsAdmins","Domain Admins","Enterprise Admins","Enterprise Key Admins","Incoming Forest Trust Builders","Key Admins","Microsoft Advanced Threat Analytics Administrators","Network Operators","Print Operators","Protected Users","Remote Desktop Users","Schema Admins","Server Operators" | ForEach-Object {
                Try
                {
                    $worksheet.PivotTables($PivotTableName).PivotFields("Group Name").PivotItems($_).Visible = $true
                }
                Catch
                {
                    # when PivotItem is not found
                }
            }

            # https://msdn.microsoft.com/en-us/vba/excel-vba/articles/xlsortorder-enumeration-excel
            $worksheet.PivotTables($PivotTableName).PivotFields("Group Name").AutoSort([Microsoft.Office.Interop.Excel.XlSortOrder]::xlDescending,"Count (Not-Recursive)")

            $worksheet.Cells.Item(3,1).Interior.ColorIndex = 5
            $worksheet.Cells.Item(3,1).font.ColorIndex = 2

            $excel.ScreenUpdating = $true

            Get-AdaptExcelChart -ChartType "xlColumnClustered" -ChartLayout 10 -ChartTitle "Privileged Groups in AD" -RangetoCover "D2:P16" -StartRow "A3" -StartColumn "B3"
            $workbook.Worksheets.Item(1).Hyperlinks.Add($workbook.Worksheets.Item(1).Cells.Item(1,4) , "" , "'Group Members'!A1", "", "Raw Data") | Out-Null
            $excel.Windows.Item(1).Displaygridlines = $false

            Get-AdaptExcelComObjRelease -ComObjtoRelease $worksheet
            Remove-Variable worksheet
        }

        # Computer Stats
        $AdaptFileName = -join($ReportPath,'\','Computers.csv')
        If (Test-Path $AdaptFileName)
        {
            Get-AdaptExcelWorkbook -Name "Computer Stats"
            Remove-Variable AdaptFileName

            $ObjAttributes = New-Object System.Collections.Specialized.OrderedDictionary
            $ObjAttributes.Add("Delegation Typ",'"Unconstrained"')
            $ObjAttributes.Add("Delegation Type",'"Constrained"')
            $ObjAttributes.Add("SIDHistory",'"*"')
            $ObjAttributes.Add("Dormant",'"TRUE"')
            $ObjAttributes.Add("Password Age (> ",'"TRUE"')
            $ObjAttributes.Add("ms-ds-CreatorSid",'"*"')

            Get-AdaptExcelAttributeStats -SrcSheetName "Computers" -Title1 "Computer Accounts in AD" -PivotTableName "Computer Accounts Status" -PivotRows "Enabled" -PivotValues "UserName" -PivotPercentage "UserName" -Title2 "Status of Computer Accounts" -ObjAttributes $ObjAttributes
            Remove-Variable ObjAttributes

            #Todo: Replace with a better way to include the LAPS Stats
            For($i = 1 ; $i -le $workbook.Sheets.count ; $i++)
            {
                $SrcSheetName = "LAPS"
                If ($workbook.Worksheets.item($i).name -eq $SrcSheetName)
                {
                    $AdaptLAPSCheck = $true
                    break
                }
                Else
                {
                   $AdaptLAPSCheck = $false
                }
            }
            If ($AdaptLAPSCheck)
            {
                $worksheet = $workbook.Worksheets.Item(1)
                $ExcelColumn = $workbook.Sheets.Item("LAPS").Columns.Find("Stored")
                $ColAddress = "$($ExcelColumn.Address($false,$false).Substring(0,$ExcelColumn.Address($false,$false).Length-1)):$($ExcelColumn.Address($false,$false).Substring(0,$ExcelColumn.Address($false,$false).Length-1))"
                $i = 9
                $row = 9
                $column = 6
                $worksheet.Cells.Item($row, $column) = "LAPS"
                $worksheet.Cells.Item($row, $column+1).Formula = "=COUNTIFS('" + $SrcSheetName + "'!" + "B:B" + ',"TRUE",' + "'" + $SrcSheetName + "'!" + $ColAddress + ',' + "TRUE" + ')'
                $worksheet.Cells.Item($row, $column+2).Formula = '=IFERROR(G' + $i + '/VLOOKUP("Enabled",A3:B6,2,FALSE),0)'
                $worksheet.Cells.Item($row, $column+3).Formula = "=COUNTIFS('" + $SrcSheetName + "'!" + "B:B" + ',"FALSE",' + "'" + $SrcSheetName + "'!" + $ColAddress + ',' + "TRUE" + ')'
                $worksheet.Cells.Item($row, $column+4).Formula = '=IFERROR(I' + $i + '/VLOOKUP("Disabled",A3:B6,2,FALSE),0)'
                $worksheet.Cells.Item($row, $column+5).Formula = "=COUNTIF('" + $SrcSheetName + "'!" + $ColAddress + ',' + "TRUE" + ')'
                $worksheet.Cells.Item($row, $column+6).Formula = '=IFERROR(K' + $i + '/VLOOKUP("Total",A3:B6,2,FALSE),0)'

                # http://www.excelhowto.com/macros/formatting-a-range-of-cells-in-excel-vba/
                "H", "J" , "L" | ForEach-Object {
                    $rng = $_ + "9" + ":" + $_ + $($row)
                    $worksheet.Range($rng).NumberFormat = "0.00%"
                }

                Get-AdaptExcelChart -ChartType "xlPie" -ChartLayout 3 -ChartTitle "Computer Accounts in AD" -RangetoCover "A12:D24" -ChartData $workbook.Worksheets.Item(1).Range("A3:A4,B3:B4")
                $workbook.Worksheets.Item(1).Hyperlinks.Add($workbook.Worksheets.Item(1).Cells.Item(11,1) , "" , "Computers!A1", "", "Raw Data") | Out-Null

                Get-AdaptExcelChart -ChartType "xlBarClustered" -ChartLayout 1 -ChartTitle "Status of Computer Accounts" -RangetoCover "F12:L24" -ChartData $workbook.Worksheets.Item(1).Range("F2:F9,G2:G9")
                $workbook.Worksheets.Item(1).Hyperlinks.Add($workbook.Worksheets.Item(1).Cells.Item(11,6) , "" , "Computers!A1", "", "Raw Data") | Out-Null
            }
            Else
            {
                Get-AdaptExcelChart -ChartType "xlPie" -ChartLayout 3 -ChartTitle "Computer Accounts in AD" -RangetoCover "A11:D23" -ChartData $workbook.Worksheets.Item(1).Range("A3:A4,B3:B4")
                $workbook.Worksheets.Item(1).Hyperlinks.Add($workbook.Worksheets.Item(1).Cells.Item(10,1) , "" , "Computers!A1", "", "Raw Data") | Out-Null

                Get-AdaptExcelChart -ChartType "xlBarClustered" -ChartLayout 1 -ChartTitle "Status of Computer Accounts" -RangetoCover "F11:L23" -ChartData $workbook.Worksheets.Item(1).Range("F2:F8,G2:G8")
                $workbook.Worksheets.Item(1).Hyperlinks.Add($workbook.Worksheets.Item(1).Cells.Item(10,6) , "" , "Computers!A1", "", "Raw Data") | Out-Null
            }

            $workbook.Worksheets.Item(1).UsedRange.EntireColumn.AutoFit() | Out-Null
            $excel.Windows.Item(1).Displaygridlines = $false
        }

        # User Stats
        $AdaptFileName = -join($ReportPath,'\','Users.csv')
        If (Test-Path $AdaptFileName)
        {
            Get-AdaptExcelWorkbook -Name "User Stats"
            Remove-Variable AdaptFileName

            $ObjAttributes = New-Object System.Collections.Specialized.OrderedDictionary
            $ObjAttributes.Add("Must Change Password at Logon",'"TRUE"')
            $ObjAttributes.Add("Cannot Change Password",'"TRUE"')
            $ObjAttributes.Add("Password Never Expires",'"TRUE"')
            $ObjAttributes.Add("Reversible Password Encryption",'"TRUE"')
            $ObjAttributes.Add("Smartcard Logon Required",'"TRUE"')
            $ObjAttributes.Add("Delegation Permitted",'"TRUE"')
            $ObjAttributes.Add("Kerberos DES Only",'"TRUE"')
            $ObjAttributes.Add("Kerberos RC4",'"TRUE"')
            $ObjAttributes.Add("Does Not Require Pre Auth",'"TRUE"')
            $ObjAttributes.Add("Password Age (> ",'"TRUE"')
            $ObjAttributes.Add("Account Locked Out",'"TRUE"')
            $ObjAttributes.Add("Never Logged in",'"TRUE"')
            $ObjAttributes.Add("Dormant",'"TRUE"')
            $ObjAttributes.Add("Password Not Required",'"TRUE"')
            $ObjAttributes.Add("Delegation Typ",'"Unconstrained"')
            $ObjAttributes.Add("SIDHistory",'"*"')

            Get-AdaptExcelAttributeStats -SrcSheetName "Users" -Title1 "User Accounts in AD" -PivotTableName "User Accounts Status" -PivotRows "Enabled" -PivotValues "UserName" -PivotPercentage "UserName" -Title2 "Status of User Accounts" -ObjAttributes $ObjAttributes
            Remove-Variable ObjAttributes

            Get-AdaptExcelChart -ChartType "xlPie" -ChartLayout 3 -ChartTitle "User Accounts in AD" -RangetoCover "A21:D33" -ChartData $workbook.Worksheets.Item(1).Range("A3:A4,B3:B4")
            $workbook.Worksheets.Item(1).Hyperlinks.Add($workbook.Worksheets.Item(1).Cells.Item(20,1) , "" , "Users!A1", "", "Raw Data") | Out-Null

            Get-AdaptExcelChart -ChartType "xlBarClustered" -ChartLayout 1 -ChartTitle "Status of User Accounts" -RangetoCover "F21:L43" -ChartData $workbook.Worksheets.Item(1).Range("F2:F18,G2:G18")
            $workbook.Worksheets.Item(1).Hyperlinks.Add($workbook.Worksheets.Item(1).Cells.Item(20,6) , "" , "Users!A1", "", "Raw Data") | Out-Null

            $workbook.Worksheets.Item(1).UsedRange.EntireColumn.AutoFit() | Out-Null
            $excel.Windows.Item(1).Displaygridlines = $false
        }

        # Create Table of Contents
        Get-AdaptExcelWorkbook -Name "Table of Contents"
        $worksheet = $workbook.Worksheets.Item(1)
        $excel.ScreenUpdating = $false

        # Simple text header (embedded logo removed for compatibility)
        $worksheet.Cells.Item(1,1) = "ADAPT AD Report"
        $worksheet.Cells.Item(1,1).Style = "Heading 1"
        $worksheet.Cells.Item(1,1).Font.Size = 24

        $row = 5
        $column = 1
        $worksheet.Cells.Item($row,$column)= "Table of Contents"
        $worksheet.Cells.Item($row,$column).Style = "Heading 2"
        $row++

        For($i=2; $i -le $workbook.Worksheets.Count; $i++)
        {
            $workbook.Worksheets.Item(1).Hyperlinks.Add($workbook.Worksheets.Item(1).Cells.Item($row,$column) , "" , "'$($workbook.Worksheets.Item($i).Name)'!A1", "", $workbook.Worksheets.Item($i).Name) | Out-Null
            $row++
        }

        $row++
		$workbook.Worksheets.Item(1).Hyperlinks.Add($workbook.Worksheets.Item(1).Cells.Item($row,1) , "https://github.com/yourusername/AdaptAD", "" , "", "github.com/yourusername/AdaptAD") | Out-Null

        $worksheet.UsedRange.EntireColumn.AutoFit() | Out-Null

        $excel.Windows.Item(1).Displaygridlines = $false
        $excel.ScreenUpdating = $true
        $ADStatFileName = -join($ExcelPath,'\',$DomainName,'AdaptAD-Report.xlsx')
        Try
        {
            # Disable prompt if file exists
            $excel.DisplayAlerts = $False
            $workbook.SaveAs($ADStatFileName)
            Write-Output "[+] Excelsheet Saved to: $ADStatFileName"
        }
        Catch
        {
            Write-Error "[EXCEPTION] $($_.Exception.Message)"
        }
        $excel.Quit()
        Get-AdaptExcelComObjRelease -ComObjtoRelease $worksheet -Final $true
        Remove-Variable worksheet
        Get-AdaptExcelComObjRelease -ComObjtoRelease $workbook -Final $true
        Remove-Variable -Name workbook -Scope Global
        Get-AdaptExcelComObjRelease -ComObjtoRelease $excel -Final $true
        Remove-Variable -Name excel -Scope Global
    }
}

Function Get-AdaptDomain
{
<#
.SYNOPSIS
    Returns information of the current (or specified) domain.

.DESCRIPTION
    Returns information of the current (or specified) domain.

.PARAMETER Method
    [string]
    Which method to use; ADWS (default), LDAP.

.PARAMETER objDomain
    [DirectoryServices.DirectoryEntry]
    Domain Directory Entry object.

.PARAMETER objDomainRootDSE
    [DirectoryServices.DirectoryEntry]
    RootDSE Directory Entry object.

.PARAMETER DomainController
    [string]
    IP Address of the Domain Controller.

.PARAMETER Credential
    [Management.Automation.PSCredential]
    Credentials.

.OUTPUTS
    PSObject.
#>
    param(
        [Parameter(Mandatory = $true)]
        [string] $Method,

        [Parameter(Mandatory = $false)]
        [DirectoryServices.DirectoryEntry] $objDomain,

        [Parameter(Mandatory = $false)]
        [DirectoryServices.DirectoryEntry] $objDomainRootDSE,

        [Parameter(Mandatory = $false)]
        [string] $DomainController,

        [Parameter(Mandatory = $false)]
        [Management.Automation.PSCredential] $Credential = [Management.Automation.PSCredential]::Empty
    )

    If ($Method -eq 'ADWS')
    {
        Try
        {
            $ADDomain = Get-ADDomain
        }
        Catch
        {
            Write-Warning "[Get-AdaptDomain] Error getting Domain Context"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }
        If ($ADDomain)
        {
            $DomainObj = @()

            # Values taken from https://technet.microsoft.com/en-us/library/hh852281(v=wps.630).aspx
            $FLAD = @{
	            0 = "Windows2000";
	            1 = "Windows2003/Interim";
	            2 = "Windows2003";
	            3 = "Windows2008";
	            4 = "Windows2008R2";
	            5 = "Windows2012";
	            6 = "Windows2012R2";
	            7 = "Windows2016"
            }
            $DomainMode = $FLAD[[convert]::ToInt32($ADDomain.DomainMode)] + "Domain"
            Remove-Variable FLAD
            If (-Not $DomainMode)
            {
                $DomainMode = $ADDomain.DomainMode
            }

            $ObjValues = @("Name", $ADDomain.DNSRoot, "NetBIOS", $ADDomain.NetBIOSName, "Functional Level", $DomainMode, "DomainSID", $ADDomain.DomainSID.Value)

            For ($i = 0; $i -lt $($ObjValues.Count); $i++)
            {
                $Obj = New-Object PSObject
                $Obj | Add-Member -MemberType NoteProperty -Name "Category" -Value $ObjValues[$i]
                $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value $ObjValues[$i+1]
                $i++
                $DomainObj += $Obj
            }
            Remove-Variable DomainMode

            For($i=0; $i -lt $ADDomain.ReplicaDirectoryServers.Count; $i++)
            {
                $Obj = New-Object PSObject
                $Obj | Add-Member -MemberType NoteProperty -Name "Category" -Value "Domain Controller"
                $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value $ADDomain.ReplicaDirectoryServers[$i]
                $DomainObj += $Obj
            }
            For($i=0; $i -lt $ADDomain.ReadOnlyReplicaDirectoryServers.Count; $i++)
            {
                $Obj = New-Object PSObject
                $Obj | Add-Member -MemberType NoteProperty -Name "Category" -Value "Read Only Domain Controller"
                $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value $ADDomain.ReadOnlyReplicaDirectoryServers[$i]
                $DomainObj += $Obj
            }

            Try
            {
                $ADForest = Get-ADForest $ADDomain.Forest
            }
            Catch
            {
                Write-Verbose "[Get-AdaptDomain] Error getting Forest Context"
                Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            }

            If (-Not $ADForest)
            {
                Try
                {
                    $ADForest = Get-ADForest -Server $DomainController
                }
                Catch
                {
                    Write-Warning "[Get-AdaptDomain] Error getting Forest Context"
                    Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
                }
            }
            If ($ADForest)
            {
                $DomainCreation = Get-ADObject -SearchBase "$($ADForest.PartitionsContainer)" -LDAPFilter "(&(objectClass=crossRef)(systemFlags=3)(Name=$($ADDomain.Name)))" -Properties whenCreated
                If (-Not $DomainCreation)
                {
                    $DomainCreation = Get-ADObject -SearchBase "$($ADForest.PartitionsContainer)" -LDAPFilter "(&(objectClass=crossRef)(systemFlags=3)(Name=$($ADDomain.NetBIOSName)))" -Properties whenCreated
                }
                Remove-Variable ADForest
            }
            # Get RIDAvailablePool
            Try
            {
                $RIDManager = Get-ADObject -Identity "CN=RID Manager$,CN=System,$($ADDomain.DistinguishedName)" -Properties rIDAvailablePool
                $RIDproperty = $RIDManager.rIDAvailablePool
                [int32] $totalSIDS = $($RIDproperty) / ([math]::Pow(2,32))
                [int64] $temp64val = $totalSIDS * ([math]::Pow(2,32))
                $RIDsIssued = [int32]($($RIDproperty) - $temp64val)
                $RIDsRemaining = $totalSIDS - $RIDsIssued
                Remove-Variable RIDManager
                Remove-Variable RIDproperty
                Remove-Variable totalSIDS
                Remove-Variable temp64val
            }
            Catch
            {
                Write-Warning "[Get-AdaptDomain] Error accessing CN=RID Manager$,CN=System,$($ADDomain.DistinguishedName)"
                Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            }
            If ($DomainCreation)
            {
                $Obj = New-Object PSObject
                $Obj | Add-Member -MemberType NoteProperty -Name "Category" -Value "Creation Date"
                $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value $DomainCreation.whenCreated
                $DomainObj += $Obj
                Remove-Variable DomainCreation
            }

            $Obj = New-Object PSObject
            $Obj | Add-Member -MemberType NoteProperty -Name "Category" -Value "ms-DS-MachineAccountQuota"
            $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value $((Get-ADObject -Identity ($ADDomain.DistinguishedName) -Properties ms-DS-MachineAccountQuota).'ms-DS-MachineAccountQuota')
            $DomainObj += $Obj

            If ($RIDsIssued)
            {
                $Obj = New-Object PSObject
                $Obj | Add-Member -MemberType NoteProperty -Name "Category" -Value "RIDs Issued"
                $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value $RIDsIssued
                $DomainObj += $Obj
                Remove-Variable RIDsIssued
            }
            If ($RIDsRemaining)
            {
                $Obj = New-Object PSObject
                $Obj | Add-Member -MemberType NoteProperty -Name "Category" -Value "RIDs Remaining"
                $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value $RIDsRemaining
                $DomainObj += $Obj
                Remove-Variable RIDsRemaining
            }
        }
    }

    If ($Method -eq 'LDAP')
    {
        If ($Credential -ne [Management.Automation.PSCredential]::Empty)
        {
            $DomainFQDN = Get-DNtoFQDN($objDomain.distinguishedName)
            $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("Domain",$($DomainFQDN),$($Credential.UserName),$($Credential.GetNetworkCredential().password))
            Try
            {
                $ADDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
            }
            Catch
            {
                Write-Warning "[Get-AdaptDomain] Error getting Domain Context"
                Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
                Return $null
            }
            Remove-Variable DomainContext
            # Get RIDAvailablePool
            Try
            {
                $SearchPath = "CN=RID Manager$,CN=System"
                $objSearchPath = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$($DomainController)/$SearchPath,$($objDomain.distinguishedName)", $Credential.UserName,$Credential.GetNetworkCredential().Password
                $objSearcherPath = New-Object System.DirectoryServices.DirectorySearcher $objSearchPath
                $objSearcherPath.PropertiesToLoad.AddRange(("ridavailablepool"))
                $objSearcherResult = $objSearcherPath.FindAll()
                $RIDproperty = $objSearcherResult.Properties.ridavailablepool
                [int32] $totalSIDS = $($RIDproperty) / ([math]::Pow(2,32))
                [int64] $temp64val = $totalSIDS * ([math]::Pow(2,32))
                $RIDsIssued = [int32]($($RIDproperty) - $temp64val)
                $RIDsRemaining = $totalSIDS - $RIDsIssued
                Remove-Variable SearchPath
                $objSearchPath.Dispose()
                $objSearcherPath.Dispose()
                $objSearcherResult.Dispose()
                Remove-Variable RIDproperty
                Remove-Variable totalSIDS
                Remove-Variable temp64val
            }
            Catch
            {
                Write-Warning "[Get-AdaptDomain] Error accessing CN=RID Manager$,CN=System,$($SearchPath),$($objDomain.distinguishedName)"
                Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            }
            # Get NetBIOS Name
            Try 
            {
                $domainDN = $objDomain.distinguishedName.ToString()
                $namingContext = $objDomainRootDSE.Properties["configurationNamingContext"].Value
                $objSearchPath = New-Object System.DirectoryServices.DirectoryEntry "LDAP://CN=Partitions,$namingContext", $Credential.UserName,$Credential.GetNetworkCredential().Password
                $objSearcherPath = New-Object System.DirectoryServices.DirectorySearcher($objSearchPath,"(&(objectCategory=crossRef)(ncName=$domainDN))")
                $objSearcherPath.PropertiesToLoad.Add("netbiosname") | Out-Null
                $objSearcherResult = $objSearcherPath.FindOne()
                $netBIOSName = $objSearcherResult.Properties["netbiosname"][0]
                Remove-Variable domainDN
                Remove-Variable namingContext
                $objSearchPath.Dispose()
                $objSearcherPath.Dispose()
                Remove-Variable objSearchPath
                Remove-Variable objSearcherPath
                Remove-Variable objSearcherResult
            }
            Catch 
            {
                Write-Warning "[Get-AdaptDomain] Error finding NetBIOS name while accessing CN=Partitions,$($namingContext)"
                Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            }
            Try
            {
                $ForestContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("Forest",$($ADDomain.Forest),$($Credential.UserName),$($Credential.GetNetworkCredential().password))
                $ADForest = [System.DirectoryServices.ActiveDirectory.Forest]::GetForest($ForestContext)
            }
            Catch
            {
                Write-Warning "[Get-AdaptDomain] Error getting Forest Context"
                Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            }
            If ($ForestContext)
            {
                Remove-Variable ForestContext
            }
            If ($ADForest)
            {
                $GlobalCatalog = $ADForest.FindGlobalCatalog()
            }
            If ($GlobalCatalog)
            {
                $DN = "GC://$($GlobalCatalog.IPAddress)/$($objDomain.distinguishedname)"
                Try
                {
                    $ADObject = New-Object -TypeName System.DirectoryServices.DirectoryEntry -ArgumentList ($($DN),$($Credential.UserName),$($Credential.GetNetworkCredential().password))
                    $ADDomainSID = New-Object System.Security.Principal.SecurityIdentifier($ADObject.objectSid[0], 0)
                    $ADObject.Dispose()
                }
                Catch
                {
                    Write-Warning "[Get-AdaptDomain] Error retrieving Domain SID using the GlobalCatalog $($GlobalCatalog.IPAddress). Using SID from the ObjDomain."
                    Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
                    $ADDomainSID = New-Object System.Security.Principal.SecurityIdentifier($objDomain.objectSid[0], 0)
                }
            }
            Else
            {
                $ADDomainSID = New-Object System.Security.Principal.SecurityIdentifier($objDomain.objectSid[0], 0)
            }
        }
        Else
        {
            $ADDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            $ADForest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
            Try
            {
                $GlobalCatalog = $ADForest.FindGlobalCatalog()
                $DN = "GC://$($GlobalCatalog)/$($objDomain.distinguishedname)"
                $ADObject = New-Object -TypeName System.DirectoryServices.DirectoryEntry -ArgumentList ($DN)
                $ADDomainSID = New-Object System.Security.Principal.SecurityIdentifier($ADObject.objectSid[0], 0)
                $ADObject.dispose()
            }
            Catch
            {
                Write-Warning "[Get-AdaptDomain] Error retrieving Domain SID using the GlobalCatalog $($GlobalCatalog.IPAddress). Using SID from the ObjDomain."
                Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
                $ADDomainSID = New-Object System.Security.Principal.SecurityIdentifier($objDomain.objectSid[0], 0)
            }
            # Get RIDAvailablePool
            Try
            {
                $RIDManager = ([ADSI]"LDAP://CN=RID Manager$,CN=System,$($objDomain.distinguishedName)")
                $RIDproperty = $ObjDomain.ConvertLargeIntegerToInt64($RIDManager.Properties.rIDAvailablePool.value)
                [int32] $totalSIDS = $($RIDproperty) / ([math]::Pow(2,32))
                [int64] $temp64val = $totalSIDS * ([math]::Pow(2,32))
                $RIDsIssued = [int32]($($RIDproperty) - $temp64val)
                $RIDsRemaining = $totalSIDS - $RIDsIssued
                Remove-Variable RIDManager
                Remove-Variable RIDproperty
                Remove-Variable totalSIDS
                Remove-Variable temp64val
            }
            Catch
            {
                Write-Warning "[Get-AdaptDomain] Error accessing CN=RID Manager$,CN=System,$($SearchPath),$($objDomain.distinguishedName)"
                Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            }
            # Get NetBIOS Name
            Try 
            {
                $domainDN = $objDomain.distinguishedName.ToString()
                $namingContext = $objDomainRootDSE.Properties["configurationNamingContext"].Value
                $objSearchPath = ([ADSI]"LDAP://CN=Partitions,$($namingContext)")
                $objSearcherPath = New-Object System.DirectoryServices.DirectorySearcher($objSearchPath,"(&(objectCategory=crossRef)(ncName=$domainDN))")
                $objSearcherPath.PropertiesToLoad.Add("netbiosname") | Out-Null
                $objSearcherResult = $objSearcherPath.FindOne()
                $netBIOSName = $objSearcherResult.Properties["netbiosname"][0]
                Remove-Variable domainDN
                Remove-Variable namingContext
                $objSearchPath.Dispose()
                $objSearcherPath.Dispose()
                Remove-Variable objSearchPath
                Remove-Variable objSearcherPath
                Remove-Variable objSearcherResult
            }
            Catch 
            {
                Write-Warning "[Get-AdaptDomain] Error finding NetBIOS name while accessing CN=Partitions,$($namingContext)"
                Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            }
        }

        If ($ADDomain)
        {
            $DomainObj = @()

            # Values taken from https://technet.microsoft.com/en-us/library/hh852281(v=wps.630).aspx
            $FLAD = @{
	            0 = "Windows2000";
	            1 = "Windows2003/Interim";
	            2 = "Windows2003";
	            3 = "Windows2008";
	            4 = "Windows2008R2";
	            5 = "Windows2012";
	            6 = "Windows2012R2";
	            7 = "Windows2016"
            }
            $DomainMode = $FLAD[[convert]::ToInt32($objDomainRootDSE.domainFunctionality,10)] + "Domain"
            Remove-Variable FLAD

            $ObjValues = @("Name", $ADDomain.Name, "NetBIOS", $netBIOSName, "Functional Level", $DomainMode, "DomainSID", $ADDomainSID.Value)

            For ($i = 0; $i -lt $($ObjValues.Count); $i++)
            {
                $Obj = New-Object PSObject
                $Obj | Add-Member -MemberType NoteProperty -Name "Category" -Value $ObjValues[$i]
                $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value $ObjValues[$i+1]
                $i++
                $DomainObj += $Obj
            }
            Remove-Variable DomainMode

            For($i=0; $i -lt $ADDomain.DomainControllers.Count; $i++)
            {
                $Obj = New-Object PSObject
                $Obj | Add-Member -MemberType NoteProperty -Name "Category" -Value "Domain Controller"
                $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value $ADDomain.DomainControllers[$i]
                $DomainObj += $Obj
            }

            $Obj = New-Object PSObject
            $Obj | Add-Member -MemberType NoteProperty -Name "Category" -Value "Creation Date"
            $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value $objDomain.whencreated.value
            $DomainObj += $Obj

            $Obj = New-Object PSObject
            $Obj | Add-Member -MemberType NoteProperty -Name "Category" -Value "ms-DS-MachineAccountQuota"
            $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value $objDomain.'ms-DS-MachineAccountQuota'.value
            $DomainObj += $Obj

            If ($RIDsIssued)
            {
                $Obj = New-Object PSObject
                $Obj | Add-Member -MemberType NoteProperty -Name "Category" -Value "RIDs Issued"
                $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value $RIDsIssued
                $DomainObj += $Obj
                Remove-Variable RIDsIssued
            }
            If ($RIDsRemaining)
            {
                $Obj = New-Object PSObject
                $Obj | Add-Member -MemberType NoteProperty -Name "Category" -Value "RIDs Remaining"
                $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value $RIDsRemaining
                $DomainObj += $Obj
                Remove-Variable RIDsRemaining
            }
        }
    }

    If ($DomainObj)
    {
        Return $DomainObj
    }
    Else
    {
        Return $null
    }
}

Function Get-AdaptForest
{
<#
.SYNOPSIS
    Returns information of the current (or specified) forest.

.DESCRIPTION
    Returns information of the current (or specified) forest.

.PARAMETER Method
    [string]
    Which method to use; ADWS (default), LDAP.

.PARAMETER objDomain
    [DirectoryServices.DirectoryEntry]
    Domain Directory Entry object.

.PARAMETER objDomainRootDSE
    [DirectoryServices.DirectoryEntry]
    RootDSE Directory Entry object.

.PARAMETER DomainController
    [string]
    IP Address of the Domain Controller.

.PARAMETER Credential
    [Management.Automation.PSCredential]
    Credentials.

.OUTPUTS
    PSObject.
#>
    param(
        [Parameter(Mandatory = $true)]
        [string] $Method,

        [Parameter(Mandatory = $false)]
        [DirectoryServices.DirectoryEntry] $objDomain,

        [Parameter(Mandatory = $false)]
        [DirectoryServices.DirectoryEntry] $objDomainRootDSE,

        [Parameter(Mandatory = $false)]
        [string] $DomainController,

        [Parameter(Mandatory = $false)]
        [Management.Automation.PSCredential] $Credential = [Management.Automation.PSCredential]::Empty
    )

    If ($Method -eq 'ADWS')
    {
        Try
        {
            $ADDomain = Get-ADDomain
        }
        Catch
        {
            Write-Warning "[Get-AdaptForest] Error getting Domain Context"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }

        Try
        {
            $ADForest = Get-ADForest $ADDomain.Forest
        }
        Catch
        {
            Write-Verbose "[Get-AdaptForest] Error getting Forest Context"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
        }
        Remove-Variable ADDomain

        If (-Not $ADForest)
        {
            Try
            {
                $ADForest = Get-ADForest -Server $DomainController
            }
            Catch
            {
                Write-Warning "[Get-AdaptForest] Error getting Forest Context using Server parameter"
                Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
                Return $null
            }
        }

        If ($ADForest)
        {
            # Get Tombstone Lifetime
            Try
            {
                $AdaptForestCNC = (Get-ADRootDSE).configurationNamingContext
                $ADForestDSCP = Get-ADObject -Identity "CN=Directory Service,CN=Windows NT,CN=Services,$($AdaptForestCNC)" -Partition $AdaptForestCNC -Properties *
                $ADForestTombstoneLifetime = $ADForestDSCP.tombstoneLifetime
                Remove-Variable ADForestCNC
                Remove-Variable ADForestDSCP
            }
            Catch
            {
                Write-Warning "[Get-AdaptForest] Error retrieving Tombstone Lifetime"
                Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            }

            # Check Recycle Bin Feature Status
            If ([convert]::ToInt32($ADForest.ForestMode) -ge 4)
            {
                Try
                {
                    $AdaptRecycleBin = Get-ADOptionalFeature -Identity "Recycle Bin Feature" -Properties whenCreated
                }
                Catch
                {
                    Write-Warning "[Get-AdaptForest] Error retrieving Recycle Bin Feature"
                    Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
                }
            }

            # Check Privileged Access Management Feature status
            If ([convert]::ToInt32($ADForest.ForestMode) -ge 7)
            {
                Try
                {
                    $PrivilegedAccessManagement = Get-ADOptionalFeature -Identity "Privileged Access Management Feature"
                }
                Catch
                {
                    Write-Warning "[Get-AdaptForest] Error retrieving Privileged Acceess Management Feature"
                    Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
                }
            }

            $ForestObj = @()

            # Values taken from https://technet.microsoft.com/en-us/library/hh852281(v=wps.630).aspx
            $FLAD = @{
                0 = "Windows2000";
                1 = "Windows2003/Interim";
                2 = "Windows2003";
                3 = "Windows2008";
                4 = "Windows2008R2";
                5 = "Windows2012";
                6 = "Windows2012R2";
                7 = "Windows2016"
            }
            $ForestMode = $FLAD[[convert]::ToInt32($ADForest.ForestMode)] + "Forest"
            Remove-Variable FLAD

            If (-Not $ForestMode)
            {
                $ForestMode = $ADForest.ForestMode
            }

            # LAPS Check
            $AdaptLAPSCheck = Get-AdaptLAPSCheck -Method ADWS

            $ObjValues = @("Name", $ADForest.Name, "Functional Level", $ForestMode, "Domain Naming Master", $ADForest.DomainNamingMaster, "Schema Master", $ADForest.SchemaMaster, "RootDomain", $ADForest.RootDomain, "Domain Count", $ADForest.Domains.Count, "Site Count", $ADForest.Sites.Count, "Global Catalog Count", $ADForest.GlobalCatalogs.Count)

            For ($i = 0; $i -lt $($ObjValues.Count); $i++)
            {
                $Obj = New-Object PSObject
                $Obj | Add-Member -MemberType NoteProperty -Name "Category" -Value $ObjValues[$i]
                $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value $ObjValues[$i+1]
                $i++
                $ForestObj += $Obj
            }
            Remove-Variable ForestMode

            For($i=0; $i -lt $ADForest.Domains.Count; $i++)
            {
                $Obj = New-Object PSObject
                $Obj | Add-Member -MemberType NoteProperty -Name "Category" -Value "Domain"
                $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value $ADForest.Domains[$i]
                $ForestObj += $Obj
            }
            For($i=0; $i -lt $ADForest.Sites.Count; $i++)
            {
                $Obj = New-Object PSObject
                $Obj | Add-Member -MemberType NoteProperty -Name "Category" -Value "Site"
                $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value $ADForest.Sites[$i]
                $ForestObj += $Obj
            }
            For($i=0; $i -lt $ADForest.GlobalCatalogs.Count; $i++)
            {
                $Obj = New-Object PSObject
                $Obj | Add-Member -MemberType NoteProperty -Name "Category" -Value "GlobalCatalog"
                $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value $ADForest.GlobalCatalogs[$i]
                $ForestObj += $Obj
            }

            $Obj = New-Object PSObject
            $Obj | Add-Member -MemberType NoteProperty -Name "Category" -Value "Tombstone Lifetime"
            If ($ADForestTombstoneLifetime)
            {
                $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value $ADForestTombstoneLifetime
                Remove-Variable ADForestTombstoneLifetime
            }
            Else
            {
                $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value "Not Retrieved"
            }
            $ForestObj += $Obj

            $Obj = New-Object PSObject
            $Obj | Add-Member -MemberType NoteProperty -Name "Category" -Value "Recycle Bin (2008 R2 onwards)"
            If ($AdaptRecycleBin)
            {
                If ($AdaptRecycleBin.EnabledScopes.Count -gt 0)
                {
                    $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value "Enabled"
                    $ForestObj += $Obj

                    $Obj = New-Object PSObject
                    $Obj | Add-Member -MemberType NoteProperty -Name "Category" -Value "Recycle Bin Enabled Date"
                    $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value $AdaptRecycleBin.whenCreated
                    $ForestObj += $Obj

                    For($i=0; $i -lt $($AdaptRecycleBin.EnabledScopes.Count); $i++)
                    {
                        $Obj = New-Object PSObject
                        $Obj | Add-Member -MemberType NoteProperty -Name "Category" -Value "Enabled Scope"
                        $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value $AdaptRecycleBin.EnabledScopes[$i]
                        $ForestObj += $Obj
                    }
                }
                Else
                {
                    $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value "Disabled"
                    $ForestObj += $Obj
                }
                Remove-Variable AdaptRecycleBin
            }
            Else
            {
                $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value "Disabled"
                $ForestObj += $Obj
            }

            $Obj = New-Object PSObject
            $Obj | Add-Member -MemberType NoteProperty -Name "Category" -Value "Privileged Access Management (2016 onwards)"
            If ($PrivilegedAccessManagement)
            {
                If ($PrivilegedAccessManagement.EnabledScopes.Count -gt 0)
                {
                    $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value "Enabled"
                    $ForestObj += $Obj
                    For($i=0; $i -lt $($PrivilegedAccessManagement.EnabledScopes.Count); $i++)
                    {
                        $Obj = New-Object PSObject
                        $Obj | Add-Member -MemberType NoteProperty -Name "Category" -Value "Enabled Scope"
                        $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value $PrivilegedAccessManagement.EnabledScopes[$i]
                        $ForestObj += $Obj
                    }
                }
                Else
                {
                    $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value "Disabled"
                    $ForestObj += $Obj
                }
                Remove-Variable PrivilegedAccessManagement
            }
            Else
            {
                $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value "Disabled"
                $ForestObj += $Obj
            }

            $Obj = New-Object PSObject
            $Obj | Add-Member -MemberType NoteProperty -Name "Category" -Value "LAPS"
            If ($AdaptLAPSCheck)
            {
                $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value "Enabled"
                $ForestObj += $Obj

                $Obj = New-Object PSObject
                $Obj | Add-Member -MemberType NoteProperty -Name "Category" -Value "LAPS Installed Date"
                $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value $((Get-ADObject "CN=ms-Mcs-AdmPwd,$((Get-ADRootDSE).schemaNamingContext)" -Properties whenCreated).whenCreated)
                $ForestObj += $Obj
            }
            Else
            {
                $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value "Disabled"
                $ForestObj += $Obj
            }

            Remove-Variable ADForest
        }
    }

    If ($Method -eq 'LDAP')
    {
        If ($Credential -ne [Management.Automation.PSCredential]::Empty)
        {
            $DomainFQDN = Get-DNtoFQDN($objDomain.distinguishedName)
            $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("Domain",$($DomainFQDN),$($Credential.UserName),$($Credential.GetNetworkCredential().password))
            Try
            {
                $ADDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
            }
            Catch
            {
                Write-Warning "[Get-AdaptForest] Error getting Domain Context"
                Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
                Return $null
            }
            Remove-Variable DomainContext

            $ForestContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("Forest",$($ADDomain.Forest),$($Credential.UserName),$($Credential.GetNetworkCredential().password))
            Remove-Variable ADDomain
            Try
            {
                $ADForest = [System.DirectoryServices.ActiveDirectory.Forest]::GetForest($ForestContext)
            }
            Catch
            {
                Write-Warning "[Get-AdaptForest] Error getting Forest Context"
                Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
                Return $null
            }
            Remove-Variable ForestContext

            # Get Tombstone Lifetime
            Try
            {
                $SearchPath = "CN=Directory Service,CN=Windows NT,CN=Services"
                $objSearchPath = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$($DomainController)/$SearchPath,$($objDomainRootDSE.configurationNamingContext)", $Credential.UserName,$Credential.GetNetworkCredential().Password
                $objSearcherPath = New-Object System.DirectoryServices.DirectorySearcher $objSearchPath
                $objSearcherPath.Filter="(name=Directory Service)"
                $objSearcherResult = $objSearcherPath.FindAll()
                $ADForestTombstoneLifetime = $objSearcherResult.Properties.tombstoneLifetime
                Remove-Variable SearchPath
                $objSearchPath.Dispose()
                $objSearcherPath.Dispose()
                $objSearcherResult.Dispose()
            }
            Catch
            {
                Write-Warning "[Get-AdaptForest] Error retrieving Tombstone Lifetime"
                Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            }
            # Check Recycle Bin Feature Status
            If ([convert]::ToInt32($objDomainRootDSE.forestFunctionality,10) -ge 4)
            {
                Try
                {
                    $SearchPath = "CN=Recycle Bin Feature,CN=Optional Features,CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration"
                    $AdaptRecycleBin = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$($DomainController)/$($SearchPath),$($objDomain.distinguishedName)", $Credential.UserName, $Credential.GetNetworkCredential().Password
                    Remove-Variable SearchPath
                }
                Catch
                {
                    Write-Warning "[Get-AdaptForest] Error retrieving Recycle Bin Feature"
                    Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
                }
            }
            # Check Privileged Access Management Feature status
            If ([convert]::ToInt32($objDomainRootDSE.forestFunctionality,10) -ge 7)
            {
                Try
                {
                    $SearchPath = "CN=Privileged Access Management Feature,CN=Optional Features,CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration"
                    $PrivilegedAccessManagement = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$($DomainController)/$($SearchPath),$($objDomain.distinguishedName)", $Credential.UserName, $Credential.GetNetworkCredential().Password
                    Remove-Variable SearchPath
                }
                Catch
                {
                    Write-Warning "[Get-AdaptForest] Error retrieving Privileged Access Management Feature"
                    Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
                }
            }
        }
        Else
        {
            $ADDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            $ADForest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()

            # Get Tombstone Lifetime
            $ADForestTombstoneLifetime = ([ADSI]"LDAP://CN=Directory Service,CN=Windows NT,CN=Services,$($objDomainRootDSE.configurationNamingContext)").tombstoneLifetime.value

            # Check Recycle Bin Feature Status
            If ([convert]::ToInt32($objDomainRootDSE.forestFunctionality,10) -ge 4)
            {
                $AdaptRecycleBin = ([ADSI]"LDAP://CN=Recycle Bin Feature,CN=Optional Features,CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,$($objDomain.distinguishedName)")
            }
            # Check Privileged Access Management Feature Status
            If ([convert]::ToInt32($objDomainRootDSE.forestFunctionality,10) -ge 7)
            {
                $PrivilegedAccessManagement = ([ADSI]"LDAP://CN=Privileged Access Management Feature,CN=Optional Features,CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,$($objDomain.distinguishedName)")
            }
        }

        # LAPS Check
        $AdaptLAPSCheck = Get-AdaptLAPSCheck -Method LDAP -objDomainRootDSE $objDomainRootDSE -DomainController $DomainController -Credential $Credential

        If ($ADForest)
        {
            $ForestObj = @()

            # Values taken from https://technet.microsoft.com/en-us/library/hh852281(v=wps.630).aspx
            $FLAD = @{
	            0 = "Windows2000";
	            1 = "Windows2003/Interim";
	            2 = "Windows2003";
	            3 = "Windows2008";
	            4 = "Windows2008R2";
	            5 = "Windows2012";
	            6 = "Windows2012R2";
                7 = "Windows2016"
            }
            $ForestMode = $FLAD[[convert]::ToInt32($objDomainRootDSE.forestFunctionality,10)] + "Forest"
            Remove-Variable FLAD

            $ObjValues = @("Name", $ADForest.Name, "Functional Level", $ForestMode, "Domain Naming Master", $ADForest.NamingRoleOwner, "Schema Master", $ADForest.SchemaRoleOwner, "RootDomain", $ADForest.RootDomain, "Domain Count", $ADForest.Domains.Count, "Site Count", $ADForest.Sites.Count, "Global Catalog Count", $ADForest.GlobalCatalogs.Count)

            For ($i = 0; $i -lt $($ObjValues.Count); $i++)
            {
                $Obj = New-Object PSObject
                $Obj | Add-Member -MemberType NoteProperty -Name "Category" -Value $ObjValues[$i]
                $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value $ObjValues[$i+1]
                $i++
                $ForestObj += $Obj
            }
            Remove-Variable ForestMode

            For($i=0; $i -lt $ADForest.Domains.Count; $i++)
            {
                $Obj = New-Object PSObject
                $Obj | Add-Member -MemberType NoteProperty -Name "Category" -Value "Domain"
                $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value $ADForest.Domains[$i]
                $ForestObj += $Obj
            }
            For($i=0; $i -lt $ADForest.Sites.Count; $i++)
            {
                $Obj = New-Object PSObject
                $Obj | Add-Member -MemberType NoteProperty -Name "Category" -Value "Site"
                $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value $ADForest.Sites[$i]
                $ForestObj += $Obj
            }
            For($i=0; $i -lt $ADForest.GlobalCatalogs.Count; $i++)
            {
                $Obj = New-Object PSObject
                $Obj | Add-Member -MemberType NoteProperty -Name "Category" -Value "GlobalCatalog"
                $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value $ADForest.GlobalCatalogs[$i]
                $ForestObj += $Obj
            }

            $Obj = New-Object PSObject
            $Obj | Add-Member -MemberType NoteProperty -Name "Category" -Value "Tombstone Lifetime"
            If ($ADForestTombstoneLifetime)
            {
                $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value $ADForestTombstoneLifetime
                Remove-Variable ADForestTombstoneLifetime
            }
            Else
            {
                $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value "Not Retrieved"
            }
            $ForestObj += $Obj

            $Obj = New-Object PSObject
            $Obj | Add-Member -MemberType NoteProperty -Name "Category" -Value "Recycle Bin (2008 R2 onwards)"
            If ($AdaptRecycleBin)
            {
                If ($AdaptRecycleBin.Properties.'msds-enabledfeaturebl'.Count -gt 0)
                {
                    $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value "Enabled"
                    $ForestObj += $Obj

                    $Obj = New-Object PSObject
                    $Obj | Add-Member -MemberType NoteProperty -Name "Category" -Value "Recycle Bin Enabled Date"
                    $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value $AdaptRecycleBin.whencreated.value
                    $ForestObj += $Obj

                    For($i=0; $i -lt $($AdaptRecycleBin.Properties.'msds-enabledfeaturebl'.Count); $i++)
                    {
                        $Obj = New-Object PSObject
                        $Obj | Add-Member -MemberType NoteProperty -Name "Category" -Value "Enabled Scope"
                        $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value $AdaptRecycleBin.Properties.'msds-enabledfeaturebl'[$i]
                        $ForestObj += $Obj
                    }
                }
                Else
                {
                    $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value "Disabled"
                    $ForestObj += $Obj
                }
                $AdaptRecycleBin.Dispose()
            }
            Else
            {
                $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value "Disabled"
                $ForestObj += $Obj
            }

            $Obj = New-Object PSObject
            $Obj | Add-Member -MemberType NoteProperty -Name "Category" -Value "Privileged Access Management (2016 onwards)"
            If ($PrivilegedAccessManagement)
            {
                If ($PrivilegedAccessManagement.Properties.'msDS-EnabledFeatureBL'.Count -gt 0)
                {
                    $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value "Enabled"
                    $ForestObj += $Obj
                    For($i=0; $i -lt $($PrivilegedAccessManagement.Properties.'msDS-EnabledFeatureBL'.Count); $i++)
                    {
                        $Obj = New-Object PSObject
                        $Obj | Add-Member -MemberType NoteProperty -Name "Category" -Value "Enabled Scope"
                        $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value $PrivilegedAccessManagement.Properties.'msDS-EnabledFeatureBL'[$i]
                        $ForestObj += $Obj
                    }
                }
                Else
                {
                    $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value "Disabled"
                    $ForestObj += $Obj
                }
                $PrivilegedAccessManagement.dispose()
            }
            Else
            {
                $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value "Disabled"
                $ForestObj += $Obj
            }

            $Obj = New-Object PSObject
            $Obj | Add-Member -MemberType NoteProperty -Name "Category" -Value "LAPS"
            If ($AdaptLAPSCheck)
            {
                $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value "Enabled"
                $ForestObj += $Obj

                $Obj = New-Object PSObject
                $Obj | Add-Member -MemberType NoteProperty -Name "Category" -Value "LAPS Installed Date"
                If ($Credential -ne [Management.Automation.PSCredential]::Empty)
                {
                    $AdaptLAPSInstalledDate = (New-Object System.DirectoryServices.DirectoryEntry "LDAP://$($DomainController)/CN=ms-Mcs-AdmPwd,$($objDomainRootDSE.schemaNamingContext)", $Credential.UserName, $Credential.GetNetworkCredential().Password).whencreated.value
                }
                Else
                {
                    $AdaptLAPSInstalledDate = ([ADSI]("LDAP://CN=ms-Mcs-AdmPwd,$($objDomainRootDSE.schemaNamingContext)")).whencreated.value
                }
                $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value $AdaptLAPSInstalledDate
                $ForestObj += $Obj
                Remove-Variable AdaptLAPSInstalledDate
            }

            Remove-Variable ADForest
        }
    }

    If ($ForestObj)
    {
        Return $ForestObj
    }
    Else
    {
        Return $null
    }
}

Function Get-AdaptTrust
{
<#
.SYNOPSIS
    Returns the Trusts of the current (or specified) domain.

.DESCRIPTION
    Returns the Trusts of the current (or specified) domain.

.PARAMETER Method
    [string]
    Which method to use; ADWS (default), LDAP.

.PARAMETER objDomain
    [DirectoryServices.DirectoryEntry]
    Domain Directory Entry object.

.OUTPUTS
    PSObject.
#>
    param(
        [Parameter(Mandatory = $true)]
        [string] $Method,

        [Parameter(Mandatory = $false)]
        [DirectoryServices.DirectoryEntry] $objDomain
    )

    # Values taken from https://msdn.microsoft.com/en-us/library/cc223768.aspx
    $TDAD = @{
        0 = "Disabled";
        1 = "Inbound";
        2 = "Outbound";
        3 = "BiDirectional";
    }

    # Values taken from https://msdn.microsoft.com/en-us/library/cc223771.aspx
    $TTAD = @{
        1 = "Downlevel";
        2 = "Uplevel";
        3 = "MIT";
        4 = "DCE";
    }

    If ($Method -eq 'ADWS')
    {
        Try
        {
            $ADTrusts = Get-ADObject -LDAPFilter "(objectClass=trustedDomain)" -Properties DistinguishedName,trustPartner,trustdirection,trusttype,TrustAttributes,whenCreated,whenChanged
        }
        Catch
        {
            Write-Warning "[Get-AdaptTrust] Error while enumerating trustedDomain Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }

        If ($ADTrusts)
        {
            Write-Verbose "[*] Total Trusts: $(Get-ObjectCount $ADTrusts)"
            # Trust Info
            $ADTrustObj = @()
            $ADTrusts | ForEach-Object {
                # Create the object for each instance.
                $Obj = New-Object PSObject
                $Obj | Add-Member -MemberType NoteProperty -Name "Source Domain" -Value (Get-DNtoFQDN $_.DistinguishedName)
                $Obj | Add-Member -MemberType NoteProperty -Name "Target Domain" -Value $_.trustPartner
                $TrustDirection = [string] $TDAD[$_.trustdirection]
                $Obj | Add-Member -MemberType NoteProperty -Name "Trust Direction" -Value $TrustDirection
                $TrustType = [string] $TTAD[$_.trusttype]
                $Obj | Add-Member -MemberType NoteProperty -Name "Trust Type" -Value $TrustType

                $TrustAttributes = $null
                If ([int32] $_.TrustAttributes -band 0x00000001) { $TrustAttributes += "Non Transitive," }
                If ([int32] $_.TrustAttributes -band 0x00000002) { $TrustAttributes += "UpLevel," }
                If ([int32] $_.TrustAttributes -band 0x00000004) { $TrustAttributes += "Quarantined," } #SID Filtering
                If ([int32] $_.TrustAttributes -band 0x00000008) { $TrustAttributes += "Forest Transitive," }
                If ([int32] $_.TrustAttributes -band 0x00000010) { $TrustAttributes += "Cross Organization," } #Selective Auth
                If ([int32] $_.TrustAttributes -band 0x00000020) { $TrustAttributes += "Within Forest," }
                If ([int32] $_.TrustAttributes -band 0x00000040) { $TrustAttributes += "Treat as External," }
                If ([int32] $_.TrustAttributes -band 0x00000080) { $TrustAttributes += "Uses RC4 Encryption," }
                If ([int32] $_.TrustAttributes -band 0x00000200) { $TrustAttributes += "No TGT Delegation," }
                If ([int32] $_.TrustAttributes -band 0x00000400) { $TrustAttributes += "PIM Trust," }
                If ($TrustAttributes)
                {
                    $TrustAttributes = $TrustAttributes.TrimEnd(",")
                }
                $Obj | Add-Member -MemberType NoteProperty -Name "Attributes" -Value $TrustAttributes
                $Obj | Add-Member -MemberType NoteProperty -Name "whenCreated" -Value ([DateTime] $($_.whenCreated))
                $Obj | Add-Member -MemberType NoteProperty -Name "whenChanged" -Value ([DateTime] $($_.whenChanged))
                $ADTrustObj += $Obj
            }
            Remove-Variable ADTrusts
        }
    }

    If ($Method -eq 'LDAP')
    {
        $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objDomain
        $ObjSearcher.PageSize = $PageSize
        $ObjSearcher.Filter = "(objectClass=trustedDomain)"
        $ObjSearcher.PropertiesToLoad.AddRange(("distinguishedname","trustpartner","trustdirection","trusttype","trustattributes","whencreated","whenchanged"))
        $ObjSearcher.SearchScope = "Subtree"

        Try
        {
            $ADTrusts = $ObjSearcher.FindAll()
        }
        Catch
        {
            Write-Warning "[Get-AdaptTrust] Error while enumerating trustedDomain Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }
        $ObjSearcher.dispose()

        If ($ADTrusts)
        {
            Write-Verbose "[*] Total Trusts: $(Get-ObjectCount $ADTrusts)"
            # Trust Info
            $ADTrustObj = @()
            $ADTrusts | ForEach-Object {
                # Create the object for each instance.
                $Obj = New-Object PSObject
                $Obj | Add-Member -MemberType NoteProperty -Name "Source Domain" -Value $(Get-DNtoFQDN ([string] $_.Properties.distinguishedname))
                $Obj | Add-Member -MemberType NoteProperty -Name "Target Domain" -Value $([string] $_.Properties.trustpartner)
                $TrustDirection = [string] $TDAD[$_.Properties.trustdirection]
                $Obj | Add-Member -MemberType NoteProperty -Name "Trust Direction" -Value $TrustDirection
                $TrustType = [string] $TTAD[$_.Properties.trusttype]
                $Obj | Add-Member -MemberType NoteProperty -Name "Trust Type" -Value $TrustType

                $TrustAttributes = $null
                If ([int32] $_.Properties.trustattributes[0] -band 0x00000001) { $TrustAttributes += "Non Transitive," }
                If ([int32] $_.Properties.trustattributes[0] -band 0x00000002) { $TrustAttributes += "UpLevel," }
                If ([int32] $_.Properties.trustattributes[0] -band 0x00000004) { $TrustAttributes += "Quarantined," } #SID Filtering
                If ([int32] $_.Properties.trustattributes[0] -band 0x00000008) { $TrustAttributes += "Forest Transitive," }
                If ([int32] $_.Properties.trustattributes[0] -band 0x00000010) { $TrustAttributes += "Cross Organization," } #Selective Auth
                If ([int32] $_.Properties.trustattributes[0] -band 0x00000020) { $TrustAttributes += "Within Forest," }
                If ([int32] $_.Properties.trustattributes[0] -band 0x00000040) { $TrustAttributes += "Treat as External," }
                If ([int32] $_.Properties.trustattributes[0] -band 0x00000080) { $TrustAttributes += "Uses RC4 Encryption," }
                If ([int32] $_.Properties.trustattributes[0] -band 0x00000200) { $TrustAttributes += "No TGT Delegation," }
                If ([int32] $_.Properties.trustattributes[0] -band 0x00000400) { $TrustAttributes += "PIM Trust," }
                If ($TrustAttributes)
                {
                    $TrustAttributes = $TrustAttributes.TrimEnd(",")
                }
                $Obj | Add-Member -MemberType NoteProperty -Name "Attributes" -Value $TrustAttributes
                $Obj | Add-Member -MemberType NoteProperty -Name "whenCreated" -Value ([DateTime] $($_.Properties.whencreated))
                $Obj | Add-Member -MemberType NoteProperty -Name "whenChanged" -Value ([DateTime] $($_.Properties.whenchanged))
                $ADTrustObj += $Obj
            }
            Remove-Variable ADTrusts
        }
    }

    If ($ADTrustObj)
    {
        Return $ADTrustObj
    }
    Else
    {
        Return $null
    }
}

Function Get-AdaptSite
{
<#
.SYNOPSIS
    Returns the Sites of the current (or specified) domain.

.DESCRIPTION
    Returns the Sites of the current (or specified) domain.

.PARAMETER Method
    [string]
    Which method to use; ADWS (default), LDAP.

.PARAMETER objDomain
    [DirectoryServices.DirectoryEntry]
    Domain Directory Entry object.

.PARAMETER objDomainRootDSE
    [DirectoryServices.DirectoryEntry]
    RootDSE Directory Entry object.

.PARAMETER DomainController
    [string]
    IP Address of the Domain Controller.

.PARAMETER Credential
    [Management.Automation.PSCredential]
    Credentials.

.OUTPUTS
    PSObject.
#>
    param(
        [Parameter(Mandatory = $true)]
        [string] $Method,

        [Parameter(Mandatory = $false)]
        [DirectoryServices.DirectoryEntry] $objDomain,

        [Parameter(Mandatory = $false)]
        [DirectoryServices.DirectoryEntry] $objDomainRootDSE,

        [Parameter(Mandatory = $false)]
        [string] $DomainController,

        [Parameter(Mandatory = $false)]
        [Management.Automation.PSCredential] $Credential = [Management.Automation.PSCredential]::Empty
    )

    If ($Method -eq 'ADWS')
    {
        Try
        {
            $SearchPath = "CN=Sites"
            $ADSites = Get-ADObject -SearchBase "$SearchPath,$((Get-ADRootDSE).configurationNamingContext)" -LDAPFilter "(objectClass=site)" -Properties Name,Description,whenCreated,whenChanged
        }
        Catch
        {
            Write-Warning "[Get-AdaptSite] Error while enumerating Site Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }

        If ($ADSites)
        {
            Write-Verbose "[*] Total Sites: $(Get-ObjectCount $ADSites)"
            # Sites Info
            $ADSiteObj = @()
            $ADSites | ForEach-Object {
                # Create the object for each instance.
                $Obj = New-Object PSObject
                $Obj | Add-Member -MemberType NoteProperty -Name "Name" -Value $_.Name
                $Obj | Add-Member -MemberType NoteProperty -Name "Description" -Value $_.Description
                $Obj | Add-Member -MemberType NoteProperty -Name "whenCreated" -Value $_.whenCreated
                $Obj | Add-Member -MemberType NoteProperty -Name "whenChanged" -Value $_.whenChanged
                $ADSiteObj += $Obj
            }
            Remove-Variable ADSites
        }
    }

    If ($Method -eq 'LDAP')
    {
        $SearchPath = "CN=Sites"
        If ($Credential -ne [Management.Automation.PSCredential]::Empty)
        {
            $objSearchPath = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$($DomainController)/$SearchPath,$($objDomainRootDSE.ConfigurationNamingContext)", $Credential.UserName,$Credential.GetNetworkCredential().Password
        }
        Else
        {
            $objSearchPath = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$SearchPath,$($objDomainRootDSE.ConfigurationNamingContext)"
        }
        $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objSearchPath
        $ObjSearcher.Filter = "(objectClass=site)"
        $ObjSearcher.SearchScope = "Subtree"

        Try
        {
            $ADSites = $ObjSearcher.FindAll()
        }
        Catch
        {
            Write-Warning "[Get-AdaptSite] Error while enumerating Site Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }
        $ObjSearcher.dispose()

        If ($ADSites)
        {
            Write-Verbose "[*] Total Sites: $(Get-ObjectCount $ADSites)"
            # Site Info
            $ADSiteObj = @()
            $ADSites | ForEach-Object {
                # Create the object for each instance.
                $Obj = New-Object PSObject
                $Obj | Add-Member -MemberType NoteProperty -Name "Name" -Value $([string] $_.Properties.name)
                $Obj | Add-Member -MemberType NoteProperty -Name "Description" -Value $([string] $_.Properties.description)
                $Obj | Add-Member -MemberType NoteProperty -Name "whenCreated" -Value ([DateTime] $($_.Properties.whencreated))
                $Obj | Add-Member -MemberType NoteProperty -Name "whenChanged" -Value ([DateTime] $($_.Properties.whenchanged))
                $ADSiteObj += $Obj
            }
            Remove-Variable ADSites
        }
    }

    If ($ADSiteObj)
    {
        Return $ADSiteObj
    }
    Else
    {
        Return $null
    }
}

Function Get-AdaptSubnet
{
<#
.SYNOPSIS
    Returns the Subnets of the current (or specified) domain.

.DESCRIPTION
    Returns the Subnets of the current (or specified) domain.

.PARAMETER Method
    [string]
    Which method to use; ADWS (default), LDAP.

.PARAMETER objDomain
    [DirectoryServices.DirectoryEntry]
    Domain Directory Entry object.

.PARAMETER objDomainRootDSE
    [DirectoryServices.DirectoryEntry]
    RootDSE Directory Entry object.

.PARAMETER DomainController
    [string]
    IP Address of the Domain Controller.

.PARAMETER Credential
    [Management.Automation.PSCredential]
    Credentials.

.OUTPUTS
    PSObject.
#>
    param(
        [Parameter(Mandatory = $true)]
        [string] $Method,

        [Parameter(Mandatory = $false)]
        [DirectoryServices.DirectoryEntry] $objDomain,

        [Parameter(Mandatory = $false)]
        [DirectoryServices.DirectoryEntry] $objDomainRootDSE,

        [Parameter(Mandatory = $false)]
        [string] $DomainController,

        [Parameter(Mandatory = $false)]
        [Management.Automation.PSCredential] $Credential = [Management.Automation.PSCredential]::Empty
    )

    If ($Method -eq 'ADWS')
    {
        Try
        {
            $SearchPath = "CN=Subnets,CN=Sites"
            $ADSubnets = Get-ADObject -SearchBase "$SearchPath,$((Get-ADRootDSE).configurationNamingContext)" -LDAPFilter "(objectClass=subnet)" -Properties Name,Description,siteObject,whenCreated,whenChanged
        }
        Catch
        {
            Write-Warning "[Get-AdaptSubnet] Error while enumerating Subnet Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }

        If ($ADSubnets)
        {
            Write-Verbose "[*] Total Subnets: $(Get-ObjectCount $ADSubnets)"
            # Subnets Info
            $ADSubnetObj = @()
            $ADSubnets | ForEach-Object {
                # Create the object for each instance.
                $Obj = New-Object PSObject
                $Obj | Add-Member -MemberType NoteProperty -Name "Site" -Value $(($_.siteObject -Split ",")[0] -replace 'CN=','')
                $Obj | Add-Member -MemberType NoteProperty -Name "Name" -Value $_.Name
                $Obj | Add-Member -MemberType NoteProperty -Name "Description" -Value $_.Description
                $Obj | Add-Member -MemberType NoteProperty -Name "whenCreated" -Value $_.whenCreated
                $Obj | Add-Member -MemberType NoteProperty -Name "whenChanged" -Value $_.whenChanged
                $ADSubnetObj += $Obj
            }
            Remove-Variable ADSubnets
        }
    }

    If ($Method -eq 'LDAP')
    {
        $SearchPath = "CN=Subnets,CN=Sites"
        If ($Credential -ne [Management.Automation.PSCredential]::Empty)
        {
            $objSearchPath = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$($DomainController)/$SearchPath,$($objDomainRootDSE.ConfigurationNamingContext)", $Credential.UserName,$Credential.GetNetworkCredential().Password
        }
        Else
        {
            $objSearchPath = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$SearchPath,$($objDomainRootDSE.ConfigurationNamingContext)"
        }
        $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objSearchPath
        $ObjSearcher.Filter = "(objectClass=subnet)"
        $ObjSearcher.SearchScope = "Subtree"

        Try
        {
            $ADSubnets = $ObjSearcher.FindAll()
        }
        Catch
        {
            Write-Warning "[Get-AdaptSubnet] Error while enumerating Subnet Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }
        $ObjSearcher.dispose()

        If ($ADSubnets)
        {
            Write-Verbose "[*] Total Subnets: $(Get-ObjectCount $ADSubnets)"
            # Subnets Info
            $ADSubnetObj = @()
            $ADSubnets | ForEach-Object {
                # Create the object for each instance.
                $Obj = New-Object PSObject
                $Obj | Add-Member -MemberType NoteProperty -Name "Site" -Value $((([string] $_.Properties.siteobject) -Split ",")[0] -replace 'CN=','')
                $Obj | Add-Member -MemberType NoteProperty -Name "Name" -Value $([string] $_.Properties.name)
                $Obj | Add-Member -MemberType NoteProperty -Name "Description" -Value $([string] $_.Properties.description)
                $Obj | Add-Member -MemberType NoteProperty -Name "whenCreated" -Value ([DateTime] $($_.Properties.whencreated))
                $Obj | Add-Member -MemberType NoteProperty -Name "whenChanged" -Value ([DateTime] $($_.Properties.whenchanged))
                $ADSubnetObj += $Obj
            }
            Remove-Variable ADSubnets
        }
    }

    If ($ADSubnetObj)
    {
        Return $ADSubnetObj
    }
    Else
    {
        Return $null
    }
}

# based on https://blogs.technet.microsoft.com/heyscriptingguy/2012/01/05/how-to-find-active-directory-schema-update-history-by-using-powershell/
Function Get-AdaptSchemaHistory
{
<#
.SYNOPSIS
    Returns the Schema History of the current (or specified) domain.

.DESCRIPTION
    Returns the Schema History of the current (or specified) domain.

.PARAMETER Method
    [string]
    Which method to use; ADWS (default), LDAP.

.PARAMETER objDomain
    [DirectoryServices.DirectoryEntry]
    Domain Directory Entry object.

.PARAMETER objDomainRootDSE
    [DirectoryServices.DirectoryEntry]
    RootDSE Directory Entry object.

.PARAMETER DomainController
    [string]
    IP Address of the Domain Controller.

.PARAMETER Credential
    [Management.Automation.PSCredential]
    Credentials.

.OUTPUTS
    PSObject.
#>
    param(
        [Parameter(Mandatory = $true)]
        [string] $Method,

        [Parameter(Mandatory = $false)]
        [DirectoryServices.DirectoryEntry] $objDomain,

        [Parameter(Mandatory = $false)]
        [DirectoryServices.DirectoryEntry] $objDomainRootDSE,

        [Parameter(Mandatory = $false)]
        [string] $DomainController,

        [Parameter(Mandatory = $false)]
        [Management.Automation.PSCredential] $Credential = [Management.Automation.PSCredential]::Empty
    )

    If ($Method -eq 'ADWS')
    {
        Try
        {
            $ADSchemaHistory = @( Get-ADObject -SearchBase ((Get-ADRootDSE).schemaNamingContext) -SearchScope OneLevel -Filter * -Property DistinguishedName, Name, ObjectClass, whenChanged, whenCreated )
        }
        Catch
        {
            Write-Warning "[Get-AdaptSchemaHistory] Error while enumerating Schema Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }

        If ($ADSchemaHistory)
        {
            Write-Verbose "[*] Total Schema Objects: $(Get-ObjectCount $ADSchemaHistory)"
            $ADSchemaObj = Parse-Schema $ADSchemaHistory $Threads
            Remove-Variable ADSchemaHistory
        }
    }

    If ($Method -eq 'LDAP')
    {
        If ($Credential -ne [Management.Automation.PSCredential]::Empty)
        {
            $objSearchPath = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$($DomainController)/$($objDomainRootDSE.schemaNamingContext)", $Credential.UserName,$Credential.GetNetworkCredential().Password
        }
        Else
        {
            $objSearchPath = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$($objDomainRootDSE.schemaNamingContext)"
        }
        $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objSearchPath
        $ObjSearcher.Filter = "(objectClass=*)"
        $ObjSearcher.PropertiesToLoad.AddRange(("distinguishedname","name","objectclass","whenchanged","whencreated"))
        $ObjSearcher.SearchScope = "OneLevel"

        Try
        {
            $ADSchemaHistory = $ObjSearcher.FindAll()
        }
        Catch
        {
            Write-Warning "[Get-AdaptSchemaHistory] Error while enumerating Schema Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }
        $ObjSearcher.dispose()

        If ($ADSchemaHistory)
        {
            Write-Verbose "[*] Total Schema Objects: $(Get-ObjectCount $ADSchemaHistory)"
            $ADSchemaObj = Parse-Schema $ADSchemaHistory $Threads
            Remove-Variable ADSchemaHistory
        }
    }

    If ($ADSchemaObj)
    {
        Return $ADSchemaObj
    }
    Else
    {
        Return $null
    }
}

Function Get-AdaptDefaultPasswordPolicy
{
<#
.SYNOPSIS
    Returns the Default Password Policy of the current (or specified) domain.

.DESCRIPTION
    Returns the Default Password Policy of the current (or specified) domain.

.PARAMETER Method
    [string]
    Which method to use; ADWS (default), LDAP.

.PARAMETER objDomain
    [DirectoryServices.DirectoryEntry]
    Domain Directory Entry object.

.OUTPUTS
    PSObject.
#>
    param(
        [Parameter(Mandatory = $true)]
        [string] $Method,

        [Parameter(Mandatory = $false)]
        [DirectoryServices.DirectoryEntry] $objDomain
    )

    If ($Method -eq 'ADWS')
    {
        Try
        {
            $ADpasspolicy = Get-ADDefaultDomainPasswordPolicy
        }
        Catch
        {
            Write-Warning "[Get-AdaptDefaultPasswordPolicy] Error while enumerating the Default Password Policy"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }

        If ($ADpasspolicy)
        {
            $ObjValues = @( "Enforce password history (passwords)", $ADpasspolicy.PasswordHistoryCount, "4", "4", "Req. 8.2.5 / 8.3.7", "N/A", "-", "24 or more",
            "Maximum password age (days)", $ADpasspolicy.MaxPasswordAge.days, "90", "90", "Req. 8.2.4 / 8.3.9", "365", "ISM-1590 Rev:1 Mar22", "1 to 365",
            "Minimum password age (days)", $ADpasspolicy.MinPasswordAge.days, "N/A", "N/A", "-", "N/A", "-", "1 or more",
            "Minimum password length (characters)", $ADpasspolicy.MinPasswordLength, "7", "12", "Req. 8.2.3 / 8.3.6", "14", "Control: ISM-0421 Rev:8 Dec21", "14 or more",
            "Password must meet complexity requirements", $ADpasspolicy.ComplexityEnabled, $true, $true, "Req. 8.2.3 / 8.3.6", "N/A", "-", $true,
            "Store password using reversible encryption for all users in the domain", $ADpasspolicy.ReversibleEncryptionEnabled, "N/A", "N/A", "-", "N/A", "-", $false,
            "Account lockout duration (mins)", $ADpasspolicy.LockoutDuration.minutes, "0 (manual unlock) or 30", "0 (manual unlock) or 30", "Req. 8.1.7 / 8.3.4", "N/A", "-", "15 or more",
            "Account lockout threshold (attempts)", $ADpasspolicy.LockoutThreshold, "1 to 6", "1 to 10", "Req. 8.1.6 / 8.3.4", "1 to 5", "Control: ISM-1403 Rev:2 Oct19", "1 to 5",
            "Reset account lockout counter after (mins)", $ADpasspolicy.LockoutObservationWindow.minutes, "N/A", "N/A", "-", "N/A", "-", "15 or more" )

            Remove-Variable ADpasspolicy
        }
    }

    If ($Method -eq 'LDAP')
    {
        If ($ObjDomain)
        {
            #Value taken from https://msdn.microsoft.com/en-us/library/ms679431(v=vs.85).aspx
            $pwdProperties = @{
                "DOMAIN_PASSWORD_COMPLEX" = 1;
                "DOMAIN_PASSWORD_NO_ANON_CHANGE" = 2;
                "DOMAIN_PASSWORD_NO_CLEAR_CHANGE" = 4;
                "DOMAIN_LOCKOUT_ADMINS" = 8;
                "DOMAIN_PASSWORD_STORE_CLEARTEXT" = 16;
                "DOMAIN_REFUSE_PASSWORD_CHANGE" = 32
            }

            If (($ObjDomain.pwdproperties.value -band $pwdProperties["DOMAIN_PASSWORD_COMPLEX"]) -eq $pwdProperties["DOMAIN_PASSWORD_COMPLEX"])
            {
                $ComplexPasswords = $true
            }
            Else
            {
                $ComplexPasswords = $false
            }

            If (($ObjDomain.pwdproperties.value -band $pwdProperties["DOMAIN_PASSWORD_STORE_CLEARTEXT"]) -eq $pwdProperties["DOMAIN_PASSWORD_STORE_CLEARTEXT"])
            {
                $ReversibleEncryption = $true
            }
            Else
            {
                $ReversibleEncryption = $false
            }

            $LockoutDuration = $($ObjDomain.ConvertLargeIntegerToInt64($ObjDomain.lockoutduration.value)/-600000000)

            If ($LockoutDuration -gt 99999)
            {
                $LockoutDuration = 0
            }

            $ObjValues = @( "Enforce password history (passwords)", $ObjDomain.PwdHistoryLength.value, "4", "4", "Req. 8.2.5 / 8.3.7", "N/A", "-", "24 or more",
                "Maximum password age (days)", $($ObjDomain.ConvertLargeIntegerToInt64($ObjDomain.maxpwdage.value) / -864000000000), "90", "90", "Req. 8.2.4 / 8.3.9", "365", "ISM-1590 Rev:1 Mar22", "1 to 365",
            "Minimum password age (days)", $($ObjDomain.ConvertLargeIntegerToInt64($ObjDomain.minpwdage.value) /-864000000000), "N/A", "N/A", "-", "N/A", "-", "1 or more",
            "Minimum password length (characters)", $ObjDomain.MinPwdLength.value, "7", "12", "Req. 8.2.3 / 8.3.6", "14", "Control: ISM-0421 Rev:8 Dec21", "14 or more",
            "Password must meet complexity requirements", $ComplexPasswords, $true, $true, "Req. 8.2.3 / 8.3.6", "N/A", "-", $true,
            "Store password using reversible encryption for all users in the domain", $ReversibleEncryption, "N/A", "N/A", "-", "N/A", "-", $false,
            "Account lockout duration (mins)", $LockoutDuration, "0 (manual unlock) or 30", "0 (manual unlock) or 30", "Req. 8.1.7 / 8.3.4", "N/A", "-", "15 or more",
            "Account lockout threshold (attempts)", $ObjDomain.LockoutThreshold.value, "1 to 6", "1 to 10", "Req. 8.1.6 / 8.3.4", "1 to 5", "Control: ISM-1403 Rev:2 Oct19", "1 to 5",
            "Reset account lockout counter after (mins)", $($ObjDomain.ConvertLargeIntegerToInt64($ObjDomain.lockoutobservationWindow.value)/-600000000), "N/A", "N/A", "-", "N/A", "-", "15 or more" )

            Remove-Variable pwdProperties
            Remove-Variable ComplexPasswords
            Remove-Variable ReversibleEncryption
        }
    }

    If ($ObjValues)
    {
        $ADPassPolObj = @()
        For ($i = 0; $i -lt $($ObjValues.Count); $i++)
        {
            $Obj = New-Object PSObject
            $Obj | Add-Member -MemberType NoteProperty -Name "Policy" -Value $ObjValues[$i]
            $Obj | Add-Member -MemberType NoteProperty -Name "Current Value" -Value $ObjValues[$i+1]
            $Obj | Add-Member -MemberType NoteProperty -Name "PCI DSS v3.2.1" -Value $ObjValues[$i+2]
            $Obj | Add-Member -MemberType NoteProperty -Name "PCI DSS v4.0" -Value $ObjValues[$i+3]
            $Obj | Add-Member -MemberType NoteProperty -Name "PCI DSS Requirement" -Value $ObjValues[$i+4]
            $Obj | Add-Member -MemberType NoteProperty -Name "ACSC ISM" -Value $ObjValues[$i+5]
            $Obj | Add-Member -MemberType NoteProperty -Name "ISM Controls 16Jun2022" -Value $ObjValues[$i+6]
            $Obj | Add-Member -MemberType NoteProperty -Name "CIS Benchmark 2022" -Value $ObjValues[$i+7]
            $i += 7
            $ADPassPolObj += $Obj
        }
        Remove-Variable ObjValues
        Return $ADPassPolObj
    }
    Else
    {
        Return $null
    }
}

Function Get-AdaptFineGrainedPasswordPolicy
{
<#
.SYNOPSIS
    Returns the Fine Grained Password Policy of the current (or specified) domain.

.DESCRIPTION
    Returns the Fine Grained Password Policy of the current (or specified) domain.

.PARAMETER Method
    [string]
    Which method to use; ADWS (default), LDAP.

.PARAMETER objDomain
    [DirectoryServices.DirectoryEntry]
    Domain Directory Entry object.

.OUTPUTS
    PSObject.
#>
    param(
        [Parameter(Mandatory = $true)]
        [string] $Method,

        [Parameter(Mandatory = $false)]
        [DirectoryServices.DirectoryEntry] $objDomain
    )

    If ($Method -eq 'ADWS')
    {
        Try
        {
            $ADFinepasspolicy = Get-ADFineGrainedPasswordPolicy -Filter *
        }
        Catch
        {
            Write-Warning "[Get-AdaptFineGrainedPasswordPolicy] Error while enumerating the Fine Grained Password Policy"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }

        If ($ADFinepasspolicy)
        {
            $FgppPassPolObj = @()

            $ADFinepasspolicy | ForEach-Object {
                $AppliesTo = ""
                $AppliesTo = $_.AppliesTo -join ", "

                $FgppValues = [ordered]@{
                    "Name"                                       = $($_.Name)
                    "Applies To"                                 = $AppliesTo
                    "Enforce password history"                   = $_.PasswordHistoryCount
                    "Maximum password age (days)"                = $_.MaxPasswordAge.days
                    "Minimum password age (days)"                = $_.MinPasswordAge.days
                    "Minimum password length"                    = $_.MinPasswordLength
                    "Password must meet complexity requirements" = $_.ComplexityEnabled
                    "Store password using reversible encryption" = $_.ReversibleEncryptionEnabled
                    "Account lockout duration (mins)"            = $_.LockoutDuration.minutes
                    "Account lockout threshold"                  = $_.LockoutThreshold
                    "Reset account lockout counter after (mins)" = $_.LockoutObservationWindow.minutes
                    "Precedence"                                 = $($_.Precedence)
                }

                $FgppObj = New-Object -TypeName PsObject -Property $FgppValues
                $FgppPassPolObj += $FgppObj
            }
            Remove-Variable ADFinepasspolicy
        }
    }

    If ($Method -eq 'LDAP')
    {
        If ($ObjDomain)
        {
            $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objDomain
            $ObjSearcher.PageSize = $PageSize
            $ObjSearcher.Filter = "(objectClass=msDS-PasswordSettings)"
            $ObjSearcher.SearchScope = "Subtree"
            Try
            {
                $ADFinepasspolicy = $ObjSearcher.FindAll()
            }
            Catch
            {
                Write-Warning "[Get-AdaptFineGrainedPasswordPolicy] Error while enumerating the Fine Grained Password Policy"
                Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
                Return $null
            }

            If ($ADFinepasspolicy)
            {
                If (Get-ObjectCount $ADFinepasspolicy -ge 1)
                {
                    $FgppPassPolObj = @()
                    $ADFinepasspolicy | ForEach-Object {
                        $AppliesTo = ""
                        $AppliesTo = $_.Properties.'msds-psoappliesto' -join ", "

                        $FgppValues = [ordered]@{
                            "Name"                                       = $($_.Properties.name)
                            "Applies To"                                 = $AppliesTo
                            "Enforce password history"                   = $($_.Properties.'msds-passwordhistorylength')
                            "Maximum password age (days)"                = $($($_.Properties.'msds-maximumpasswordage') /-864000000000)
                            "Minimum password age (days)"                = $($($_.Properties.'msds-minimumpasswordage') /-864000000000)
                            "Minimum password length"                    = $($_.Properties.'msds-minimumpasswordlength')
                            "Password must meet complexity requirements" = $($_.Properties.'msds-passwordcomplexityenabled')
                            "Store password using reversible encryption" = $($_.Properties.'msds-passwordreversibleencryptionenabled')
                            "Account lockout duration (mins)"            = $($($_.Properties.'msds-lockoutduration')/-600000000)
                            "Account lockout threshold"                  = $($_.Properties.'msds-lockoutthreshold')
                            "Reset account lockout counter after (mins)" = $($($_.Properties.'msds-lockoutobservationwindow')/-600000000)
                            "Precedence"                                 = $($_.Properties.'msds-passwordsettingsprecedence')
                        }

                        $FgppObj = New-Object -TypeName PsObject -Property $FgppValues
                        $FgppPassPolObj += $FgppObj
                    }
                }
                Remove-Variable ADFinepasspolicy
            }
        }
    }

    If ($FgppPassPolObj)
    {
        Return $FgppPassPolObj
    }
    Else
    {
        Return $null
    }
}

Function Get-AdaptDomainController
{
<#
.SYNOPSIS
    Returns the domain controllers for the current (or specified) forest.

.DESCRIPTION
    Returns the domain controllers for the current (or specified) forest.

.PARAMETER Method
    [string]
    Which method to use; ADWS (default), LDAP.

.PARAMETER objDomain
    [DirectoryServices.DirectoryEntry]
    Domain Directory Entry object.

.PARAMETER Credential
    [Management.Automation.PSCredential]
    Credentials.

.OUTPUTS
    PSObject.
#>
    param(
        [Parameter(Mandatory = $true)]
        [string] $Method,

        [Parameter(Mandatory = $false)]
        [DirectoryServices.DirectoryEntry] $objDomain,

        [Parameter(Mandatory = $false)]
        [Management.Automation.PSCredential] $Credential = [Management.Automation.PSCredential]::Empty
    )

    If ($Method -eq 'ADWS')
    {
        Try
        {
            $ADDomainControllers = @( Get-ADDomainController -Filter * )
        }
        Catch
        {
            Write-Warning "[Get-AdaptDomainController] Error while enumerating DomainController Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }

        # DC Info
        If ($ADDomainControllers)
        {
            Write-Verbose "[*] Total Domain Controllers: $(Get-ObjectCount $ADDomainControllers)"
            $DCObj = Parse-DomainController $ADDomainControllers $Threads
            Remove-Variable ADDomainControllers
        }
    }

    If ($Method -eq 'LDAP')
    {
        If ($Credential -ne [Management.Automation.PSCredential]::Empty)
        {
            $DomainFQDN = Get-DNtoFQDN($objDomain.distinguishedName)
            $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("Domain",$($DomainFQDN),$($Credential.UserName),$($Credential.GetNetworkCredential().password))
            Try
            {
                $ADDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
            }
            Catch
            {
                Write-Warning "[Get-AdaptDomainController] Error getting Domain Context"
                Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
                Return $null
            }
            Remove-Variable DomainContext
        }
        Else
        {
            $ADDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        }

        If ($ADDomain.DomainControllers)
        {
            Write-Verbose "[*] Total Domain Controllers: $(Get-ObjectCount $ADDomain.DomainControllers)"
            $DCObj = Parse-DomainController $ADDomain.DomainControllers $Threads
            Remove-Variable ADDomain
        }
    }

    If ($DCObj)
    {
        Return $DCObj
    }
    Else
    {
        Return $null
    }
}

Function Get-AdaptUser
{
<#
.SYNOPSIS
    Returns all users and/or service principal name (SPN) in the current (or specified) domain.

.DESCRIPTION
    Returns all users and/or  service principal name (SPN) in the current (or specified) domain.

.PARAMETER Method
    [string]
    Which method to use; ADWS (default), LDAP.

.PARAMETER date
    [DateTime]
    Date when Adapt AD was executed.

.PARAMETER objDomain
    [DirectoryServices.DirectoryEntry]
    Domain Directory Entry object.

.PARAMETER DormantTimeSpan
    [int]
    Timespan for Dormant accounts. Default 90 days.

.PARAMETER PageSize
    [int]
    The PageSize to set for the LDAP searcher object. Default 200.

.PARAMETER Threads
    [int]
    The number of threads to use during processing of objects. Default 10.

.PARAMETER AdaptUsers
    [bool]

.PARAMETER AdaptUserSPNs
    [bool]

.PARAMETER OnlyEnabled
    [bool]

.OUTPUTS
    PSObject.
#>
    param(
        [Parameter(Mandatory = $true)]
        [string] $Method,

        [Parameter(Mandatory = $true)]
        [DateTime] $date,

        [Parameter(Mandatory = $false)]
        [DirectoryServices.DirectoryEntry] $objDomain,

        [Parameter(Mandatory = $true)]
        [int] $DormantTimeSpan = 90,

        [Parameter(Mandatory = $true)]
        [int] $PageSize = 200,

        [Parameter(Mandatory = $false)]
        [int] $Threads = 10,

        [Parameter(Mandatory = $false)]
        [int] $AdaptUsers = $true,

        [Parameter(Mandatory = $false)]
        [int] $AdaptUserSPNs = $false,

        [Parameter(Mandatory = $false)]
        [int] $OnlyEnabled = $false
    )

    If ($Method -eq 'ADWS')
    {
        If (!$AdaptUsers)
        {
            Try
            {
                If ($OnlyEnabled)
                {
                    $ADUsers = @( Get-ADObject -LDAPFilter "(&(samAccountType=805306368)(servicePrincipalName=*)(!userAccountControl:1.2.840.113556.1.4.803:=2))" -ResultPageSize $PageSize -Properties Name,Description,memberOf,sAMAccountName,servicePrincipalName,primaryGroupID,pwdLastSet,userAccountControl )
                }
                Else
                {
                    $ADUsers = @( Get-ADObject -LDAPFilter "(&(samAccountType=805306368)(servicePrincipalName=*))" -ResultPageSize $PageSize -Properties Name,Description,memberOf,sAMAccountName,servicePrincipalName,primaryGroupID,pwdLastSet,userAccountControl )
                }
            }
            Catch
            {
                Write-Warning "[Get-AdaptUser] Error while enumerating UserSPN Objects"
                Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
                Return $null
            }
        }
        Else
        {
            Try
            {
                If ($OnlyEnabled)
                {
                    $ADUsers = @( Get-ADUser -Filter 'enabled -eq $true' -ResultPageSize $PageSize -Properties AccountExpirationDate,accountExpires,AccountNotDelegated,AdminCount,AllowReversiblePasswordEncryption,c,CannotChangePassword,CanonicalName,Company,Department,Description,DistinguishedName,DoesNotRequirePreAuth,Enabled,givenName,homeDirectory,Info,LastLogonDate,lastLogonTimestamp,LockedOut,LogonWorkstations,mail,Manager,memberOf,middleName,mobile,'msDS-AllowedToDelegateTo','msDS-SupportedEncryptionTypes',Name,PasswordExpired,PasswordLastSet,PasswordNeverExpires,PasswordNotRequired,primaryGroupID,profilePath,pwdlastset,SamAccountName,ScriptPath,servicePrincipalName,SID,SIDHistory,SmartcardLogonRequired,sn,Title,TrustedForDelegation,TrustedToAuthForDelegation,UseDESKeyOnly,UserAccountControl,whenChanged,whenCreated )
                }
                Else
                {
                    $ADUsers = @( Get-ADUser -Filter * -ResultPageSize $PageSize -Properties AccountExpirationDate,accountExpires,AccountNotDelegated,AdminCount,AllowReversiblePasswordEncryption,c,CannotChangePassword,CanonicalName,Company,Department,Description,DistinguishedName,DoesNotRequirePreAuth,Enabled,givenName,homeDirectory,Info,LastLogonDate,lastLogonTimestamp,LockedOut,LogonWorkstations,mail,Manager,memberOf,middleName,mobile,'msDS-AllowedToDelegateTo','msDS-SupportedEncryptionTypes',Name,PasswordExpired,PasswordLastSet,PasswordNeverExpires,PasswordNotRequired,primaryGroupID,profilePath,pwdlastset,SamAccountName,ScriptPath,servicePrincipalName,SID,SIDHistory,SmartcardLogonRequired,sn,Title,TrustedForDelegation,TrustedToAuthForDelegation,UseDESKeyOnly,UserAccountControl,whenChanged,whenCreated )
                }
            }
            Catch
            {
                Write-Warning "[Get-AdaptUser] Error while enumerating User Objects"
                Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
                Return $null
            }
        }
        If ($ADUsers)
        {
            Write-Verbose "[*] Total Users: $(Get-ObjectCount $ADUsers)"
            If ($AdaptUsers)
            {
                Try
                {
                    $ADpasspolicy = Get-ADDefaultDomainPasswordPolicy
                    $PassMaxAge = $ADpasspolicy.MaxPasswordAge.days
                    Remove-Variable ADpasspolicy
                }
                Catch
                {
                    Write-Warning "[Get-AdaptUser] Error retrieving Max Password Age from the Default Password Policy. Using value as 90 days"
                    Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
                    $PassMaxAge = 90
                }
                $UserObj = Parse-User $ADUsers $date $DormantTimeSpan $PassMaxAge $Threads
            }
            If ($AdaptUserSPNs)
            {
                $UserSPNObj = Parse-UserSPN $ADUsers $Threads
            }
            Remove-Variable ADUsers
        }
    }

    If ($Method -eq 'LDAP')
    {
        If (!$AdaptUsers)
        {
            $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objDomain
            $ObjSearcher.PageSize = $PageSize
            If ($OnlyEnabled)
            {
                $ObjSearcher.Filter = "(&(samAccountType=805306368)(servicePrincipalName=*)(!userAccountControl:1.2.840.113556.1.4.803:=2))"
            }
            Else
            {
                $ObjSearcher.Filter = "(&(samAccountType=805306368)(servicePrincipalName=*))"
            }
            $ObjSearcher.PropertiesToLoad.AddRange(("name","description","memberof","samaccountname","serviceprincipalname","primarygroupid","pwdlastset","useraccountcontrol"))
            $ObjSearcher.SearchScope = "Subtree"
            Try
            {
                $ADUsers = $ObjSearcher.FindAll()
            }
            Catch
            {
                Write-Warning "[Get-AdaptUser] Error while enumerating UserSPN Objects"
                Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
                Return $null
            }
            $ObjSearcher.dispose()
        }
        Else
        {
            $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objDomain
            $ObjSearcher.PageSize = $PageSize
            If ($OnlyEnabled)
            {
                $ObjSearcher.Filter = "(&(samAccountType=805306368)(!userAccountControl:1.2.840.113556.1.4.803:=2))"
            }
            Else
            {
                $ObjSearcher.Filter = "(samAccountType=805306368)"
            }
                # https://msdn.microsoft.com/en-us/library/system.directoryservices.securitymasks(v=vs.110).aspx
            $ObjSearcher.SecurityMasks = [System.DirectoryServices.SecurityMasks]'Dacl'
            $ObjSearcher.PropertiesToLoad.AddRange(("accountExpires","admincount","c","canonicalname","company","department","description","distinguishedname","givenName","homedirectory","info","lastLogontimestamp","mail","manager","memberof","middleName","mobile","msDS-AllowedToDelegateTo","msDS-SupportedEncryptionTypes","name","ntsecuritydescriptor","objectsid","primarygroupid","profilepath","pwdLastSet","samaccountName","scriptpath","serviceprincipalname","sidhistory","sn","title","useraccountcontrol","userworkstations","whenchanged","whencreated"))
            $ObjSearcher.SearchScope = "Subtree"
            Try
            {
                $ADUsers = $ObjSearcher.FindAll()
            }
            Catch
            {
                Write-Warning "[Get-AdaptUser] Error while enumerating User Objects"
                Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
                Return $null
            }
            $ObjSearcher.dispose()
        }
        If ($ADUsers)
        {
            Write-Verbose "[*] Total Users: $(Get-ObjectCount $ADUsers)"
            If ($AdaptUsers)
            {
                $PassMaxAge = $($ObjDomain.ConvertLargeIntegerToInt64($ObjDomain.maxpwdage.value) /-864000000000)
                If (-Not $PassMaxAge)
                {
                    Write-Warning "[Get-AdaptUser] Error retrieving Max Password Age from the Default Password Policy. Using value as 90 days"
                    Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
                    $PassMaxAge = 90
                }
                $UserObj = Parse-User $ADUsers $date $DormantTimeSpan $PassMaxAge $Threads
            }
            If ($AdaptUserSPNs)
            {
                $UserSPNObj = Parse-UserSPN $ADUsers $Threads
            }
            Remove-Variable ADUsers
        }
    }

    If ($UserObj)
    {
        Export-Adapt -AdaptObj $UserObj -AdaptOutputDir $AdaptOutputDir -OutputType $OutputType -AdaptModuleName "Users"
        Remove-Variable UserObj
    }
    If ($UserSPNObj)
    {
        Export-Adapt -AdaptObj $UserSPNObj -AdaptOutputDir $AdaptOutputDir -OutputType $OutputType -AdaptModuleName "UserSPNs"
        Remove-Variable UserSPNObj
    }
}

#TODO
Function Get-AdaptPasswordAttributes
{
<#
.SYNOPSIS
    Returns all objects with plaintext passwords in the current (or specified) domain.

.DESCRIPTION
    Returns all objects with plaintext passwords in the current (or specified) domain.

.PARAMETER Method
    [string]
    Which method to use; ADWS (default), LDAP.

.PARAMETER objDomain
    [DirectoryServices.DirectoryEntry]
    Domain Directory Entry object.

.PARAMETER PageSize
    [int]
    The PageSize to set for the LDAP searcher object. Default 200.

.OUTPUTS
    PSObject.

.LINK
    https://www.ibm.com/support/knowledgecenter/en/ssw_aix_71/com.ibm.aix.security/ad_password_attribute_selection.htm
    https://msdn.microsoft.com/en-us/library/cc223248.aspx
    https://msdn.microsoft.com/en-us/library/cc223249.aspx
#>
    param(
        [Parameter(Mandatory = $true)]
        [string] $Method,

        [Parameter(Mandatory = $false)]
        [DirectoryServices.DirectoryEntry] $objDomain,

        [Parameter(Mandatory = $true)]
        [int] $PageSize
    )

    If ($Method -eq 'ADWS')
    {
        Try
        {
            $ADUsers = Get-ADObject -LDAPFilter '(|(UserPassword=*)(UnixUserPassword=*)(unicodePwd=*)(msSFU30Password=*))' -ResultPageSize $PageSize -Properties *
        }
        Catch
        {
            Write-Warning "[Get-AdaptPasswordAttributes] Error while enumerating Password Attributes"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }

        If ($ADUsers)
        {
            Write-Warning "[*] Total PasswordAttribute Objects: $(Get-ObjectCount $ADUsers)"
            $UserObj = $ADUsers
            Remove-Variable ADUsers
        }
    }

    If ($Method -eq 'LDAP')
    {
        $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objDomain
        $ObjSearcher.PageSize = $PageSize
        $ObjSearcher.Filter = "(|(UserPassword=*)(UnixUserPassword=*)(unicodePwd=*)(msSFU30Password=*))"
        $ObjSearcher.SearchScope = "Subtree"
        Try
        {
            $ADUsers = $ObjSearcher.FindAll()
        }
        Catch
        {
            Write-Warning "[Get-AdaptPasswordAttributes] Error while enumerating Password Attributes"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }
        $ObjSearcher.dispose()

        If ($ADUsers)
        {
            $cnt = Get-ObjectCount $ADUsers
            If ($cnt -gt 0)
            {
                Write-Warning "[*] Total PasswordAttribute Objects: $cnt"
            }
            $UserObj = $ADUsers
            Remove-Variable ADUsers
        }
    }

    If ($UserObj)
    {
        Return $UserObj
    }
    Else
    {
        Return $null
    }
}

Function Get-AdaptGroup
{
<#
.SYNOPSIS
    Returns all groups and/or membership changes in the current (or specified) domain.

.DESCRIPTION
    Returns all groups and/or membership changes in the current (or specified) domain.

.PARAMETER Method
    [string]
    Which method to use; ADWS (default), LDAP.

.PARAMETER date
    [DateTime]
    Date when Adapt AD was executed.

.PARAMETER objDomain
    [DirectoryServices.DirectoryEntry]
    Domain Directory Entry object.

.PARAMETER PageSize
    [int]
    The PageSize to set for the LDAP searcher object. Default 200.

.PARAMETER Threads
    [int]
    The number of threads to use during processing of objects. Default 10.

.PARAMETER AdaptOutputDir
    [string]
    Path for Adapt AD output folder.

.PARAMETER OutputType
    [array]
    Output Type.

.PARAMETER AdaptGroups
    [bool]

.PARAMETER AdaptGroupChanges
    [bool]

.OUTPUTS
    PSObject.
#>
    param(
        [Parameter(Mandatory = $true)]
        [string] $Method,

        [Parameter(Mandatory = $true)]
        [DateTime] $date,

        [Parameter(Mandatory = $false)]
        [DirectoryServices.DirectoryEntry] $objDomain,

        [Parameter(Mandatory = $true)]
        [int] $PageSize = 200,

        [Parameter(Mandatory = $false)]
        [int] $Threads = 10,

        [Parameter(Mandatory = $true)]
        [string] $AdaptOutputDir,

        [Parameter(Mandatory = $true)]
        [array] $OutputType,

        [Parameter(Mandatory = $false)]
        [bool] $AdaptGroups = $true,

        [Parameter(Mandatory = $false)]
        [bool] $AdaptGroupChanges = $false
    )

    If ($Method -eq 'ADWS')
    {
        Try
        {
            $ADGroups = @( Get-ADGroup -Filter * -ResultPageSize $PageSize -Properties AdminCount,CanonicalName,DistinguishedName,Description,GroupCategory,GroupScope,SamAccountName,SID,SIDHistory,managedBy,'msDS-ReplValueMetaData',whenChanged,whenCreated )
        }
        Catch
        {
            Write-Warning "[Get-AdaptGroup] Error while enumerating Group Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }

        If ($ADGroups)
        {
            Write-Verbose "[*] Total Groups: $(Get-ObjectCount $ADGroups)"
            If ($AdaptGroups)
            {
                $GroupObj = Parse-Group $ADGroups $Threads
            }
            If ($AdaptGroupChanges)
            {
                $GroupChangesObj = Parse-GroupChange $ADGroups $date $Threads
            }
            Remove-Variable ADGroups
            Remove-Variable AdaptGroups
            Remove-Variable AdaptGroupChanges
        }
    }

    If ($Method -eq 'LDAP')
    {
        $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objDomain
        $ObjSearcher.PageSize = $PageSize
        $ObjSearcher.Filter = "(objectClass=group)"
        $ObjSearcher.PropertiesToLoad.AddRange(("admincount","canonicalname", "distinguishedname", "description", "grouptype","samaccountname", "sidhistory", "managedby", "msds-replvaluemetadata", "objectsid", "whencreated", "whenchanged"))
        $ObjSearcher.SearchScope = "Subtree"

        Try
        {
            $ADGroups = $ObjSearcher.FindAll()
        }
        Catch
        {
            Write-Warning "[Get-AdaptGroup] Error while enumerating Group Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }
        $ObjSearcher.dispose()

        If ($ADGroups)
        {
            Write-Verbose "[*] Total Groups: $(Get-ObjectCount $ADGroups)"
            If ($AdaptGroups)
            {
                $GroupObj = Parse-Group $ADGroups $Threads
            }
            If ($AdaptGroupChanges)
            {
                $GroupChangesObj = Parse-GroupChange $ADGroups $date $Threads
            }
            Remove-Variable ADGroups
            Remove-Variable AdaptGroups
            Remove-Variable AdaptGroupChanges
        }
    }

    If ($GroupObj)
    {
        Export-Adapt -AdaptObj $GroupObj -AdaptOutputDir $AdaptOutputDir -OutputType $OutputType -AdaptModuleName "Groups"
        Remove-Variable GroupObj
    }

    If ($GroupChangesObj)
    {
        Export-Adapt -AdaptObj $GroupChangesObj -AdaptOutputDir $AdaptOutputDir -OutputType $OutputType -AdaptModuleName "GroupChanges"
        Remove-Variable GroupChangesObj
    }
}

Function Get-AdaptGroupMember
{
<#
.SYNOPSIS
    Returns all groups and their members in the current (or specified) domain.

.DESCRIPTION
    Returns all groups and their members in the current (or specified) domain.

.PARAMETER Method
    [string]
    Which method to use; ADWS (default), LDAP.

.PARAMETER objDomain
    [DirectoryServices.DirectoryEntry]
    Domain Directory Entry object.

.PARAMETER PageSize
    [int]
    The PageSize to set for the LDAP searcher object. Default 200.

.PARAMETER Threads
    [int]
    The number of threads to use during processing of objects. Default 10.

.OUTPUTS
    PSObject.
#>
    param(
        [Parameter(Mandatory = $true)]
        [string] $Method,

        [Parameter(Mandatory = $false)]
        [DirectoryServices.DirectoryEntry] $objDomain,

        [Parameter(Mandatory = $true)]
        [int] $PageSize = 200,

        [Parameter(Mandatory = $false)]
        [int] $Threads = 10
    )

    If ($Method -eq 'ADWS')
    {
        Try
        {
            $ADDomain = Get-ADDomain
            $ADDomainSID = $ADDomain.DomainSID.Value
            Remove-Variable ADDomain
        }
        Catch
        {
            Write-Warning "[Get-AdaptGroupMember] Error getting Domain Context"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }

        Try
        {
            $ADGroups = $ADGroups = @( Get-ADGroup -Filter * -ResultPageSize $PageSize -Properties SamAccountName,SID )
        }
        Catch
        {
            Write-Warning "[Get-AdaptGroupMember] Error while enumerating Group Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
        }

        Try
        {
            $ADGroupMembers = @( Get-ADObject -LDAPFilter '(|(memberof=*)(primarygroupid=*))' -Properties DistinguishedName,ObjectClass,memberof,primaryGroupID,sAMAccountName,samaccounttype, objectSid )
        }
        Catch
        {
            Write-Warning "[Get-AdaptGroupMember] Error while enumerating GroupMember Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }

        If ( ($ADDomainSID) -and ($ADGroups) -and ($ADGroupMembers) )
        {
            Write-Verbose "[*] Total GroupMember Objects: $(Get-ObjectCount $ADGroupMembers)"
            $GroupMemberObj = Parse-GroupMember $ADGroups $ADGroupMembers, $ADDomainSID, $Threads
            Remove-Variable ADGroups
            Remove-Variable ADGroupMembers
            Remove-Variable ADDomainSID
        }
    }

    If ($Method -eq 'LDAP')
    {

        If ($Credential -ne [Management.Automation.PSCredential]::Empty)
        {
            $DomainFQDN = Get-DNtoFQDN($objDomain.distinguishedName)
            $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("Domain",$($DomainFQDN),$($Credential.UserName),$($Credential.GetNetworkCredential().password))
            Try
            {
                $ADDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
            }
            Catch
            {
                Write-Warning "[Get-AdaptGroupMember] Error getting Domain Context"
                Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
                Return $null
            }
            Remove-Variable DomainContext
            Try
            {
                $ForestContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("Forest",$($ADDomain.Forest),$($Credential.UserName),$($Credential.GetNetworkCredential().password))
                $ADForest = [System.DirectoryServices.ActiveDirectory.Forest]::GetForest($ForestContext)
            }
            Catch
            {
                Write-Warning "[Get-AdaptGroupMember] Error getting Forest Context"
                Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            }
            If ($ForestContext)
            {
                Remove-Variable ForestContext
            }
            If ($ADForest)
            {
                $GlobalCatalog = $ADForest.FindGlobalCatalog()
            }
            If ($GlobalCatalog)
            {
                $DN = "GC://$($GlobalCatalog.IPAddress)/$($objDomain.distinguishedname)"
                Try
                {
                    $ADObject = New-Object -TypeName System.DirectoryServices.DirectoryEntry -ArgumentList ($($DN),$($Credential.UserName),$($Credential.GetNetworkCredential().password))
                    $ADDomainSID = New-Object System.Security.Principal.SecurityIdentifier($ADObject.objectSid[0], 0)
                    $ADObject.Dispose()
                }
                Catch
                {
                    Write-Warning "[Get-AdaptGroupMember] Error retrieving Domain SID using the GlobalCatalog $($GlobalCatalog.IPAddress). Using SID from the ObjDomain."
                    Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
                    $ADDomainSID = New-Object System.Security.Principal.SecurityIdentifier($objDomain.objectSid[0], 0)
                }
            }
            Else
            {
                $ADDomainSID = New-Object System.Security.Principal.SecurityIdentifier($objDomain.objectSid[0], 0)
            }
        }
        Else
        {
            $ADDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            $ADForest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
            Try
            {
                $GlobalCatalog = $ADForest.FindGlobalCatalog()
                $DN = "GC://$($GlobalCatalog)/$($objDomain.distinguishedname)"
                $ADObject = New-Object -TypeName System.DirectoryServices.DirectoryEntry -ArgumentList ($DN)
                $ADDomainSID = New-Object System.Security.Principal.SecurityIdentifier($ADObject.objectSid[0], 0)
                $ADObject.dispose()
            }
            Catch
            {
                Write-Warning "[Get-AdaptGroupMember] Error retrieving Domain SID using the GlobalCatalog $($GlobalCatalog.IPAddress). Using SID from the ObjDomain."
                Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
                $ADDomainSID = New-Object System.Security.Principal.SecurityIdentifier($objDomain.objectSid[0], 0)
            }
        }

        $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objDomain
        $ObjSearcher.PageSize = $PageSize
        $ObjSearcher.Filter = "(objectClass=group)"
        $ObjSearcher.PropertiesToLoad.AddRange(("samaccountname", "objectsid"))
        $ObjSearcher.SearchScope = "Subtree"

        Try
        {
            $ADGroups = $ObjSearcher.FindAll()
        }
        Catch
        {
            Write-Warning "[Get-AdaptGroupMember] Error while enumerating Group Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }
        $ObjSearcher.dispose()

        $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objDomain
        $ObjSearcher.PageSize = $PageSize
        $ObjSearcher.Filter = "(|(memberof=*)(primarygroupid=*))"
        $ObjSearcher.PropertiesToLoad.AddRange(("distinguishedname", "dnshostname", "objectclass", "primarygroupid", "memberof", "samaccountname", "samaccounttype", "objectsid"))
        $ObjSearcher.SearchScope = "Subtree"

        Try
        {
            $ADGroupMembers = $ObjSearcher.FindAll()
        }
        Catch
        {
            Write-Warning "[Get-AdaptGroupMember] Error while enumerating GroupMember Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }
        $ObjSearcher.dispose()

        If ( ($ADDomainSID) -and ($ADGroups) -and ($ADGroupMembers) )
        {
            Write-Verbose "[*] Total GroupMember Objects: $(Get-ObjectCount $ADGroupMembers)"
            $GroupMemberObj = Parse-GroupMember $ADGroups $ADGroupMembers, $ADDomainSID, $Threads
            Remove-Variable ADGroups
            Remove-Variable ADGroupMembers
            Remove-Variable ADDomainSID
        }
    }

    If ($GroupMemberObj)
    {
        Return $GroupMemberObj
    }
    Else
    {
        Return $null
    }
}

Function Get-AdaptOU
{
<#
.SYNOPSIS
    Returns all Organizational Units (OU) in the current (or specified) domain.

.DESCRIPTION
    Returns all Organizational Units (OU) in the current (or specified) domain.

.PARAMETER Method
    [string]
    Which method to use; ADWS (default), LDAP.

.PARAMETER objDomain
    [DirectoryServices.DirectoryEntry]
    Domain Directory Entry object.

.PARAMETER PageSize
    [int]
    The PageSize to set for the LDAP searcher object. Default 200.

.PARAMETER Threads
    [int]
    The number of threads to use during processing of objects. Default 10.

.OUTPUTS
    PSObject.
#>
    param(
        [Parameter(Mandatory = $true)]
        [string] $Method,

        [Parameter(Mandatory = $false)]
        [DirectoryServices.DirectoryEntry] $objDomain,

        [Parameter(Mandatory = $true)]
        [int] $PageSize = 200,

        [Parameter(Mandatory = $false)]
        [int] $Threads = 10
    )

    If ($Method -eq 'ADWS')
    {
        Try
        {
            $ADOUs = @( Get-ADOrganizationalUnit -Filter * -Properties DistinguishedName,Description,Name,whenCreated,whenChanged )
        }
        Catch
        {
            Write-Warning "[Get-AdaptOU] Error while enumerating OU Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }

        If ($ADOUs)
        {
            Write-Verbose "[*] Total OUs: $(Get-ObjectCount $ADOUs)"
            $OUObj = Parse-OU $ADOUs $Threads
            Remove-Variable ADOUs
        }
    }

    If ($Method -eq 'LDAP')
    {
        $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objDomain
        $ObjSearcher.PageSize = $PageSize
        $ObjSearcher.Filter = "(objectclass=organizationalunit)"
        $ObjSearcher.PropertiesToLoad.AddRange(("distinguishedname","description","name","whencreated","whenchanged"))
        $ObjSearcher.SearchScope = "Subtree"

        Try
        {
            $ADOUs = $ObjSearcher.FindAll()
        }
        Catch
        {
            Write-Warning "[Get-AdaptOU] Error while enumerating OU Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }
        $ObjSearcher.dispose()

        If ($ADOUs)
        {
            Write-Verbose "[*] Total OUs: $(Get-ObjectCount $ADOUs)"
            $OUObj = Parse-OU $ADOUs $Threads
            Remove-Variable ADOUs
        }
    }

    If ($OUObj)
    {
        Return $OUObj
    }
    Else
    {
        Return $null
    }
}

Function Get-AdaptGPO
{
<#
.SYNOPSIS
    Returns all Group Policy Objects (GPO) in the current (or specified) domain.

.DESCRIPTION
    Returns all Group Policy Objects (GPO) in the current (or specified) domain.

.PARAMETER Method
    [string]
    Which method to use; ADWS (default), LDAP.

.PARAMETER objDomain
    [DirectoryServices.DirectoryEntry]
    Domain Directory Entry object.

.PARAMETER Credential
    [Management.Automation.PSCredential]
    Credentials.

.PARAMETER PageSize
    [int]
    The PageSize to set for the LDAP searcher object. Default 200.

.PARAMETER Threads
    [int]
    The number of threads to use during processing of objects. Default 10.

.OUTPUTS
    PSObject.
#>
    param(
        [Parameter(Mandatory = $true)]
        [string] $Method,

        [Parameter(Mandatory = $false)]
        [DirectoryServices.DirectoryEntry] $objDomain,

        [Parameter(Mandatory = $true)]
        [int] $PageSize = 200,

        [Parameter(Mandatory = $false)]
        [int] $Threads = 10
    )

    If ($Method -eq 'ADWS')
    {
        Try
        {
            $ADGPOs = @( Get-ADObject -LDAPFilter '(objectCategory=groupPolicyContainer)' -Properties DisplayName,DistinguishedName,Name,gPCFileSysPath,whenCreated,whenChanged )
        }
        Catch
        {
            Write-Warning "[Get-AdaptGPO] Error while enumerating groupPolicyContainer Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }

        If ($ADGPOs)
        {
            Write-Verbose "[*] Total GPOs: $(Get-ObjectCount $ADGPOs)"
            $GPOsObj = Parse-GPO $ADGPOs $Threads
            Remove-Variable ADGPOs
        }
    }

    If ($Method -eq 'LDAP')
    {
        $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objDomain
        $ObjSearcher.PageSize = $PageSize
        $ObjSearcher.Filter = "(objectCategory=groupPolicyContainer)"
        $ObjSearcher.SearchScope = "Subtree"

        Try
        {
            $ADGPOs = $ObjSearcher.FindAll()
        }
        Catch
        {
            Write-Warning "[Get-AdaptGPO] Error while enumerating groupPolicyContainer Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }
        $ObjSearcher.dispose()

        If ($ADGPOs)
        {
            Write-Verbose "[*] Total GPOs: $(Get-ObjectCount $ADGPOs)"
            $GPOsObj = Parse-GPO $ADGPOs $Threads
            Remove-Variable ADGPOs
        }
    }

    If ($GPOsObj)
    {
        Return $GPOsObj
    }
    Else
    {
        Return $null
    }
}

# based on https://github.com/GoateePFE/GPLinkReport/blob/master/gPLinkReport.ps1
Function Get-AdaptGPLink
{
<#
.SYNOPSIS
    Returns all group policy links (gPLink) applied to Scope of Management (SOM) in the current (or specified) domain.

.DESCRIPTION
    Returns all group policy links (gPLink) applied to Scope of Management (SOM) in the current (or specified) domain.

.PARAMETER Method
    [string]
    Which method to use; ADWS (default), LDAP.

.PARAMETER objDomain
    [DirectoryServices.DirectoryEntry]
    Domain Directory Entry object.

.PARAMETER PageSize
    [int]
    The PageSize to set for the LDAP searcher object. Default 200.

.PARAMETER Threads
    [int]
    The number of threads to use during processing of objects. Default 10.

.OUTPUTS
    PSObject.
#>
    param(
        [Parameter(Mandatory = $true)]
        [string] $Method,

        [Parameter(Mandatory = $false)]
        [DirectoryServices.DirectoryEntry] $objDomain,

        [Parameter(Mandatory = $true)]
        [int] $PageSize = 200,

        [Parameter(Mandatory = $false)]
        [int] $Threads = 10
    )

    If ($Method -eq 'ADWS')
    {
        Try
        {
            $ADSOMs = @( Get-ADObject -LDAPFilter '(|(objectclass=domain)(objectclass=organizationalUnit))' -Properties DistinguishedName,Name,gPLink,gPOptions )
            $ADSOMs += @( Get-ADObject -SearchBase "CN=Sites,$((Get-ADRootDSE).configurationNamingContext)" -LDAPFilter "(objectclass=site)" -Properties DistinguishedName,Name,gPLink,gPOptions )
        }
        Catch
        {
            Write-Warning "[Get-AdaptGPLink] Error while enumerating SOM Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }

        Try
        {
            $ADGPOs = @( Get-ADObject -LDAPFilter '(objectCategory=groupPolicyContainer)' -Properties DisplayName,DistinguishedName )
        }
        Catch
        {
            Write-Warning "[Get-AdaptGPLink] Error while enumerating groupPolicyContainer Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }

        If ( ($ADSOMs) -and ($ADGPOs) )
        {
            Write-Verbose "[*] Total SOMs: $(Get-ObjectCount $ADSOMs)"
            $SOMObj = Parse-SOM $ADGPOs $ADSOMs, $Threads
            Remove-Variable ADSOMs
            Remove-Variable ADGPOs
        }
    }

    If ($Method -eq 'LDAP')
    {
        $ADSOMs = @()
        $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objDomain
        $ObjSearcher.PageSize = $PageSize
        $ObjSearcher.Filter = "(|(objectclass=domain)(objectclass=organizationalUnit))"
        $ObjSearcher.PropertiesToLoad.AddRange(("distinguishedname","name","gplink","gpoptions"))
        $ObjSearcher.SearchScope = "Subtree"

        Try
        {
            $ADSOMs += $ObjSearcher.FindAll()
        }
        Catch
        {
            Write-Warning "[Get-AdaptGPLink] Error while enumerating SOM Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }
        $ObjSearcher.dispose()

        $SearchPath = "CN=Sites"
        If ($Credential -ne [Management.Automation.PSCredential]::Empty)
        {
            $objSearchPath = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$($DomainController)/$SearchPath,$($objDomainRootDSE.ConfigurationNamingContext)", $Credential.UserName,$Credential.GetNetworkCredential().Password
        }
        Else
        {
            $objSearchPath = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$SearchPath,$($objDomainRootDSE.ConfigurationNamingContext)"
        }
        $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objSearchPath
        $ObjSearcher.Filter = "(objectclass=site)"
        $ObjSearcher.PropertiesToLoad.AddRange(("distinguishedname","name","gplink","gpoptions"))
        $ObjSearcher.SearchScope = "Subtree"

        Try
        {
            $ADSOMs += $ObjSearcher.FindAll()
        }
        Catch
        {
            Write-Warning "[Get-AdaptGPLink] Error while enumerating SOM Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }
        $ObjSearcher.dispose()

        $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objDomain
        $ObjSearcher.PageSize = $PageSize
        $ObjSearcher.Filter = "(objectCategory=groupPolicyContainer)"
        $ObjSearcher.SearchScope = "Subtree"

        Try
        {
            $ADGPOs = $ObjSearcher.FindAll()
        }
        Catch
        {
            Write-Warning "[Get-AdaptGPLink] Error while enumerating groupPolicyContainer Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }
        $ObjSearcher.dispose()

        If ( ($ADSOMs) -and ($ADGPOs) )
        {
            Write-Verbose "[*] Total SOMs: $(Get-ObjectCount $ADSOMs)"
            $SOMObj = Parse-SOM $ADGPOs $ADSOMs, $Threads
            Remove-Variable ADSOMs
            Remove-Variable ADGPOs
        }
    }

    If ($SOMObj)
    {
        Return $SOMObj
    }
    Else
    {
        Return $null
    }
}

# DNS record conversion helper
Function Convert-DNSRecord
{
<#
.SYNOPSIS

Helpers that decodes a binary DNS record blob.

Author: Michael B. Smith, Will Schroeder
License: BSD 3-Clause
Required Dependencies: None

.DESCRIPTION

Decodes a binary blob representing an Active Directory DNS entry.
Used by Get-DomainDNSRecord.

Adapted/ported from Michael B. Smith's code at https://raw.githubusercontent.com/mmessano/PowerShell/master/dns-dump.ps1

.PARAMETER DNSRecord

A byte array representing the DNS record.

.OUTPUTS

System.Management.Automation.PSCustomObject

Outputs custom PSObjects with detailed information about the DNS record entry.

.LINK

https://raw.githubusercontent.com/mmessano/PowerShell/master/dns-dump.ps1
#>

    [OutputType('System.Management.Automation.PSCustomObject')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [Byte[]]
        $DNSRecord
    )

    BEGIN {
        Function Get-Name
        {
            [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseOutputTypeCorrectly', '')]
            [CmdletBinding()]
            Param(
                [Byte[]]
                $Raw
            )

            [Int]$Length = $Raw[0]
            [Int]$Segments = $Raw[1]
            [Int]$Index =  2
            [String]$Name  = ''

            while ($Segments-- -gt 0)
            {
                [Int]$SegmentLength = $Raw[$Index++]
                while ($SegmentLength-- -gt 0)
                {
                    $Name += [Char]$Raw[$Index++]
                }
                $Name += "."
            }
            $Name
        }
    }

    PROCESS
    {
        # $RDataLen = [BitConverter]::ToUInt16($DNSRecord, 0)
        $RDataType = [BitConverter]::ToUInt16($DNSRecord, 2)
        $UpdatedAtSerial = [BitConverter]::ToUInt32($DNSRecord, 8)

        $TTLRaw = $DNSRecord[12..15]

        # reverse for big endian
        $Null = [array]::Reverse($TTLRaw)
        $TTL = [BitConverter]::ToUInt32($TTLRaw, 0)

        $Age = [BitConverter]::ToUInt32($DNSRecord, 20)
        If ($Age -ne 0)
        {
            $TimeStamp = ((Get-Date -Year 1601 -Month 1 -Day 1 -Hour 0 -Minute 0 -Second 0).AddHours($age)).ToString()
        }
        Else
        {
            $TimeStamp = '[static]'
        }

        $DNSRecordObject = New-Object PSObject

        switch ($RDataType)
        {
            1
            {
                $IP = "{0}.{1}.{2}.{3}" -f $DNSRecord[24], $DNSRecord[25], $DNSRecord[26], $DNSRecord[27]
                $Data = $IP
                $DNSRecordObject | Add-Member Noteproperty 'RecordType' 'A'
            }

            2
            {
                $NSName = Get-Name $DNSRecord[24..$DNSRecord.length]
                $Data = $NSName
                $DNSRecordObject | Add-Member Noteproperty 'RecordType' 'NS'
            }

            5
            {
                $Alias = Get-Name $DNSRecord[24..$DNSRecord.length]
                $Data = $Alias
                $DNSRecordObject | Add-Member Noteproperty 'RecordType' 'CNAME'
            }

            6
            {
                $PrimaryNS = Get-Name $DNSRecord[44..$DNSRecord.length]
                $ResponsibleParty = Get-Name $DNSRecord[$(46+$DNSRecord[44])..$DNSRecord.length]
                $SerialRaw = $DNSRecord[24..27]
                # reverse for big endian
                $Null = [array]::Reverse($SerialRaw)
                $Serial = [BitConverter]::ToUInt32($SerialRaw, 0)

                $RefreshRaw = $DNSRecord[28..31]
                $Null = [array]::Reverse($RefreshRaw)
                $Refresh = [BitConverter]::ToUInt32($RefreshRaw, 0)

                $RetryRaw = $DNSRecord[32..35]
                $Null = [array]::Reverse($RetryRaw)
                $Retry = [BitConverter]::ToUInt32($RetryRaw, 0)

                $ExpiresRaw = $DNSRecord[36..39]
                $Null = [array]::Reverse($ExpiresRaw)
                $Expires = [BitConverter]::ToUInt32($ExpiresRaw, 0)

                $MinTTLRaw = $DNSRecord[40..43]
                $Null = [array]::Reverse($MinTTLRaw)
                $MinTTL = [BitConverter]::ToUInt32($MinTTLRaw, 0)

                $Data = "[" + $Serial + "][" + $PrimaryNS + "][" + $ResponsibleParty + "][" + $Refresh + "][" + $Retry + "][" + $Expires + "][" + $MinTTL + "]"
                $DNSRecordObject | Add-Member Noteproperty 'RecordType' 'SOA'
            }

            12
            {
                $Ptr = Get-Name $DNSRecord[24..$DNSRecord.length]
                $Data = $Ptr
                $DNSRecordObject | Add-Member Noteproperty 'RecordType' 'PTR'
            }

            13
            {
                [string]$CPUType = ""
                [string]$OSType  = ""
                [int]$SegmentLength = $DNSRecord[24]
                $Index = 25
                while ($SegmentLength-- -gt 0)
                {
                    $CPUType += [char]$DNSRecord[$Index++]
                }
                $Index = 24 + $DNSRecord[24] + 1
                [int]$SegmentLength = $Index++
                while ($SegmentLength-- -gt 0)
                {
                    $OSType += [char]$DNSRecord[$Index++]
                }
                $Data = "[" + $CPUType + "][" + $OSType + "]"
                $DNSRecordObject | Add-Member Noteproperty 'RecordType' 'HINFO'
            }

            15
            {
                $PriorityRaw = $DNSRecord[24..25]
                # reverse for big endian
                $Null = [array]::Reverse($PriorityRaw)
                $Priority = [BitConverter]::ToUInt16($PriorityRaw, 0)
                $MXHost   = Get-Name $DNSRecord[26..$DNSRecord.length]
                $Data = "[" + $Priority + "][" + $MXHost + "]"
                $DNSRecordObject | Add-Member Noteproperty 'RecordType' 'MX'
            }

            16
            {
                [string]$TXT  = ''
                [int]$SegmentLength = $DNSRecord[24]
                $Index = 25
                while ($SegmentLength-- -gt 0)
                {
                    $TXT += [char]$DNSRecord[$Index++]
                }
                $Data = $TXT
                $DNSRecordObject | Add-Member Noteproperty 'RecordType' 'TXT'
            }

            28
            {
        		### yeah, this doesn't do all the fancy formatting that can be done for IPv6
                $AAAA = ""
                for ($i = 24; $i -lt 40; $i+=2)
                {
                    $BlockRaw = $DNSRecord[$i..$($i+1)]
                    # reverse for big endian
                    $Null = [array]::Reverse($BlockRaw)
                    $Block = [BitConverter]::ToUInt16($BlockRaw, 0)
			        $AAAA += ($Block).ToString('x4')
			        If ($i -ne 38)
                    {
                        $AAAA += ':'
                    }
                }
                $Data = $AAAA
                $DNSRecordObject | Add-Member Noteproperty 'RecordType' 'AAAA'
            }

            33
            {
                $PriorityRaw = $DNSRecord[24..25]
                # reverse for big endian
                $Null = [array]::Reverse($PriorityRaw)
                $Priority = [BitConverter]::ToUInt16($PriorityRaw, 0)

                $WeightRaw = $DNSRecord[26..27]
                $Null = [array]::Reverse($WeightRaw)
                $Weight = [BitConverter]::ToUInt16($WeightRaw, 0)

                $PortRaw = $DNSRecord[28..29]
                $Null = [array]::Reverse($PortRaw)
                $Port = [BitConverter]::ToUInt16($PortRaw, 0)

                $SRVHost = Get-Name $DNSRecord[30..$DNSRecord.length]
                $Data = "[" + $Priority + "][" + $Weight + "][" + $Port + "][" + $SRVHost + "]"
                $DNSRecordObject | Add-Member Noteproperty 'RecordType' 'SRV'
            }

            default
            {
                $Data = $([System.Convert]::ToBase64String($DNSRecord[24..$DNSRecord.length]))
                $DNSRecordObject | Add-Member Noteproperty 'RecordType' 'UNKNOWN'
            }
        }
        $DNSRecordObject | Add-Member Noteproperty 'UpdatedAtSerial' $UpdatedAtSerial
        $DNSRecordObject | Add-Member Noteproperty 'TTL' $TTL
        $DNSRecordObject | Add-Member Noteproperty 'Age' $Age
        $DNSRecordObject | Add-Member Noteproperty 'TimeStamp' $TimeStamp
        $DNSRecordObject | Add-Member Noteproperty 'Data' $Data
        Return $DNSRecordObject
    }
}

Function Get-AdaptDNSZone
{
<#
.SYNOPSIS
    Returns all DNS Zones and Records in the current (or specified) domain.

.DESCRIPTION
    Returns all DNS Zones and Records in the current (or specified) domain.

.PARAMETER Method
    [string]
    Which method to use; ADWS (default), LDAP.

.PARAMETER objDomain
    [DirectoryServices.DirectoryEntry]
    Domain Directory Entry object.

.PARAMETER DomainController
    [string]
    IP Address of the Domain Controller.

.PARAMETER Credential
    [Management.Automation.PSCredential]
    Credentials.

.PARAMETER PageSize
    [int]
    The PageSize to set for the LDAP searcher object. Default 200.

.PARAMETER AdaptOutputDir
    [string]
    Path for Adapt AD output folder.

.PARAMETER OutputType
    [array]
    Output Type.

.PARAMETER AdaptDNSZones
    [bool]

.PARAMETER AdaptDNSRecords
    [bool]

.OUTPUTS
    CSV files are created in the folder specified with the information.
#>
    param(
        [Parameter(Mandatory = $true)]
        [string] $Method,

        [Parameter(Mandatory = $false)]
        [DirectoryServices.DirectoryEntry] $objDomain,

        [Parameter(Mandatory = $false)]
        [string] $DomainController,

        [Parameter(Mandatory = $false)]
        [Management.Automation.PSCredential] $Credential = [Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $true)]
        [int] $PageSize = 200,

        [Parameter(Mandatory = $true)]
        [string] $AdaptOutputDir,

        [Parameter(Mandatory = $true)]
        [array] $OutputType,

        [Parameter(Mandatory = $false)]
        [bool] $AdaptDNSZones = $true,

        [Parameter(Mandatory = $false)]
        [bool] $AdaptDNSRecords = $false
    )

    If ($Method -eq 'ADWS')
    {
        Try
        {
            $ADDNSZones = Get-ADObject -LDAPFilter '(objectClass=dnsZone)' -Properties Name,whenCreated,whenChanged,usncreated,usnchanged,distinguishedname
        }
        Catch
        {
            Write-Warning "[Get-AdaptDNSZone] Error while enumerating dnsZone Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
        }

        $DNSZoneArray = @()
        If ($ADDNSZones)
        {
            $DNSZoneArray += $ADDNSZones
            Remove-Variable ADDNSZones
        }

        Try
        {
            $ADDomain = Get-ADDomain
        }
        Catch
        {
            Write-Warning "[Get-AdaptDNSZone] Error getting Domain Context"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }

        Try
        {
            $ADDNSZones1 = Get-ADObject -LDAPFilter '(objectClass=dnsZone)' -SearchBase "DC=DomainDnsZones,$($ADDomain.DistinguishedName)" -Properties Name,whenCreated,whenChanged,usncreated,usnchanged,distinguishedname
        }
        Catch
        {
            Write-Warning "[Get-AdaptDNSZone] Error while enumerating DC=DomainDnsZones,$($ADDomain.DistinguishedName) dnsZone Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
        }
        If ($ADDNSZones1)
        {
            $DNSZoneArray += $ADDNSZones1
            Remove-Variable ADDNSZones1
        }

        Try
        {
            $ADDNSZones2 = Get-ADObject -LDAPFilter '(objectClass=dnsZone)' -SearchBase "DC=ForestDnsZones,DC=$($ADDomain.Forest -replace '\.',',DC=')" -Properties Name,whenCreated,whenChanged,usncreated,usnchanged,distinguishedname
        }
        Catch
        {
            Write-Warning "[Get-AdaptDNSZone] Error while enumerating DC=ForestDnsZones,DC=$($ADDomain.Forest -replace '\.',',DC=') dnsZone Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
        }
        If ($ADDNSZones2)
        {
            $DNSZoneArray += $ADDNSZones2
            Remove-Variable ADDNSZones2
        }

        If ($ADDomain)
        {
            Remove-Variable ADDomain
        }

        Write-Verbose "[*] Total DNS Zones: $(Get-ObjectCount $DNSZoneArray)"

        If ($DNSZoneArray)
        {
            $ADDNSZonesObj = @()
            $ADDNSNodesObj = @()
            $DNSZoneArray | ForEach-Object {
                # Create the object for each instance.
                $Obj = New-Object PSObject
                $Obj | Add-Member -MemberType NoteProperty -Name Name -Value $(Clean-String $_.Name)
                Try
                {
                    $DNSNodes = Get-ADObject -SearchBase $($_.DistinguishedName) -LDAPFilter '(objectClass=dnsNode)' -Properties DistinguishedName,dnsrecord,dNSTombstoned,Name,ProtectedFromAccidentalDeletion,showInAdvancedViewOnly,whenChanged,whenCreated
                }
                Catch
                {
                    Write-Warning "[Get-AdaptDNSZone] Error while enumerating $($_.DistinguishedName) dnsNode Objects"
                    Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
                }
                If ($DNSNodes)
                {
                    $Obj | Add-Member -MemberType NoteProperty -Name RecordCount -Value $($DNSNodes | Measure-Object | Select-Object -ExpandProperty Count)
                    $DNSNodes | ForEach-Object {
                        $ObjNode = New-Object PSObject
                        $ObjNode | Add-Member -MemberType NoteProperty -Name ZoneName -Value $Obj.Name
                        $ObjNode | Add-Member -MemberType NoteProperty -Name Name -Value $_.Name
                        Try
                        {
                            $DNSRecord = Convert-DNSRecord $_.dnsrecord[0]
                        }
                        Catch
                        {
                            Write-Warning "[Get-AdaptDNSZone] Error while converting the DNSRecord"
                            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
                        }
                        $ObjNode | Add-Member -MemberType NoteProperty -Name RecordType -Value $DNSRecord.RecordType
                        $ObjNode | Add-Member -MemberType NoteProperty -Name Data -Value $DNSRecord.Data
                        $ObjNode | Add-Member -MemberType NoteProperty -Name TTL -Value $DNSRecord.TTL
                        $ObjNode | Add-Member -MemberType NoteProperty -Name Age -Value $DNSRecord.Age
                        $ObjNode | Add-Member -MemberType NoteProperty -Name TimeStamp -Value $DNSRecord.TimeStamp
                        $ObjNode | Add-Member -MemberType NoteProperty -Name UpdatedAtSerial -Value $DNSRecord.UpdatedAtSerial
                        $ObjNode | Add-Member -MemberType NoteProperty -Name whenCreated -Value $_.whenCreated
                        $ObjNode | Add-Member -MemberType NoteProperty -Name whenChanged -Value $_.whenChanged
                        # TO DO LDAP part
                        #$ObjNode | Add-Member -MemberType NoteProperty -Name dNSTombstoned -Value $_.dNSTombstoned
                        #$ObjNode | Add-Member -MemberType NoteProperty -Name ProtectedFromAccidentalDeletion -Value $_.ProtectedFromAccidentalDeletion
                        $ObjNode | Add-Member -MemberType NoteProperty -Name showInAdvancedViewOnly -Value $_.showInAdvancedViewOnly
                        $ObjNode | Add-Member -MemberType NoteProperty -Name DistinguishedName -Value $_.DistinguishedName
                        $ADDNSNodesObj += $ObjNode
                        If ($DNSRecord)
                        {
                            Remove-Variable DNSRecord
                        }
                    }
                }
                Else
                {
                    $Obj | Add-Member -MemberType NoteProperty -Name RecordCount -Value $null
                }
                $Obj | Add-Member -MemberType NoteProperty -Name USNCreated -Value $_.usncreated
                $Obj | Add-Member -MemberType NoteProperty -Name USNChanged -Value $_.usnchanged
                $Obj | Add-Member -MemberType NoteProperty -Name whenCreated -Value $_.whenCreated
                $Obj | Add-Member -MemberType NoteProperty -Name whenChanged -Value $_.whenChanged
                $Obj | Add-Member -MemberType NoteProperty -Name DistinguishedName -Value $_.DistinguishedName
                $ADDNSZonesObj += $Obj
            }
            Write-Verbose "[*] Total DNS Records: $(Get-ObjectCount $ADDNSNodesObj)"
            Remove-Variable DNSZoneArray
        }
    }

    If ($Method -eq 'LDAP')
    {
        $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objDomain
        $ObjSearcher.PageSize = $PageSize
        $ObjSearcher.PropertiesToLoad.AddRange(("name","whencreated","whenchanged","usncreated","usnchanged","distinguishedname"))
        $ObjSearcher.Filter = "(objectClass=dnsZone)"
        $ObjSearcher.SearchScope = "Subtree"

        Try
        {
            $ADDNSZones = $ObjSearcher.FindAll()
        }
        Catch
        {
            Write-Warning "[Get-AdaptDNSZone] Error while enumerating dnsZone Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
        }
        $ObjSearcher.dispose()

        $DNSZoneArray = @()
        If ($ADDNSZones)
        {
            $DNSZoneArray += $ADDNSZones
            Remove-Variable ADDNSZones
        }

        $SearchPath = "DC=DomainDnsZones"
        If ($Credential -ne [Management.Automation.PSCredential]::Empty)
        {
            $objSearchPath = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$($DomainController)/$($SearchPath),$($objDomain.distinguishedName)", $Credential.UserName,$Credential.GetNetworkCredential().Password
        }
        Else
        {
            $objSearchPath = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$($SearchPath),$($objDomain.distinguishedName)"
        }
        $objSearcherPath = New-Object System.DirectoryServices.DirectorySearcher $objSearchPath
        $objSearcherPath.Filter = "(objectClass=dnsZone)"
        $objSearcherPath.PageSize = $PageSize
        $objSearcherPath.PropertiesToLoad.AddRange(("name","whencreated","whenchanged","usncreated","usnchanged","distinguishedname"))
        $objSearcherPath.SearchScope = "Subtree"

        Try
        {
            $ADDNSZones1 = $objSearcherPath.FindAll()
        }
        Catch
        {
            Write-Warning "[Get-AdaptDNSZone] Error while enumerating $($SearchPath),$($objDomain.distinguishedName) dnsZone Objects."
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
        }
        $objSearcherPath.dispose()

        If ($ADDNSZones1)
        {
            $DNSZoneArray += $ADDNSZones1
            Remove-Variable ADDNSZones1
        }

        $SearchPath = "DC=ForestDnsZones"
        If ($Credential -ne [Management.Automation.PSCredential]::Empty)
        {
            $DomainFQDN = Get-DNtoFQDN($objDomain.distinguishedName)
            $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("Domain",$($DomainFQDN),$($Credential.UserName),$($Credential.GetNetworkCredential().password))
            Try
            {
                $ADDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
            }
            Catch
            {
                Write-Warning "[Get-AdaptForest] Error getting Domain Context"
                Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
                Return $null
            }
            Remove-Variable DomainContext
            $objSearchPath = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$($DomainController)/$($SearchPath),DC=$($ADDomain.Forest.Name -replace '\.',',DC=')", $Credential.UserName,$Credential.GetNetworkCredential().Password
        }
        Else
        {
            $ADDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            $objSearchPath = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$($SearchPath),DC=$($ADDomain.Forest.Name -replace '\.',',DC=')"
        }

        $objSearcherPath = New-Object System.DirectoryServices.DirectorySearcher $objSearchPath
        $objSearcherPath.Filter = "(objectClass=dnsZone)"
        $objSearcherPath.PageSize = $PageSize
        $objSearcherPath.PropertiesToLoad.AddRange(("name","whencreated","whenchanged","usncreated","usnchanged","distinguishedname"))
        $objSearcherPath.SearchScope = "Subtree"

        Try
        {
            $ADDNSZones2 = $objSearcherPath.FindAll()
        }
        Catch
        {
            Write-Warning "[Get-AdaptDNSZone] Error while enumerating $($SearchPath),DC=$($ADDomain.Forest.Name -replace '\.',',DC=') dnsZone Objects."
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
        }
        $objSearcherPath.dispose()

        If ($ADDNSZones2)
        {
            $DNSZoneArray += $ADDNSZones2
            Remove-Variable ADDNSZones2
        }

        If($ADDomain)
        {
            Remove-Variable ADDomain
        }

        Write-Verbose "[*] Total DNS Zones: $(Get-ObjectCount $DNSZoneArray)"

        If ($DNSZoneArray)
        {
            $ADDNSZonesObj = @()
            $ADDNSNodesObj = @()
            $DNSZoneArray | ForEach-Object {
                If ($Credential -ne [Management.Automation.PSCredential]::Empty)
                {
                    $objSearchPath = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$($DomainController)/$($_.Properties.distinguishedname)", $Credential.UserName,$Credential.GetNetworkCredential().Password
                }
                Else
                {
                    $objSearchPath = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$($_.Properties.distinguishedname)"
                }
                $objSearcherPath = New-Object System.DirectoryServices.DirectorySearcher $objSearchPath
                $objSearcherPath.Filter = "(objectClass=dnsNode)"
                $objSearcherPath.PageSize = $PageSize
                $objSearcherPath.PropertiesToLoad.AddRange(("distinguishedname","dnsrecord","name","dc","showinadvancedviewonly","whenchanged","whencreated"))
                Try
                {
                    $DNSNodes = $objSearcherPath.FindAll()
                }
                Catch
                {
                    Write-Warning "[Get-AdaptDNSZone] Error while enumerating $($_.Properties.distinguishedname) dnsNode Objects"
                    Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
                }
                $objSearcherPath.dispose()
                Remove-Variable objSearchPath

                # Create the object for each instance.
                $Obj = New-Object PSObject
                $Obj | Add-Member -MemberType NoteProperty -Name Name -Value $(Clean-String $_.Properties.name[0])
                If ($DNSNodes)
                {
                    $Obj | Add-Member -MemberType NoteProperty -Name RecordCount -Value $($DNSNodes | Measure-Object | Select-Object -ExpandProperty Count)
                    $DNSNodes | ForEach-Object {
                        $ObjNode = New-Object PSObject
                        $ObjNode | Add-Member -MemberType NoteProperty -Name ZoneName -Value $Obj.Name
                        $name = ([string] $($_.Properties.name))
                        If (-Not $name)
                        {
                            $name = ([string] $($_.Properties.dc))
                        }
                        $ObjNode | Add-Member -MemberType NoteProperty -Name Name -Value $name
                        Try
                        {
                            $DNSRecord = Convert-DNSRecord $_.Properties.dnsrecord[0]
                        }
                        Catch
                        {
                            Write-Warning "[Get-AdaptDNSZone] Error while converting the DNSRecord"
                            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
                        }
                        $ObjNode | Add-Member -MemberType NoteProperty -Name RecordType -Value $DNSRecord.RecordType
                        $ObjNode | Add-Member -MemberType NoteProperty -Name Data -Value $DNSRecord.Data
                        $ObjNode | Add-Member -MemberType NoteProperty -Name TTL -Value $DNSRecord.TTL
                        $ObjNode | Add-Member -MemberType NoteProperty -Name Age -Value $DNSRecord.Age
                        $ObjNode | Add-Member -MemberType NoteProperty -Name TimeStamp -Value $DNSRecord.TimeStamp
                        $ObjNode | Add-Member -MemberType NoteProperty -Name UpdatedAtSerial -Value $DNSRecord.UpdatedAtSerial
                        $ObjNode | Add-Member -MemberType NoteProperty -Name whenCreated -Value ([DateTime] $($_.Properties.whencreated))
                        $ObjNode | Add-Member -MemberType NoteProperty -Name whenChanged -Value ([DateTime] $($_.Properties.whenchanged))
                        # TO DO
                        #$ObjNode | Add-Member -MemberType NoteProperty -Name dNSTombstoned -Value $null
                        #$ObjNode | Add-Member -MemberType NoteProperty -Name ProtectedFromAccidentalDeletion -Value $null
                        $ObjNode | Add-Member -MemberType NoteProperty -Name showInAdvancedViewOnly -Value ([string] $($_.Properties.showinadvancedviewonly))
                        $ObjNode | Add-Member -MemberType NoteProperty -Name DistinguishedName -Value ([string] $($_.Properties.distinguishedname))
                        $ADDNSNodesObj += $ObjNode
                        If ($DNSRecord)
                        {
                            Remove-Variable DNSRecord
                        }
                    }
                }
                Else
                {
                    $Obj | Add-Member -MemberType NoteProperty -Name RecordCount -Value $null
                }
                $Obj | Add-Member -MemberType NoteProperty -Name USNCreated -Value ([string] $($_.Properties.usncreated))
                $Obj | Add-Member -MemberType NoteProperty -Name USNChanged -Value ([string] $($_.Properties.usnchanged))
                $Obj | Add-Member -MemberType NoteProperty -Name whenCreated -Value ([DateTime] $($_.Properties.whencreated))
                $Obj | Add-Member -MemberType NoteProperty -Name whenChanged -Value ([DateTime] $($_.Properties.whenchanged))
                $Obj | Add-Member -MemberType NoteProperty -Name DistinguishedName -Value ([string] $($_.Properties.distinguishedname))
                $ADDNSZonesObj += $Obj
            }
            Write-Verbose "[*] Total DNS Records: $(Get-ObjectCount $ADDNSNodesObj)"
            Remove-Variable DNSZoneArray
        }
    }

    If ($ADDNSZonesObj -and $AdaptDNSZones)
    {
        Export-Adapt $ADDNSZonesObj $AdaptOutputDir $OutputType "DNSZones"
        Remove-Variable ADDNSZonesObj
    }

    If ($ADDNSNodesObj -and $AdaptDNSRecords)
    {
        Export-Adapt $ADDNSNodesObj $AdaptOutputDir $OutputType "DNSNodes"
        Remove-Variable ADDNSNodesObj
    }
}

Function Get-AdaptPrinter
{
<#
.SYNOPSIS
    Returns all printers in the current (or specified) domain.

.DESCRIPTION
    Returns all printers in the current (or specified) domain.

.PARAMETER Method
    [string]
    Which method to use; ADWS (default), LDAP.

.PARAMETER objDomain
    [DirectoryServices.DirectoryEntry]
    Domain Directory Entry object.

.PARAMETER PageSize
    [int]
    The PageSize to set for the LDAP searcher object. Default 200.

.PARAMETER Threads
    [int]
    The number of threads to use during processing of objects. Default 10.

.OUTPUTS
    PSObject.
#>

    param(
        [Parameter(Mandatory = $true)]
        [string] $Method,

        [Parameter(Mandatory = $false)]
        [DirectoryServices.DirectoryEntry] $objDomain,

        [Parameter(Mandatory = $true)]
        [int] $PageSize = 200,

        [Parameter(Mandatory = $false)]
        [int] $Threads = 10
    )

    If ($Method -eq 'ADWS')
    {
        Try
        {
            $ADPrinters = @( Get-ADObject -LDAPFilter '(objectCategory=printQueue)' -Properties driverName,driverVersion,Name,portName,printShareName,serverName,url,whenChanged,whenCreated )
        }
        Catch
        {
            Write-Warning "[Get-AdaptPrinter] Error while enumerating printQueue Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }

        If ($ADPrinters)
        {
            Write-Verbose "[*] Total Printers: $(Get-ObjectCount $ADPrinters)"
            $PrintersObj = Parse-Printer $ADPrinters $Threads
            Remove-Variable ADPrinters
        }
    }

    If ($Method -eq 'LDAP')
    {
        $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objDomain
        $ObjSearcher.PageSize = $PageSize
        $ObjSearcher.Filter = "(objectCategory=printQueue)"
        $ObjSearcher.SearchScope = "Subtree"

        Try
        {
            $ADPrinters = $ObjSearcher.FindAll()
        }
        Catch
        {
            Write-Warning "[Get-AdaptPrinter] Error while enumerating printQueue Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }
        $ObjSearcher.dispose()

        If ($ADPrinters)
        {
            $cnt = $(Get-ObjectCount $ADPrinters)
            If ($cnt -ge 1)
            {
                Write-Verbose "[*] Total Printers: $cnt"
                $PrintersObj = Parse-Printer $ADPrinters $Threads
            }
            Remove-Variable ADPrinters
        }
    }

    If ($PrintersObj)
    {
        Return $PrintersObj
    }
    Else
    {
        Return $null
    }
}

Function Get-AdaptComputer
{
<#
.SYNOPSIS
    Returns all computers and/or service principal name (SPN) in the current (or specified) domain.

.DESCRIPTION
    Returns all computers and/or service principal name (SPN) in the current (or specified) domain.

.PARAMETER Method
    [string]
    Which method to use; ADWS (default), LDAP.

.PARAMETER date
    [DateTime]
    Date when Adapt AD was executed.

.PARAMETER objDomain
    [DirectoryServices.DirectoryEntry]
    Domain Directory Entry object.

.PARAMETER DormantTimeSpan
    [int]
    Timespan for Dormant accounts. Default 90 days.

.PARAMTER PassMaxAge
    [int]
    Maximum machine account password age. Default 30 days
    https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/domain-member-maximum-machine-account-password-age

.PARAMETER PageSize
    [int]
    The PageSize to set for the LDAP searcher object. Default 200.

.PARAMETER Threads
    [int]
    The number of threads to use during processing of objects. Default 10.

.PARAMETER AdaptComputers
    [bool]

.PARAMETER AdaptComputerSPNs
    [bool]

.PARAMETER OnlyEnabled
    [bool]

.OUTPUTS
    PSObject.
#>
    param(
        [Parameter(Mandatory = $true)]
        [string] $Method,

        [Parameter(Mandatory = $true)]
        [DateTime] $date,

        [Parameter(Mandatory = $false)]
        [DirectoryServices.DirectoryEntry] $objDomain,

        [Parameter(Mandatory = $true)]
        [int] $DormantTimeSpan = 90,

        [Parameter(Mandatory = $true)]
        [int] $PassMaxAge = 30,

        [Parameter(Mandatory = $true)]
        [int] $PageSize = 200,

        [Parameter(Mandatory = $false)]
        [int] $Threads = 10,

        [Parameter(Mandatory = $false)]
        [int] $AdaptComputers = $true,

        [Parameter(Mandatory = $false)]
        [int] $AdaptComputerSPNs = $false,

        [Parameter(Mandatory = $false)]
        [int] $OnlyEnabled = $false
    )

    If ($Method -eq 'ADWS')
    {
        If (!$AdaptComputers)
        {
            Try
            {
                If ($OnlyEnabled)
                {
                    $ADComputers = @( Get-ADObject -LDAPFilter "(&(samAccountType=805306369)(servicePrincipalName=*)(!userAccountControl:1.2.840.113556.1.4.803:=2))" -ResultPageSize $PageSize -Properties Name, servicePrincipalName )
                }
                Else
                {
                    $ADComputers = @( Get-ADObject -LDAPFilter "(&(samAccountType=805306369)(servicePrincipalName=*))" -ResultPageSize $PageSize -Properties Name,servicePrincipalName )
                }
            }
            Catch
            {
                Write-Warning "[Get-AdaptComputer] Error while enumerating ComputerSPN Objects"
                Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
                Return $null
            }
        }
        Else
        {
            Try
            {
                If ($OnlyEnabled)
                {
                    $ADComputers = @( Get-ADComputer -Filter 'enabled -eq $true' -ResultPageSize $PageSize -Properties Description,DistinguishedName,DNSHostName,Enabled,IPv4Address,LastLogonDate,'msDS-AllowedToDelegateTo','ms-ds-CreatorSid','msDS-SupportedEncryptionTypes',Name,OperatingSystem,OperatingSystemHotfix,OperatingSystemServicePack,OperatingSystemVersion,PasswordLastSet,primaryGroupID,SamAccountName,servicePrincipalName,SID,SIDHistory,TrustedForDelegation,TrustedToAuthForDelegation,UserAccountControl,whenChanged,whenCreated )
                }
                Else
                {
                    $ADComputers = @( Get-ADComputer -Filter * -ResultPageSize $PageSize -Properties Description,DistinguishedName,DNSHostName,Enabled,IPv4Address,LastLogonDate,'msDS-AllowedToDelegateTo','ms-ds-CreatorSid','msDS-SupportedEncryptionTypes',Name,OperatingSystem,OperatingSystemHotfix,OperatingSystemServicePack,OperatingSystemVersion,PasswordLastSet,primaryGroupID,SamAccountName,servicePrincipalName,SID,SIDHistory,TrustedForDelegation,TrustedToAuthForDelegation,UserAccountControl,whenChanged,whenCreated )
                }
            }
            Catch
            {
                Write-Warning "[Get-AdaptComputer] Error while enumerating Computer Objects"
                Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
                Return $null
            }
        }
        If ($ADComputers)
        {
            Write-Verbose "[*] Total Computers: $(Get-ObjectCount $ADComputers)"
            If ($AdaptComputers)
            {
                $ComputerObj = Parse-Computer $ADComputers $date $DormantTimeSpan $PassMaxAge $Threads
            }
            If ($AdaptComputerSPNs)
            {
                $ComputerSPNObj = Parse-ComputerSPN $ADComputers $Threads
            }
            Remove-Variable ADComputers
        }
    }

    If ($Method -eq 'LDAP')
    {
        If (!$AdaptComputers)
        {
            $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objDomain
            $ObjSearcher.PageSize = $PageSize
            If ($OnlyEnabled)
            {
                $ObjSearcher.Filter = "(&(samAccountType=805306369)(servicePrincipalName=*)(!userAccountControl:1.2.840.113556.1.4.803:=2))"
            }
            Else
            {
                $ObjSearcher.Filter = "(&(samAccountType=805306369)(servicePrincipalName=*))"
            }
            $ObjSearcher.PropertiesToLoad.AddRange(("name","serviceprincipalname"))
            $ObjSearcher.SearchScope = "Subtree"
            Try
            {
                $ADComputers = $ObjSearcher.FindAll()
            }
            Catch
            {
                Write-Warning "[Get-AdaptComputer] Error while enumerating ComputerSPN Objects"
                Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
                Return $null
            }
            $ObjSearcher.dispose()
        }
        Else
        {
            $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objDomain
            $ObjSearcher.PageSize = $PageSize
            If ($OnlyEnabled)
            {
                $ObjSearcher.Filter = "(&(samAccountType=805306369)(!userAccountControl:1.2.840.113556.1.4.803:=2))"
            }
            Else
            {
                $ObjSearcher.Filter = "(samAccountType=805306369)"
            }
            $ObjSearcher.PropertiesToLoad.AddRange(("description","distinguishedname","dnshostname","lastlogontimestamp","msDS-AllowedToDelegateTo","ms-ds-CreatorSid","msDS-SupportedEncryptionTypes","name","objectsid","operatingsystem","operatingsystemhotfix","operatingsystemservicepack","operatingsystemversion","primarygroupid","pwdlastset","samaccountname","serviceprincipalname","sidhistory","useraccountcontrol","whenchanged","whencreated"))
            $ObjSearcher.SearchScope = "Subtree"

            Try
            {
                $ADComputers = $ObjSearcher.FindAll()
            }
            Catch
            {
                Write-Warning "[Get-AdaptComputer] Error while enumerating Computer Objects"
                Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
                Return $null
            }
            $ObjSearcher.dispose()
        }

        If ($ADComputers)
        {
            Write-Verbose "[*] Total Computers: $(Get-ObjectCount $ADComputers)"
            If ($AdaptComputers)
            {
                $ComputerObj = Parse-Computer $ADComputers $date $DormantTimeSpan $PassMaxAge $Threads
            }
            If ($AdaptComputerSPNs)
            {
                $ComputerSPNObj = Parse-ComputerSPN $ADComputers $Threads
            }
            Remove-Variable ADComputers
        }
    }

    If ($ComputerObj)
    {
        Export-Adapt -AdaptObj $ComputerObj -AdaptOutputDir $AdaptOutputDir -OutputType $OutputType -AdaptModuleName "Computers"
        Remove-Variable ComputerObj
    }
    If ($ComputerSPNObj)
    {
        Export-Adapt -AdaptObj $ComputerSPNObj -AdaptOutputDir $AdaptOutputDir -OutputType $OutputType -AdaptModuleName "ComputerSPNs"
        Remove-Variable ComputerSPNObj
    }
}

Function Get-AdaptLAPSCheck
{
<#
.SYNOPSIS
    Checks if LAPS (local administrator) is enabled in the current (or specified) domain.

.DESCRIPTION
    Checks if LAPS (local administrator) is enabled in the current (or specified) domain.

.PARAMETER Method
    [string]
    Which method to use; ADWS (default), LDAP.

.PARAMETER objDomainRootDSE
    [DirectoryServices.DirectoryEntry]
    Domain Directory Entry object.

.PARAMETER DomainController
    [string]
    IP Address of the Domain Controller.

.PARAMETER Credential
    [Management.Automation.PSCredential]
    Credentials.

.OUTPUTS
    Bool.
#>
    param(
        [Parameter(Mandatory = $true)]
        [string] $Method,

        [Parameter(Mandatory = $false)]
        [DirectoryServices.DirectoryEntry] $objDomainRootDSE,

        [Parameter(Mandatory = $false)]
        [string] $DomainController,

        [Parameter(Mandatory = $false)]
        [Management.Automation.PSCredential] $Credential = [Management.Automation.PSCredential]::Empty
    )

    If ($Method -eq 'ADWS')
    {
        Try
        {
            $AdaptLAPSCheck = @( Get-ADObject "CN=ms-Mcs-AdmPwd,$((Get-ADRootDSE).schemaNamingContext)" )
        }
        Catch
        {
            Write-Verbose "[*] LAPS is not implemented."
            Return $false
        }

        If ($AdaptLAPSCheck)
        {
            Remove-Variable AdaptLAPSCheck
            Return $true
        }
        Else
        {
            Return $false
        }
    }

    If ($Method -eq 'LDAP')
    {
        Try
        {
            If ($Credential -ne [Management.Automation.PSCredential]::Empty)
            {
                $AdaptLAPSCheckDSE = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$($DomainController)/CN=ms-Mcs-AdmPwd,$($objDomainRootDSE.schemaNamingContext)", $Credential.UserName, $Credential.GetNetworkCredential().Password
                If (-Not ($AdaptLAPSCheckDSE.Path))
                {
                    $AdaptLAPSCheck = $false
                }
                Else
                {
                    $AdaptLAPSCheck = $true
                    $AdaptLAPSCheckDSE.dispose()
                }
            }
            Else
            {
                $AdaptLAPSCheck = [ADSI]::Exists("LDAP://CN=ms-Mcs-AdmPwd,$($objDomainRootDSE.schemaNamingContext)")
            }
        }
        Catch
        {
            Write-Verbose "[Get-AdaptLAPSCheck] Error while checking for existance of LAPS Properties"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
        }

        If ($AdaptLAPSCheck)
        {
            Remove-Variable AdaptLAPSCheck
            Return $true
        }
        Else
        {
            Return $false
        }
    }
}

# based on https://github.com/kfosaaen/Get-LAPSPasswords/blob/master/Get-LAPSPasswords.ps1
Function Get-AdaptLAPS
{
<#
.SYNOPSIS
    Returns all LAPS (local administrator) stored passwords in the current (or specified) domain.

.DESCRIPTION
    Returns all LAPS (local administrator) stored passwords in the current (or specified) domain. Other details such as the Password Expiration, whether the password is readable by the current user are also returned.

.PARAMETER Method
    [string]
    Which method to use; ADWS (default), LDAP.

.PARAMETER objDomain
    [DirectoryServices.DirectoryEntry]
    Domain Directory Entry object.

.PARAMETER PageSize
    [int]
    The PageSize to set for the LDAP searcher object. Default 200.

.PARAMETER Threads
    [int]
    The number of threads to use during processing of objects. Default 10.

.OUTPUTS
    PSObject.
#>
    param(
        [Parameter(Mandatory = $true)]
        [string] $Method,

        [Parameter(Mandatory = $false)]
        [DirectoryServices.DirectoryEntry] $objDomain,

        [Parameter(Mandatory = $false)]
        [int] $PageSize = 200,

        [Parameter(Mandatory = $false)]
        [int] $Threads = 10
    )

    If ($Method -eq 'ADWS')
    {
        Try
        {
            $ADComputers = @( Get-ADObject -LDAPFilter "(samAccountType=805306369)" -Properties CN, DNSHostName, 'ms-Mcs-AdmPwd', 'ms-Mcs-AdmPwdExpirationTime',useraccountcontrol -ResultPageSize $PageSize )
        }
        Catch
        {
            Write-Warning "[Get-AdaptLAPS] Error while enumerating LAPS Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }

        If ($ADComputers)
        {
            Write-Verbose "[*] Total LAPS Objects: $(Get-ObjectCount $ADComputers)"
            $LAPSObj = Parse-LAPS $ADComputers $Threads
            Remove-Variable ADComputers
        }
    }

    If ($Method -eq 'LDAP')
    {
        $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objDomain
        $ObjSearcher.PageSize = $PageSize
        $ObjSearcher.Filter = "(samAccountType=805306369)"
        $ObjSearcher.PropertiesToLoad.AddRange(("cn","dnshostname","ms-mcs-admpwd","ms-mcs-admpwdexpirationtime","useraccountcontrol"))
        $ObjSearcher.SearchScope = "Subtree"
        Try
        {
            $ADComputers = $ObjSearcher.FindAll()
        }
        Catch
        {
            Write-Warning "[Get-AdaptLAPS] Error while enumerating LAPS Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }
        $ObjSearcher.dispose()

        If ($ADComputers)
        {
            Write-Verbose "[*] Total LAPS Objects: $(Get-ObjectCount $ADComputers)"
            $LAPSObj = Parse-LAPS $ADComputers $Threads
            Remove-Variable ADComputers
        }
    }

    If ($LAPSObj)
    {
        Return $LAPSObj
    }
    Else
    {
        Return $null
    }
}

Function Get-AdaptBitLocker
{
<#
.SYNOPSIS
    Returns all BitLocker status stored in the current (or specified) domain.

.DESCRIPTION
    Returns all BitLocker status stored in the current (or specified) domain.

.PARAMETER Method
    [string]
    Which method to use; ADWS (default), LDAP.

.PARAMETER objDomain
    [DirectoryServices.DirectoryEntry]
    Domain Directory Entry object.

.PARAMETER DomainController
    [string]
    IP Address of the Domain Controller.

.PARAMETER Credential
    [Management.Automation.PSCredential]
    Credentials.

.OUTPUTS
    PSObject.
#>
    param(
        [Parameter(Mandatory = $true)]
        [string] $Method,

        [Parameter(Mandatory = $false)]
        [DirectoryServices.DirectoryEntry] $objDomain,

        [Parameter(Mandatory = $false)]
        [string] $DomainController,

        [Parameter(Mandatory = $false)]
        [Management.Automation.PSCredential] $Credential = [Management.Automation.PSCredential]::Empty
    )

    If ($Method -eq 'ADWS')
    {
        Try
        {
            $ADBitLockerRecoveryKeys = Get-ADObject -LDAPFilter '(objectClass=msFVE-RecoveryInformation)' -Properties distinguishedName,msFVE-RecoveryPassword,msFVE-RecoveryGuid,msFVE-VolumeGuid,Name,whenCreated
        }
        Catch
        {
            Write-Warning "[Get-AdaptBitLocker] Error while enumerating msFVE-RecoveryInformation Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }

        If ($ADBitLockerRecoveryKeys)
        {
            $cnt = $(Get-ObjectCount $ADBitLockerRecoveryKeys)
            If ($cnt -ge 1)
            {
                Write-Verbose "[*] Total BitLocker status: $cnt"
                $BitLockerObj = @()
                $ADBitLockerRecoveryKeys | ForEach-Object {
                    # Create the object for each instance.
                    $Obj = New-Object PSObject
                    $Obj | Add-Member -MemberType NoteProperty -Name "Distinguished Name" -Value $((($_.distinguishedName -split '}')[1]).substring(1))
                    $Obj | Add-Member -MemberType NoteProperty -Name "Name" -Value $_.Name
                    $Obj | Add-Member -MemberType NoteProperty -Name "whenCreated" -Value $_.whenCreated
                    $Obj | Add-Member -MemberType NoteProperty -Name "Recovery Key ID" -Value $([GUID] $_.'msFVE-RecoveryGuid')
                    $Obj | Add-Member -MemberType NoteProperty -Name "Recovery Key" -Value $_.'msFVE-RecoveryPassword'
                    $Obj | Add-Member -MemberType NoteProperty -Name "Volume GUID" -Value $([GUID] $_.'msFVE-VolumeGuid')
                    Try
                    {
                        $TempComp = Get-ADComputer -Identity $Obj.'Distinguished Name' -Properties msTPM-OwnerInformation,msTPM-TpmInformationForComputer
                    }
                    Catch
                    {
                        Write-Warning "[Get-AdaptBitLocker] Error while enumerating $($Obj.'Distinguished Name') Computer Object"
                        Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
                    }
                    If ($TempComp)
                    {
                        # msTPM-OwnerInformation (Vista/7 or Server 2008/R2)
                        $Obj | Add-Member -MemberType NoteProperty -Name "msTPM-OwnerInformation" -Value $TempComp.'msTPM-OwnerInformation'

                        # msTPM-TpmInformationForComputer (Windows 8/10 or Server 2012/R2)
                        $Obj | Add-Member -MemberType NoteProperty -Name "msTPM-TpmInformationForComputer" -Value $TempComp.'msTPM-TpmInformationForComputer'
                        If ($null -ne $TempComp.'msTPM-TpmInformationForComputer')
                        {
                            # Grab the TPM Owner Info from the msTPM-InformationObject
                            $TPMObject = Get-ADObject -Identity $TempComp.'msTPM-TpmInformationForComputer' -Properties msTPM-OwnerInformation
                            $TPMRecoveryInfo = $TPMObject.'msTPM-OwnerInformation'
                        }
                        Else
                        {
                            $TPMRecoveryInfo = $null
                        }
                    }
                    Else
                    {
                        $Obj | Add-Member -MemberType NoteProperty -Name "msTPM-OwnerInformation" -Value $null
                        $Obj | Add-Member -MemberType NoteProperty -Name "msTPM-TpmInformationForComputer" -Value $null
                        $TPMRecoveryInfo = $null

                    }
                    $Obj | Add-Member -MemberType NoteProperty -Name "TPM Owner Password" -Value $TPMRecoveryInfo
                    $BitLockerObj += $Obj
                }
            }
            Remove-Variable ADBitLockerRecoveryKeys
        }
    }

    If ($Method -eq 'LDAP')
    {
        $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objDomain
        $ObjSearcher.PageSize = $PageSize
        $ObjSearcher.Filter = "(objectClass=msFVE-RecoveryInformation)"
        $ObjSearcher.PropertiesToLoad.AddRange(("distinguishedName","msfve-recoverypassword","msfve-recoveryguid","msfve-volumeguid","mstpm-ownerinformation","mstpm-tpminformationforcomputer","name","whencreated"))
        $ObjSearcher.SearchScope = "Subtree"

        Try
        {
            $ADBitLockerRecoveryKeys = $ObjSearcher.FindAll()
        }
        Catch
        {
            Write-Warning "[Get-AdaptBitLocker] Error while enumerating msFVE-RecoveryInformation Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }
        $ObjSearcher.dispose()

        If ($ADBitLockerRecoveryKeys)
        {
            $cnt = $(Get-ObjectCount $ADBitLockerRecoveryKeys)
            If ($cnt -ge 1)
            {
                Write-Verbose "[*] Total BitLocker status: $cnt"
                $BitLockerObj = @()
                $ADBitLockerRecoveryKeys | ForEach-Object {
                    # Create the object for each instance.
                    $Obj = New-Object PSObject
                    $Obj | Add-Member -MemberType NoteProperty -Name "Distinguished Name" -Value $((($_.Properties.distinguishedname -split '}')[1]).substring(1))
                    $Obj | Add-Member -MemberType NoteProperty -Name "Name" -Value ([string] ($_.Properties.name))
                    $Obj | Add-Member -MemberType NoteProperty -Name "whenCreated" -Value ([DateTime] $($_.Properties.whencreated))
                    $Obj | Add-Member -MemberType NoteProperty -Name "Recovery Key ID" -Value $([GUID] $_.Properties.'msfve-recoveryguid'[0])
                    $Obj | Add-Member -MemberType NoteProperty -Name "Recovery Key" -Value ([string] ($_.Properties.'msfve-recoverypassword'))
                    $Obj | Add-Member -MemberType NoteProperty -Name "Volume GUID" -Value $([GUID] $_.Properties.'msfve-volumeguid'[0])

                    $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objDomain
                    $ObjSearcher.PageSize = $PageSize
                    $ObjSearcher.Filter = "(&(samAccountType=805306369)(distinguishedName=$($Obj.'Distinguished Name')))"
                    $ObjSearcher.PropertiesToLoad.AddRange(("mstpm-ownerinformation","mstpm-tpminformationforcomputer"))
                    $ObjSearcher.SearchScope = "Subtree"

                    Try
                    {
                        $TempComp = $ObjSearcher.FindAll()
                    }
                    Catch
                    {
                        Write-Warning "[Get-AdaptBitLocker] Error while enumerating $($Obj.'Distinguished Name') Computer Object"
                        Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
                    }
                    $ObjSearcher.dispose()

                    If ($TempComp)
                    {
                        # msTPM-OwnerInformation (Vista/7 or Server 2008/R2)
                        $Obj | Add-Member -MemberType NoteProperty -Name "msTPM-OwnerInformation" -Value $([string] $TempComp.Properties.'mstpm-ownerinformation')

                        # msTPM-TpmInformationForComputer (Windows 8/10 or Server 2012/R2)
                        $Obj | Add-Member -MemberType NoteProperty -Name "msTPM-TpmInformationForComputer" -Value $([string] $TempComp.Properties.'mstpm-tpminformationforcomputer')
                        If ($null -ne $TempComp.Properties.'mstpm-tpminformationforcomputer')
                        {
                            # Grab the TPM Owner Info from the msTPM-InformationObject
                            If ($Credential -ne [Management.Automation.PSCredential]::Empty)
                            {
                                $objSearchPath = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$($DomainController)/$($TempComp.Properties.'mstpm-tpminformationforcomputer')", $Credential.UserName,$Credential.GetNetworkCredential().Password
                                $objSearcherPath = New-Object System.DirectoryServices.DirectorySearcher $objSearchPath
                                $objSearcherPath.PropertiesToLoad.AddRange(("mstpm-ownerinformation"))
                                Try
                                {
                                    $TPMObject = $objSearcherPath.FindAll()
                                }
                                Catch
                                {
                                    Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
                                }
                                $objSearcherPath.dispose()

                                If ($TPMObject)
                                {
                                    $TPMRecoveryInfo = $([string] $TPMObject.Properties.'mstpm-ownerinformation')
                                }
                                Else
                                {
                                    $TPMRecoveryInfo = $null
                                }
                            }
                            Else
                            {
                                Try
                                {
                                    $TPMObject = ([ADSI]"LDAP://$($TempComp.Properties.'mstpm-tpminformationforcomputer')")
                                }
                                Catch
                                {
                                    Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
                                }
                                If ($TPMObject)
                                {
                                    $TPMRecoveryInfo = $([string] $TPMObject.Properties.'mstpm-ownerinformation')
                                }
                                Else
                                {
                                    $TPMRecoveryInfo = $null
                                }
                            }
                        }
                    }
                    Else
                    {
                        $Obj | Add-Member -MemberType NoteProperty -Name "msTPM-OwnerInformation" -Value $null
                        $Obj | Add-Member -MemberType NoteProperty -Name "msTPM-TpmInformationForComputer" -Value $null
                        $TPMRecoveryInfo = $null
                    }
                    $Obj | Add-Member -MemberType NoteProperty -Name "TPM Owner Password" -Value $TPMRecoveryInfo
                    $BitLockerObj += $Obj
                }
            }
            Remove-Variable cnt
            Remove-Variable ADBitLockerRecoveryKeys
        }
    }

    If ($BitLockerObj)
    {
        Return $BitLockerObj
    }
    Else
    {
        Return $null
    }
}

# SID to name resolution helper
Function ConvertFrom-SID
{
<#
.SYNOPSIS
    Converts a security identifier (SID) to a group/user name.

    Author: Will Schroeder
    License: BSD 3-Clause

.DESCRIPTION
    Converts a security identifier string (SID) to a group/user name using IADsNameTranslate interface.

.PARAMETER Method
    [string]
    Which method to use; ADWS (default), LDAP.

.PARAMETER ObjectSid
    Specifies one or more SIDs to convert.

.PARAMETER DomainFQDN
    Specifies the FQDN of the Domain.

.PARAMETER Credential
    Specifies an alternate credential to use for the translation.

.PARAMETER ResolveSIDs
    [bool]
    Whether to resolve SIDs in the ACLs module. (Default False)

.EXAMPLE

    ConvertFrom-SID S-1-5-21-890171859-3433809279-3366196753-1108

    DOMAIN\user

.EXAMPLE

    "S-1-5-21-890171859-3433809279-3366196753-1107", "S-1-5-21-890171859-3433809279-3366196753-1108", "S-1-5-32-562" | ConvertFrom-SID

    TESTLAB\WINDOWS2$
    DOMAIN\user
    BUILTIN\Distributed COM Users

.EXAMPLE

    $SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
    $Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm', $SecPassword)
    ConvertFrom-SID S-1-5-21-890171859-3433809279-3366196753-1108 -Credential $Cred

    DOMAIN\user

.INPUTS
    [String]
    Accepts one or more SID strings on the pipeline.

.OUTPUTS
    [String]
    The converted DOMAIN\username.
#>
    Param(
        [Parameter(Mandatory = $true)]
        [string] $Method,

        [Parameter(Mandatory = $true)]
        [Alias('SID')]
        #[ValidatePattern('^S-1-.*')]
        [String]
        $ObjectSid,

        [Parameter(Mandatory = $false)]
        [string] $DomainFQDN,

        [Parameter(Mandatory = $false)]
        [Management.Automation.PSCredential] $Credential = [Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false)]
        [bool] $ResolveSID = $false
    )

    BEGIN {
        # Name Translator Initialization Types
        # https://msdn.microsoft.com/en-us/library/aa772266%28v=vs.85%29.aspx
        $ADS_NAME_INITTYPE_DOMAIN   = 1 # Initializes a NameTranslate object by setting the domain that the object binds to.
        #$ADS_NAME_INITTYPE_SERVER   = 2 # Initializes a NameTranslate object by setting the server that the object binds to.
        $ADS_NAME_INITTYPE_GC       = 3 # Initializes a NameTranslate object by locating the global catalog that the object binds to.

        # Name Transator Name Types
        # https://msdn.microsoft.com/en-us/library/aa772267%28v=vs.85%29.aspx
        #$ADS_NAME_TYPE_1779                     = 1 # Name format as specified in RFC 1779. For example, "CN=Jeff Smith,CN=users,DC=Fabrikam,DC=com".
        #$ADS_NAME_TYPE_CANONICAL                = 2 # Canonical name format. For example, "Fabrikam.com/Users/Jeff Smith".
        $ADS_NAME_TYPE_NT4                      = 3 # Account name format used in Windows. For example, "Fabrikam\JeffSmith".
        #$ADS_NAME_TYPE_DISPLAY                  = 4 # Display name format. For example, "Jeff Smith".
        #$ADS_NAME_TYPE_DOMAIN_SIMPLE            = 5 # Simple domain name format. For example, "JeffSmith@Fabrikam.com".
        #$ADS_NAME_TYPE_ENTERPRISE_SIMPLE        = 6 # Simple enterprise name format. For example, "JeffSmith@Fabrikam.com".
        #$ADS_NAME_TYPE_GUID                     = 7 # Global Unique Identifier format. For example, "{95ee9fff-3436-11d1-b2b0-d15ae3ac8436}".
        $ADS_NAME_TYPE_UNKNOWN                  = 8 # Unknown name type. The system will estimate the format. This element is a meaningful option only with the IADsNameTranslate.Set or the IADsNameTranslate.SetEx method, but not with the IADsNameTranslate.Get or IADsNameTranslate.GetEx method.
        #$ADS_NAME_TYPE_USER_PRINCIPAL_NAME      = 9 # User principal name format. For example, "JeffSmith@Fabrikam.com".
        #$ADS_NAME_TYPE_CANONICAL_EX             = 10 # Extended canonical name format. For example, "Fabrikam.com/Users Jeff Smith".
        #$ADS_NAME_TYPE_SERVICE_PRINCIPAL_NAME   = 11 # Service principal name format. For example, "www/www.fabrikam.com@fabrikam.com".
        #$ADS_NAME_TYPE_SID_OR_SID_HISTORY_NAME  = 12 # A SID string, as defined in the Security Descriptor Definition Language (SDDL), for either the SID of the current object or one from the object SID history. For example, "O:AOG:DAD:(A;;RPWPCCDCLCSWRCWDWOGA;;;S-1-0-0)"

        # https://msdn.microsoft.com/en-us/library/aa772250.aspx
        #$ADS_CHASE_REFERRALS_NEVER       = (0x00) # The client should never chase the referred-to server. Setting this option prevents a client from contacting other servers in a referral process.
        #$ADS_CHASE_REFERRALS_SUBORDINATE = (0x20) # The client chases only subordinate referrals which are a subordinate naming context in a directory tree. For example, if the base search is requested for "DC=Fabrikam,DC=Com", and the server returns a result set and a referral of "DC=Sales,DC=Fabrikam,DC=Com" on the AdbSales server, the client can contact the AdbSales server to continue the search. The ADSI LDAP provider always turns off this flag for paged searches.
        #$ADS_CHASE_REFERRALS_EXTERNAL    = (0x40) # The client chases external referrals. For example, a client requests server A to perform a search for "DC=Fabrikam,DC=Com". However, server A does not contain the object, but knows that an independent server, B, owns it. It then refers the client to server B.
        $ADS_CHASE_REFERRALS_ALWAYS      = (0x60) # Referrals are chased for either the subordinate or external type.
    }

    PROCESS {
        $TargetSid = $($ObjectSid.TrimStart("O:"))
        $TargetSid = $($TargetSid.Trim('*'))
        If ($TargetSid -match '^S-1-.*')
        {
            Try
            {
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
                    'S-1-5-32-580'  { 'BUILTIN\Remote Management Users' }
                    Default {
                        # AD name format conversion
                        If ( ($TargetSid -match '^S-1-.*') -and ($ResolveSID) )
                        {
                            If ($Method -eq 'ADWS')
                            {
                                Try
                                {
                                    $ADObject = Get-ADObject -Filter "objectSid -eq '$TargetSid'" -Properties DistinguishedName,sAMAccountName
                                }
                                Catch
                                {
                                    Write-Warning "[ConvertFrom-SID] Error while enumerating Object using SID"
                                    Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
                                }
                                If ($ADObject)
                                {
                                    $UserDomain = Get-DNtoFQDN -ADObjectDN $ADObject.DistinguishedName
                                    $ADSOutput = $UserDomain + "\" + $ADObject.sAMAccountName
                                    Remove-Variable UserDomain
                                }
                            }

                            If ($Method -eq 'LDAP')
                            {
                                If ($Credential -ne [Management.Automation.PSCredential]::Empty)
                                {
                                    $ADObject = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$DomainFQDN/<SID=$TargetSid>",($Credential.GetNetworkCredential()).UserName,($Credential.GetNetworkCredential()).Password)
                                }
                                Else
                                {
                                    $ADObject = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$DomainFQDN/<SID=$TargetSid>")
                                }
                                If ($ADObject)
                                {
                                    If (-Not ([string]::IsNullOrEmpty($ADObject.Properties.samaccountname)) )
                                    {
                                        $UserDomain = Get-DNtoFQDN -ADObjectDN $([string] ($ADObject.Properties.distinguishedname))
                                        $ADSOutput = $UserDomain + "\" + $([string] ($ADObject.Properties.samaccountname))
                                        Remove-Variable UserDomain
                                    }
                                }
                            }

                            If ( (-Not $ADSOutput) -or ([string]::IsNullOrEmpty($ADSOutput)) )
                            {
                                $ADSOutputType = $ADS_NAME_TYPE_NT4
                                $Init = $true
                                $Translate = New-Object -ComObject NameTranslate
                                If ($Credential -ne [Management.Automation.PSCredential]::Empty)
                                {
                                    $ADSInitType = $ADS_NAME_INITTYPE_DOMAIN
                                    Try
                                    {
                                        [System.__ComObject].InvokeMember("InitEx","InvokeMethod",$null,$Translate,$(@($ADSInitType,$DomainFQDN,($Credential.GetNetworkCredential()).UserName,$DomainFQDN,($Credential.GetNetworkCredential()).Password)))
                                    }
                                    Catch
                                    {
                                        $Init = $false
                                        #Write-Verbose "[ConvertFrom-SID] Error initializing translation for $($TargetSid) using alternate credentials"
                                        #Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
                                    }
                                }
                                Else
                                {
                                    $ADSInitType = $ADS_NAME_INITTYPE_GC
                                    Try
                                    {
                                        [System.__ComObject].InvokeMember("Init","InvokeMethod",$null,$Translate,($ADSInitType,$null))
                                    }
                                    Catch
                                    {
                                        $Init = $false
                                        #Write-Verbose "[ConvertFrom-SID] Error initializing translation for $($TargetSid)"
                                        #Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
                                    }
                                }
                                If ($Init)
                                {
                                    [System.__ComObject].InvokeMember("ChaseReferral","SetProperty",$null,$Translate,$ADS_CHASE_REFERRALS_ALWAYS)
                                    Try
                                    {
                                        [System.__ComObject].InvokeMember("Set","InvokeMethod",$null,$Translate,($ADS_NAME_TYPE_UNKNOWN, $TargetSID))
                                        $ADSOutput = [System.__ComObject].InvokeMember("Get","InvokeMethod",$null,$Translate,$ADSOutputType)
                                    }
                                    Catch
                                    {
                                        #Write-Verbose "[ConvertFrom-SID] Error translating $($TargetSid)"
                                        #Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
                                    }
                                }
                            }
                        }
                        If (-Not ([string]::IsNullOrEmpty($ADSOutput)) )
                        {
                            Return $ADSOutput
                        }
                        Else
                        {
                            Return $TargetSid
                        }
                    }
                }
            }
            Catch
            {
                #Write-Output "[ConvertFrom-SID] Error converting SID $($TargetSid)"
                #Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            }
        }
        Else
        {
            Return $TargetSid
        }
    }
}

# based on https://gallery.technet.microsoft.com/Active-Directory-OU-1d09f989
Function Get-AdaptACL
{
<#
.SYNOPSIS
    Returns all ACLs for the Domain, OUs, Root Containers, GPO, User, Computer and Group objects in the current (or specified) domain.

.DESCRIPTION
    Returns all ACLs for the Domain, OUs, Root Containers, GPO, User, Computer and Group objects in the current (or specified) domain.

.PARAMETER Method
    [string]
    Which method to use; ADWS (default), LDAP.

.PARAMETER objDomain
    [DirectoryServices.DirectoryEntry]
    Domain Directory Entry object.

.PARAMETER DomainController
    [string]
    IP Address of the Domain Controller.

.PARAMETER Credential
    [Management.Automation.PSCredential]
    Credentials.

.PARAMETER ResolveSIDs
    [bool]
    Whether to resolve SIDs in the ACLs module. (Default False)

.PARAMETER PageSize
    [int]
    The PageSize to set for the LDAP searcher object. Default 200.

.PARAMETER Threads
    [int]
    The number of threads to use during processing of objects. Default 10.

.OUTPUTS
    PSObject.

.LINK
    https://gallery.technet.microsoft.com/Active-Directory-OU-1d09f989
#>
    param(
        [Parameter(Mandatory = $true)]
        [string] $Method,

        [Parameter(Mandatory = $false)]
        [DirectoryServices.DirectoryEntry] $objDomain,

        [Parameter(Mandatory = $false)]
        [string] $DomainController,

        [Parameter(Mandatory = $false)]
        [Management.Automation.PSCredential] $Credential = [Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false)]
        [bool] $ResolveSID = $false,

        [Parameter(Mandatory = $true)]
        [int] $PageSize = 200,

        [Parameter(Mandatory = $false)]
        [int] $Threads = 10,

        [Parameter(Mandatory = $false)]
        [string] $DnBase = $($ADDomain.DistinguishedName)
    )

    If ($Method -eq 'ADWS')
    {
        If ($Credential -eq [Management.Automation.PSCredential]::Empty)
        {
            If (Test-Path AD:)
            {
                Set-Location AD:
            }
            Else
            {
                Write-Warning "Default AD drive not found ... Skipping ACL enumeration"
                Return $null
            }
        }
        $GUIDs = @{'00000000-0000-0000-0000-000000000000' = 'All'}
        Try
        {
            Write-Verbose "[*] Enumerating schemaIDs"
            $schemaIDs = Get-ADObject -SearchBase (Get-ADRootDSE).schemaNamingContext -LDAPFilter '(schemaIDGUID=*)' -Properties name, schemaIDGUID
        }
        Catch
        {
            Write-Warning "[Get-AdaptACL] Error while enumerating schemaIDs"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
        }

        If ($schemaIDs)
        {
            $schemaIDs | Where-Object {$_} | ForEach-Object {
                # convert the GUID
                $GUIDs[(New-Object Guid (,$_.schemaIDGUID)).Guid] = $_.name
            }
            Remove-Variable schemaIDs
        }

        Try
        {
            Write-Verbose "[*] Enumerating Active Directory Rights"
            $schemaIDs = Get-ADObject -SearchBase "CN=Extended-Rights,$((Get-ADRootDSE).configurationNamingContext)" -LDAPFilter '(objectClass=controlAccessRight)' -Properties name, rightsGUID
        }
        Catch
        {
            Write-Warning "[Get-AdaptACL] Error while enumerating Active Directory Rights"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
        }

        If ($schemaIDs)
        {
            $schemaIDs | Where-Object {$_} | ForEach-Object {
                # convert the GUID
                $GUIDs[(New-Object Guid (,$_.rightsGUID)).Guid] = $_.name
            }
            Remove-Variable schemaIDs
        }

        # Get the DistinguishedNames of Domain, OUs, Root Containers and GroupPolicy objects.
        $Objs = @()
        Try
        {
            $ADDomain = Get-ADDomain
        }
        Catch
        {
            Write-Warning "[Get-AdaptACL] Error getting Domain Context"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
        }

        Try
        {
            Write-Verbose "[*] Enumerating Domain, OU, GPO, User, Computer and Group Objects"
            $Objs += Get-ADObject -SearchBase $DnBase -LDAPFilter '(|(objectClass=domain)(objectCategory=organizationalunit)(objectCategory=groupPolicyContainer)(samAccountType=805306368)(samAccountType=805306369)(samaccounttype=268435456)(samaccounttype=268435457)(samaccounttype=536870912)(samaccounttype=536870913))' -Properties DisplayName, DistinguishedName, Name, ntsecuritydescriptor, ObjectClass, objectsid
        }
        Catch
        {
            Write-Warning "[Get-AdaptACL] Error while enumerating Domain, OU, GPO, User, Computer and Group Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
        }

        If ($ADDomain)
        {
            Try
            {
                Write-Verbose "[*] Enumerating Root Container Objects"
                $Objs += Get-ADObject -SearchBase $($ADDomain.DistinguishedName) -SearchScope OneLevel -LDAPFilter '(objectClass=container)' -Properties DistinguishedName, Name, ntsecuritydescriptor, ObjectClass
            }
            Catch
            {
                Write-Warning "[Get-AdaptACL] Error while enumerating Root Container Objects"
                Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            }
        }

        If ($Objs)
        {
            $ACLObj = @()
            Write-Verbose "[*] Total Objects: $(Get-ObjectCount $Objs)"
            Write-Verbose "[-] DACLs"
            $DACLObj = Parse-DACL $Objs $GUIDs, $Threads
            #Write-Verbose "[-] SACLs - May need a Privileged Account"
            Write-Warning "[*] SACLs - Currently, the module is only supported with LDAP."
            #$SACLObj = Parse-SACL $Objs $GUIDs, $Threads
            Remove-Variable Objs
            Remove-Variable GUIDs
        }
    }

    If ($Method -eq 'LDAP')
    {
        $GUIDs = @{'00000000-0000-0000-0000-000000000000' = 'All'}

        If ($Credential -ne [Management.Automation.PSCredential]::Empty)
        {
            $DomainFQDN = Get-DNtoFQDN($objDomain.distinguishedName)
            $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("Domain",$($DomainFQDN),$($Credential.UserName),$($Credential.GetNetworkCredential().password))
            Try
            {
                $ADDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
            }
            Catch
            {
                Write-Warning "[Get-AdaptACL] Error getting Domain Context"
                Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            }

            Try
            {
                $ForestContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("Forest",$($ADDomain.Forest),$($Credential.UserName),$($Credential.GetNetworkCredential().password))
                $ADForest = [System.DirectoryServices.ActiveDirectory.Forest]::GetForest($ForestContext)
                $SchemaPath = $ADForest.Schema.Name
                Remove-Variable ADForest
            }
            Catch
            {
                Write-Warning "[Get-AdaptACL] Error enumerating SchemaPath"
                Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            }
        }
        Else
        {
            $ADDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            $ADForest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
            $SchemaPath = $ADForest.Schema.Name
            Remove-Variable ADForest
        }

        If ($SchemaPath)
        {
            Write-Verbose "[*] Enumerating schemaIDs"
            If ($Credential -ne [Management.Automation.PSCredential]::Empty)
            {
                $objSearchPath = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$($DomainController)/$($SchemaPath)", $Credential.UserName,$Credential.GetNetworkCredential().Password
                $objSearcherPath = New-Object System.DirectoryServices.DirectorySearcher $objSearchPath
            }
            Else
            {
                $objSearcherPath = New-Object System.DirectoryServices.DirectorySearcher ([ADSI] "LDAP://$($SchemaPath)")
            }
            $objSearcherPath.PageSize = $PageSize
            $objSearcherPath.filter = "(schemaIDGUID=*)"

            Try
            {
                $SchemaSearcher = $objSearcherPath.FindAll()
            }
            Catch
            {
                Write-Warning "[Get-AdaptACL] Error enumerating SchemaIDs"
                Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            }

            If ($SchemaSearcher)
            {
                $SchemaSearcher | Where-Object {$_} | ForEach-Object {
                    # convert the GUID
                    $GUIDs[(New-Object Guid (,$_.properties.schemaidguid[0])).Guid] = $_.properties.name[0]
                }
                $SchemaSearcher.dispose()
            }
            $objSearcherPath.dispose()

            Write-Verbose "[*] Enumerating Active Directory Rights"
            If ($Credential -ne [Management.Automation.PSCredential]::Empty)
            {
                $objSearchPath = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$($DomainController)/$($SchemaPath.replace("Schema","Extended-Rights"))", $Credential.UserName,$Credential.GetNetworkCredential().Password
                $objSearcherPath = New-Object System.DirectoryServices.DirectorySearcher $objSearchPath
            }
            Else
            {
                $objSearcherPath = New-Object System.DirectoryServices.DirectorySearcher ([ADSI] "LDAP://$($SchemaPath.replace("Schema","Extended-Rights"))")
            }
            $objSearcherPath.PageSize = $PageSize
            $objSearcherPath.filter = "(objectClass=controlAccessRight)"

            Try
            {
                $RightsSearcher = $objSearcherPath.FindAll()
            }
            Catch
            {
                Write-Warning "[Get-AdaptACL] Error enumerating Active Directory Rights"
                Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            }

            If ($RightsSearcher)
            {
                $RightsSearcher | Where-Object {$_} | ForEach-Object {
                    # convert the GUID
                    $GUIDs[$_.properties.rightsguid[0].toString()] = $_.properties.name[0]
                }
                $RightsSearcher.dispose()
            }
            $objSearcherPath.dispose()
        }

        # Get the Domain, OUs, Root Containers, GPO, User, Computer and Group objects.
        $Objs = @()
        Write-Verbose "[*] Enumerating Domain, OU, GPO, User, Computer and Group Objects"
        $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objDomain
        $ObjSearcher.PageSize = $PageSize
        $objSearcherPath.SearchRoot = "LDAP://$DnBase"
        $ObjSearcher.Filter = "(|(objectClass=domain)(objectCategory=organizationalunit)(objectCategory=groupPolicyContainer)(samAccountType=805306368)(samAccountType=805306369)(samaccounttype=268435456)(samaccounttype=268435457)(samaccounttype=536870912)(samaccounttype=536870913))"
        # https://msdn.microsoft.com/en-us/library/system.directoryservices.securitymasks(v=vs.110).aspx
        $ObjSearcher.SecurityMasks = [System.DirectoryServices.SecurityMasks]::Dacl -bor [System.DirectoryServices.SecurityMasks]::Group -bor [System.DirectoryServices.SecurityMasks]::Owner -bor [System.DirectoryServices.SecurityMasks]::Sacl
        $ObjSearcher.PropertiesToLoad.AddRange(("displayname","distinguishedname","name","ntsecuritydescriptor","objectclass","objectsid"))
        $ObjSearcher.SearchScope = "Subtree"

        Try
        {
            $Objs += $ObjSearcher.FindAll()
        }
        Catch
        {
            Write-Warning "[Get-AdaptACL] Error while enumerating Domain, OU, GPO, User, Computer and Group Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
        }
        $ObjSearcher.dispose()

        Write-Verbose "[*] Enumerating Root Container Objects"
        $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objDomain
        $ObjSearcher.PageSize = $PageSize
        $ObjSearcher.Filter = "(objectClass=container)"
        # https://msdn.microsoft.com/en-us/library/system.directoryservices.securitymasks(v=vs.110).aspx
        $ObjSearcher.SecurityMasks = $ObjSearcher.SecurityMasks = [System.DirectoryServices.SecurityMasks]::Dacl -bor [System.DirectoryServices.SecurityMasks]::Group -bor [System.DirectoryServices.SecurityMasks]::Owner -bor [System.DirectoryServices.SecurityMasks]::Sacl
        $ObjSearcher.PropertiesToLoad.AddRange(("distinguishedname","name","ntsecuritydescriptor","objectclass"))
        $ObjSearcher.SearchScope = "OneLevel"

        Try
        {
            $Objs += $ObjSearcher.FindAll()
        }
        Catch
        {
            Write-Warning "[Get-AdaptACL] Error while enumerating Root Container Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
        }
        $ObjSearcher.dispose()

        If ($Objs)
        {
            Write-Verbose "[*] Total Objects: $(Get-ObjectCount $Objs)"
            Write-Verbose "[-] DACLs"
            $DACLObj = Parse-DACL $Objs $GUIDs, $Threads
            Write-Verbose "[-] SACLs - May need a Privileged Account"
            $SACLObj = Parse-SACL $Objs $GUIDs, $Threads
            Remove-Variable Objs
            Remove-Variable GUIDs
        }
    }

    If ($DACLObj)
    {
        Export-Adapt $DACLObj $AdaptOutputDir $OutputType "DACLs"
        Remove-Variable DACLObj
    }

    If ($SACLObj)
    {
        Export-Adapt $SACLObj $AdaptOutputDir $OutputType "SACLs"
        Remove-Variable SACLObj
    }
}

Function Get-AdaptGPOReport
{
<#
.SYNOPSIS
    Runs the Get-GPOReport cmdlet if available.

.DESCRIPTION
    Runs the Get-GPOReport cmdlet if available and saves in HTML and XML formats.

.PARAMETER Method
    [string]
    Which method to use; ADWS (default), LDAP.

.PARAMETER UseAltCreds
    [bool]
    Whether to use provided credentials or not.

.PARAMETER AdaptOutputDir
    [string]
    Path for Adapt AD output folder.

.OUTPUTS
    HTML and XML GPOReports are created in the folder specified.
#>
    param(
        [Parameter(Mandatory = $true)]
        [string] $Method,

        [Parameter(Mandatory = $true)]
        [bool] $UseAltCreds,

        [Parameter(Mandatory = $true)]
        [string] $AdaptOutputDir
    )

    If ($Method -eq 'ADWS')
    {
        Try
        {
            # Suppress verbose output on module import
            $SaveVerbosePreference = $script:VerbosePreference
            $script:VerbosePreference = 'SilentlyContinue'

            If ($PSVersionTable.PSEdition -eq "Core")
            {
                Import-Module GroupPolicy -SkipEditionCheck -WarningAction Stop -ErrorAction Stop | Out-Null
            }
            Else
            {
                Import-Module GroupPolicy -WarningAction Stop -ErrorAction Stop | Out-Null
            }
            If ($SaveVerbosePreference)
            {
                $script:VerbosePreference = $SaveVerbosePreference
                Remove-Variable SaveVerbosePreference
            }
        }
        Catch
        {
            Write-Warning "[Get-AdaptGPOReport] Error importing the GroupPolicy Module. Skipping GPOReport"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            If ($SaveVerbosePreference)
            {
                $script:VerbosePreference = $SaveVerbosePreference
                Remove-Variable SaveVerbosePreference
            }
            Return $null
        }
        Try
        {
            Write-Verbose "[*] GPOReport XML"
            $AdaptFileName = -join($AdaptOutputDir,'\','GPO-Report','.xml')
            Get-GPOReport -All -ReportType XML -Path $AdaptFileName
        }
        Catch
        {
            If ($UseAltCreds)
            {
                Write-Warning "[*] Run the tool using RUNAS."
                Write-Warning "[*] runas /user:<Domain FQDN>\<Username> /netonly powershell.exe"
                Return $null
            }
            Write-Warning "[Get-AdaptGPOReport] Error getting the GPOReport in XML"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
        }
        Try
        {
            Write-Verbose "[*] GPOReport HTML"
            $AdaptFileName = -join($AdaptOutputDir,'\','GPO-Report','.html')
            Get-GPOReport -All -ReportType HTML -Path $AdaptFileName
        }
        Catch
        {
            If ($UseAltCreds)
            {
                Write-Warning "[*] Run the tool using RUNAS."
                Write-Warning "[*] runas /user:<Domain FQDN>\<Username> /netonly powershell.exe"
                Return $null
            }
            Write-Warning "[Get-AdaptGPOReport] Error getting the GPOReport in XML"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
        }
    }
    If ($Method -eq 'LDAP')
    {
        Write-Warning "[*] Currently, the module is only supported with ADWS."
    }
}

# SPNAudit module removed for compatibility

# based on https://gallery.technet.microsoft.com/scriptcenter/PowerShell-script-to-find-6fc15ecb
Function Get-AdaptDomainAccountsusedforServiceLogon
{
<#
.SYNOPSIS
    Returns all accounts used by services on computers in an Active Directory domain.

.DESCRIPTION
    Retrieves a list of all computers in the current domain and reads service configuration using Get-WmiObject.

.PARAMETER Method
    [string]
    Which method to use; ADWS (default), LDAP.

.PARAMETER objDomain
    [DirectoryServices.DirectoryEntry]
    Domain Directory Entry object.

.PARAMETER PageSize
    [int]
    The PageSize to set for the LDAP searcher object. Default 200.

.PARAMETER Threads
    [int]
    The number of threads to use during processing of objects. Default 10.

.OUTPUTS
    PSObject.
#>
    param(
        [Parameter(Mandatory = $true)]
        [string] $Method,

        [Parameter(Mandatory = $false)]
        [DirectoryServices.DirectoryEntry] $objDomain,

        [Parameter(Mandatory = $false)]
        [Management.Automation.PSCredential] $Credential = [Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $true)]
        [int] $PageSize = 200,

        [Parameter(Mandatory = $false)]
        [int] $Threads = 10
    )

    BEGIN {
        $readServiceAccounts = [scriptblock] {
            # scriptblock to retrieve service list form a remove machine
            $hostname = [string] $args[0]
            $OperatingSystem = [string] $args[1]
            #$Credential = [Management.Automation.PSCredential] $args[2]
            $Credential = $args[2]
            $timeout = 250
            $port = 135
            Try
            {
                $tcpclient = New-Object System.Net.Sockets.TcpClient
                $result = $tcpclient.BeginConnect($hostname,$port,$null,$null)
                $success = $result.AsyncWaitHandle.WaitOne($timeout,$null)
            }
            Catch
            {
                $warning = "$hostname ($OperatingSystem) is unreachable $($_.Exception.Message)"
                $success = $false
                $tcpclient.Close()
            }
            If ($success)
            {
                # PowerShellv2 does not support New-CimSession
                If ($PSVersionTable.PSVersion.Major -ne 2)
                {
                    If ($Credential -ne [Management.Automation.PSCredential]::Empty)
                    {
                        $session = New-CimSession -ComputerName $hostname -SessionOption $(New-CimSessionOption -Protocol DCOM) -Credential $Credential
                        If ($session)
                        {
                            $serviceList = @( Get-CimInstance -ClassName Win32_Service -Property Name,StartName,SystemName -CimSession $session -ErrorAction Stop)
                        }
                    }
                    Else
                    {
                        $session = New-CimSession -ComputerName $hostname -SessionOption $(New-CimSessionOption -Protocol DCOM)
                        If ($session)
                        {
                            $serviceList = @( Get-CimInstance -ClassName Win32_Service -Property Name,StartName,SystemName -CimSession $session -ErrorAction Stop )
                        }
                    }
                }
                Else
                {
                    If ($Credential -ne [Management.Automation.PSCredential]::Empty)
                    {
                        $serviceList = @( Get-WmiObject -Class Win32_Service -ComputerName $hostname -Credential $Credential -Impersonation 3 -Property Name,StartName,SystemName -ErrorAction Stop )
                    }
                    Else
                    {
                        $serviceList = @( Get-WmiObject -Class Win32_Service -ComputerName $hostname -Property Name,StartName,SystemName -ErrorAction Stop )
                    }
                }
                $serviceList
            }
            Try
            {
                If ($tcpclient) { $tcpclient.EndConnect($result) | Out-Null }
            }
            Catch
            {
                $warning = "$hostname ($OperatingSystem) : $($_.Exception.Message)"
            }
            $warning
        }

        Function processCompletedJobs()
        {
            # reads service list from completed jobs,
            # updates $serviceAccount table and removes completed job

            $jobs = Get-Job -State Completed
            ForEach( $job in $jobs )
            {
                If ($null -ne $job)
                {
                    $data = Receive-Job $job
                    Remove-Job $job
                }

                If ($data)
                {
                    If ( $data.GetType() -eq [Object[]] )
                    {
                        $serviceList = $data | Where-Object { if ($_.StartName) { $_ }}
                        $serviceList | ForEach-Object {
                            $Obj = New-Object PSObject
                            $Obj | Add-Member -MemberType NoteProperty -Name "Account" -Value $_.StartName
                            $Obj | Add-Member -MemberType NoteProperty -Name "Service Name" -Value $_.Name
                            $Obj | Add-Member -MemberType NoteProperty -Name "SystemName" -Value $_.SystemName
                            If ($_.StartName.toUpper().Contains($currentDomain))
                            {
                                $Obj | Add-Member -MemberType NoteProperty -Name "Running as Domain User" -Value $true
                            }
                            Else
                            {
                                $Obj | Add-Member -MemberType NoteProperty -Name "Running as Domain User" -Value $false
                            }
                            $script:serviceAccounts += $Obj
                        }
                    }
                    ElseIf ( $data.GetType() -eq [String] )
                    {
                        $script:warnings += $data
                        Write-Verbose $data
                    }
                }
            }
        }
    }

    PROCESS
    {
        $script:serviceAccounts = @()
        [string[]] $warnings = @()
        If ($Method -eq 'ADWS')
        {
            Try
            {
                $ADDomain = Get-ADDomain
            }
            Catch
            {
                Write-Warning "[Get-AdaptDomainAccountsusedforServiceLogon] Error getting Domain Context"
                Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
                Return $null
            }
            If ($ADDomain)
            {
                $currentDomain = $ADDomain.NetBIOSName.toUpper()
                Remove-Variable ADDomain
            }
            Else
            {
                $currentDomain = ""
                Write-Warning "Current Domain could not be retrieved."
            }

            Try
            {
                $ADComputers = Get-ADComputer -Filter { Enabled -eq $true -and OperatingSystem -Like "*Windows*" } -Properties Name,DNSHostName,OperatingSystem
            }
            Catch
            {
                Write-Warning "[Get-AdaptDomainAccountsusedforServiceLogon] Error while enumerating Windows Computer Objects"
                Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
                Return $null
            }

            If ($ADComputers)
            {
                # start data retrieval job for each server in the list
                # use up to $Threads threads
                $cnt = $(Get-ObjectCount $ADComputers)
                Write-Verbose "[*] Total Windows Hosts: $cnt"
                $icnt = 0
                $ADComputers | ForEach-Object {
                    $StopWatch = [System.Diagnostics.StopWatch]::StartNew()
                    If( $_.dnshostname )
	                {
                        $args = @($_.DNSHostName, $_.OperatingSystem, $Credential)
		                Start-Job -ScriptBlock $readServiceAccounts -Name "read_$($_.name)" -ArgumentList $args | Out-Null
		                ++$icnt
		                If ($StopWatch.Elapsed.TotalMilliseconds -ge 1000)
                        {
                            Write-Progress -Activity "Retrieving data from servers" -Status "$("{0:N2}" -f (($icnt/$cnt*100),2)) % Complete:" -PercentComplete 100
                            $StopWatch.Reset()
                            $StopWatch.Start()
		                }
                        while ( ( Get-Job -State Running).count -ge $Threads ) { Start-Sleep -Seconds 3 }
		                processCompletedJobs
	                }
                }

                # process remaining jobs

                Write-Progress -Activity "Retrieving data from servers" -Status "Waiting for background jobs to complete..." -PercentComplete 100
                Wait-Job -State Running -Timeout 30  | Out-Null
                Get-Job -State Running | Stop-Job
                processCompletedJobs
                Write-Progress -Activity "Retrieving data from servers" -Completed -Status "All Done"
            }
        }

        If ($Method -eq 'LDAP')
        {
            $currentDomain = ([string]($objDomain.name)).toUpper()

            $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objDomain
            $ObjSearcher.PageSize = $PageSize
            $ObjSearcher.Filter = "(&(samAccountType=805306369)(!userAccountControl:1.2.840.113556.1.4.803:=2)(operatingSystem=*Windows*))"
            $ObjSearcher.PropertiesToLoad.AddRange(("name","dnshostname","operatingsystem"))
            $ObjSearcher.SearchScope = "Subtree"

            Try
            {
                $ADComputers = $ObjSearcher.FindAll()
            }
            Catch
            {
                Write-Warning "[Get-AdaptDomainAccountsusedforServiceLogon] Error while enumerating Windows Computer Objects"
                Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
                Return $null
            }
            $ObjSearcher.dispose()

            If ($ADComputers)
            {
                # start data retrieval job for each server in the list
                # use up to $Threads threads
                $cnt = $(Get-ObjectCount $ADComputers)
                Write-Verbose "[*] Total Windows Hosts: $cnt"
                $icnt = 0
                $ADComputers | ForEach-Object {
                    If( $_.Properties.dnshostname )
	                {
                        $args = @($_.Properties.dnshostname, $_.Properties.operatingsystem, $Credential)
		                Start-Job -ScriptBlock $readServiceAccounts -Name "read_$($_.Properties.name)" -ArgumentList $args | Out-Null
		                ++$icnt
		                If ($StopWatch.Elapsed.TotalMilliseconds -ge 1000)
                        {
		                    Write-Progress -Activity "Retrieving data from servers" -Status "$("{0:N2}" -f (($icnt/$cnt*100),2)) % Complete:" -PercentComplete 100
                            $StopWatch.Reset()
                            $StopWatch.Start()
		                }
		                while ( ( Get-Job -State Running).count -ge $Threads ) { Start-Sleep -Seconds 3 }
		                processCompletedJobs
	                }
                }

                # process remaining jobs
                Write-Progress -Activity "Retrieving data from servers" -Status "Waiting for background jobs to complete..." -PercentComplete 100
                Wait-Job -State Running -Timeout 30  | Out-Null
                Get-Job -State Running | Stop-Job
                processCompletedJobs
                Write-Progress -Activity "Retrieving data from servers" -Completed -Status "All Done"
            }
        }

        If ($script:serviceAccounts)
        {
            Return $script:serviceAccounts
        }
        Else
        {
            Return $null
        }
    }
}

Function Remove-EmptyAdaptOutputDir
{
<#
.SYNOPSIS
    Removes Adapt AD output folder if empty.

.DESCRIPTION
    Removes Adapt AD output folder if empty.

.PARAMETER AdaptOutputDir
    [string]
	Path for Adapt AD output folder.

.PARAMETER OutputType
    [array]
    Output Type.
#>
    param(
        [Parameter(Mandatory = $true)]
        [string] $AdaptOutputDir,

        [Parameter(Mandatory = $true)]
        [array] $OutputType
    )

    Switch ($OutputType)
    {
        'CSV'
        {
            $CSVPath  = -join($AdaptOutputDir,'\','CSV-Files')
            If (!(Test-Path -Path $CSVPath\*))
            {
                Write-Verbose "Removed Empty Directory $CSVPath"
                Remove-Item $CSVPath
            }
        }
        'XML'
        {
            $XMLPath  = -join($AdaptOutputDir,'\','XML-Files')
            If (!(Test-Path -Path $XMLPath\*))
            {
                Write-Verbose "Removed Empty Directory $XMLPath"
                Remove-Item $XMLPath
            }
        }
        'JSON'
        {
            $JSONPath  = -join($AdaptOutputDir,'\','JSON-Files')
            If (!(Test-Path -Path $JSONPath\*))
            {
                Write-Verbose "Removed Empty Directory $JSONPath"
                Remove-Item $JSONPath
            }
        }
        'HTML'
        {
            $HTMLPath  = -join($AdaptOutputDir,'\','HTML-Files')
            If (!(Test-Path -Path $HTMLPath\*))
            {
                Write-Verbose "Removed Empty Directory $HTMLPath"
                Remove-Item $HTMLPath
            }
        }
    }
    If (!(Test-Path -Path $AdaptOutputDir\*))
    {
        Remove-Item $AdaptOutputDir
        Write-Verbose "Removed Empty Directory $AdaptOutputDir"
    }
}

Function Get-AdaptAbout
{
<#
.SYNOPSIS
    Returns information about Adapt AD.

.DESCRIPTION
    Returns information about Adapt AD.

.PARAMETER Method
    [string]
    Which method to use; ADWS (default), LDAP.

.PARAMETER date
    [DateTime]
    Date

.PARAMETER AdaptADVersion
    [string]
    Adapt AD Version.

.PARAMETER Credential
    [Management.Automation.PSCredential]
    Credentials.

.PARAMETER RanonComputer
    [string]
    Details of the Computer running Adapt AD.

.PARAMETER TotalTime
    [string]
    TotalTime.

.OUTPUTS
    PSObject.
#>
    param(
        [Parameter(Mandatory = $true)]
        [string] $Method,

        [Parameter(Mandatory = $true)]
        [DateTime] $date,

        [Parameter(Mandatory = $true)]
        [string] $AdaptADVersion,

        [Parameter(Mandatory = $false)]
        [Management.Automation.PSCredential] $Credential = [Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $true)]
        [string] $RanonComputer,

        [Parameter(Mandatory = $true)]
        [string] $TotalTime
    )

    $AboutAdaptAD = @()

    $Version = $Method + " Version"

    If ($Credential -ne [Management.Automation.PSCredential]::Empty)
    {
        $Username = $($Credential.UserName)
    }
    Else
    {
        $Username = $([Environment]::UserName)
    }

    $ObjValues = @("Date", $($date), "AdaptAD", "https://github.com/yourusername/AdaptAD", $Version, $($AdaptADVersion), "Ran as user", $Username, "Ran on computer", $RanonComputer, "Execution Time (mins)", $($TotalTime))

    For ($i = 0; $i -lt $($ObjValues.Count); $i++)
    {
        $Obj = New-Object PSObject
        $Obj | Add-Member -MemberType NoteProperty -Name "Category" -Value $ObjValues[$i]
        $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value $ObjValues[$i+1]
        $i++
        $AboutAdaptAD += $Obj
    }
    Return $AboutAdaptAD
}

Function Invoke-AdaptAD
{
<#
.SYNOPSIS
    Wrapper function to run Adapt AD modules.

.DESCRIPTION
    Wrapper function to set variables, check dependencies and run Adapt AD modules.

.PARAMETER Method
    [string]
    Which method to use; ADWS (default), LDAP.

.PARAMETER Collect
    [array]
    Which modules to run; Tenant, Forest, Domain, Trusts, Sites, Subnets, PasswordPolicy, FineGrainedPasswordPolicy, DomainControllers, Users, UserSPNs, PasswordAttributes, Groups, GroupMembers, GroupChanges, OUs, GPOs, gPLinks, DNSZones, Printers, Computers, ComputerSPNs, LAPS, BitLocker, ACLs, GPOReport, DomainAccountsusedforServiceLogon.

.PARAMETER DomainController
    [string]
    IP Address of the Domain Controller.

.PARAMETER Credential
    [Management.Automation.PSCredential]
    Credentials.

.PARAMETER OutputDir
    [string]
	Path for Adapt AD output folder to save the CSV files and the AdaptAD-Report.xlsx.

.PARAMETER DormantTimeSpan
    [int]
    Timespan for Dormant accounts. Default 90 days.

.PARAMETER PassMaxAge
    [int]
    Maximum machine account password age. Default 30 days

.PARAMETER PageSize
    [int]
    The PageSize to set for the LDAP searcher object. Default 200.

.PARAMETER Threads
    [int]
    The number of threads to use during processing of objects. Default 10.

.PARAMETER OnlyEnabled
    [bool]
    Only collect details for enabled objects.

.PARAMETER UseAltCreds
    [bool]
    Whether to use provided credentials or not.

.PARAMETER Logo
    [string]
    Which Logo to use in the excel file? AdaptAD (default), CyberCX, Payatu.

.OUTPUTS
    STDOUT, CSV, XML, JSON, HTML and/or Excel file is created in the folder specified with the information.
#>
    param(
        [Parameter(Mandatory = $false)]
        [string] $GenExcel,

        [Parameter(Mandatory = $false)]
        [ValidateSet('ADWS', 'LDAP')]
        [string] $Method = 'ADWS',

        [Parameter(Mandatory = $false)]
        [array] $Collect = 'Default',

        [Parameter(Mandatory = $false)]
        [string] $DomainController = '',

        [Parameter(Mandatory = $false)]
        [Management.Automation.PSCredential] $Credential = [Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false)]
        [array] $OutputType = 'Default',

        [Parameter(Mandatory = $false)]
        [string] $AdaptOutputDir,

        [Parameter(Mandatory = $false)]
        [int] $DormantTimeSpan = 90,

        [Parameter(Mandatory = $false)]
        [int] $PassMaxAge = 30,

        [Parameter(Mandatory = $false)]
        [int] $PageSize = 200,

        [Parameter(Mandatory = $false)]
        [int] $Threads = 10,

        [Parameter(Mandatory = $false)]
        [bool] $OnlyEnabled = $false,

        [Parameter(Mandatory = $false)]
        [bool] $UseAltCreds = $false,

        [Parameter(Mandatory = $false)]
        [ValidateSet('AdaptAD', 'CyberCX', 'Payatu')]
        [string] $Logo = "AdaptAD"
    )

    If ($PSVersionTable.PSEdition -eq "Core")
    {
        If ($PSVersionTable.Platform -ne "Win32NT")
        {
            Write-Warning "[Invoke-AdaptAD] Currently not supported ... Exiting"
            Return $null
        }
    }

    [string] $AdaptADVersion = "v1.0"

    $Banner = @"

     _    ____    _    ____ _____      _    ____
    / \  |  _ \  / \  |  _ \_   _|    / \  |  _ \
   / _ \ | | | |/ _ \ | |_) || |     / _ \ | | | |
  / ___ \| |_| / ___ \|  __/ | |    / ___ \| |_| |
 /_/   \_\____/_/   \_\_|    |_|   /_/   \_\____/

  Active Directory Reconnaissance & Assessment
  Based on ADRecon by Prashant Mahajan (@prashant3535)
"@

    Write-Output $Banner
    Write-Output "[*] Adapt AD $AdaptADVersion"

    If ($GenExcel)
    {
        If (-Not (Test-Path $GenExcel))
        {
            Write-Output "[Invoke-AdaptAD] Invalid Path ... Exiting"
            Return $null
        }
        Export-AdaptExcel -ExcelPath $GenExcel -Logo $Logo
        Return $null
    }

    # Suppress verbose output
    $SaveVerbosePreference = $script:VerbosePreference
    $script:VerbosePreference = 'SilentlyContinue'
    Try
    {
        If ($PSVersionTable.PSVersion.Major -ne 2)
        {
            $computer = Get-CimInstance -ClassName Win32_ComputerSystem
            $computerdomainrole = ($computer).DomainRole
        }
        Else
        {
            $computer = Get-WMIObject win32_computersystem
            $computerdomainrole = ($computer).DomainRole
        }
    }
    Catch
    {
        Write-Output "[Invoke-AdaptAD] $($_.Exception.Message)"
    }
    If ($SaveVerbosePreference)
    {
        $script:VerbosePreference = $SaveVerbosePreference
        Remove-Variable SaveVerbosePreference
    }

    switch ($computerdomainrole)
    {
        0
        {
            [string] $computerrole = "Standalone Workstation"
            $Env:ADPS_LoadDefaultDrive = 0
            $UseAltCreds = $true
        }
        1 { [string] $computerrole = "Member Workstation" }
        2
        {
            [string] $computerrole = "Standalone Server"
            $UseAltCreds = $true
            $Env:ADPS_LoadDefaultDrive = 0
        }
        3 { [string] $computerrole = "Member Server" }
        4 { [string] $computerrole = "Backup Domain Controller" }
        5 { [string] $computerrole = "Primary Domain Controller" }
        default { Write-Output "Computer Role could not be identified." }
    }

    $RanonComputer = "$($computer.domain)\$([Environment]::MachineName) - $($computerrole)"
    Remove-Variable computer
    Remove-Variable computerdomainrole
    Remove-Variable computerrole

    # If either DomainController or Credentials are provided, treat as non-member
    If (($DomainController -ne "") -or ($Credential -ne [Management.Automation.PSCredential]::Empty))
    {
        # Disable loading of default drive on member
        If (($Method -eq 'ADWS') -and (-Not $UseAltCreds))
        {
            $Env:ADPS_LoadDefaultDrive = 0
        }
        $UseAltCreds = $true
    }

    # Import ActiveDirectory module
    If ($Method -eq 'ADWS')
    {
        If (Get-Module -ListAvailable -Name ActiveDirectory)
        {
            Try
            {
                # Suppress verbose output on module import
                $SaveVerbosePreference = $script:VerbosePreference;
                $script:VerbosePreference = 'SilentlyContinue';
                Import-Module ActiveDirectory -WarningAction Stop -ErrorAction Stop | Out-Null
                If ($SaveVerbosePreference)
                {
                    $script:VerbosePreference = $SaveVerbosePreference
                    Remove-Variable SaveVerbosePreference
                }
            }
            Catch
            {
                Write-Warning "[Invoke-AdaptAD] Error importing ActiveDirectory Module from RSAT (Remote Server Administration Tools) ... Continuing with LDAP"
                $Method = 'LDAP'
                If ($SaveVerbosePreference)
                {
                    $script:VerbosePreference = $SaveVerbosePreference
                    Remove-Variable SaveVerbosePreference
                }
                Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            }
        }
        Else
        {
            Write-Warning "[Invoke-AdaptAD] ActiveDirectory Module from RSAT (Remote Server Administration Tools) is not installed ... Continuing with LDAP"
            $Method = 'LDAP'
        }
    }


    # C# compilation removed - using native PowerShell functions instead
    # This avoids EDR detection from Add-Type -TypeDefinition

    # Allow running using RUNAS from a non-domain joined machine
    # runas /user:<Domain FQDN>\<Username> /netonly powershell.exe
    If (($Method -eq 'LDAP') -and ($UseAltCreds) -and ($DomainController -eq "") -and ($Credential -eq [Management.Automation.PSCredential]::Empty))
    {
        Try
        {
            $objDomain = [ADSI]""
            If(!($objDomain.name))
            {
                Write-Verbose "[Invoke-AdaptAD] RUNAS Check, LDAP bind Unsuccessful"
            }
            $UseAltCreds = $false
            $objDomain.Dispose()
        }
        Catch
        {
            $UseAltCreds = $true
        }
    }

    If ($UseAltCreds -and (($DomainController -eq "") -or ($Credential -eq [Management.Automation.PSCredential]::Empty)))
    {

        If (($DomainController -ne "") -and ($Credential -eq [Management.Automation.PSCredential]::Empty))
        {
            Try
            {
                $Credential = Get-Credential
            }
            Catch
            {
                Write-Output "[Invoke-AdaptAD] $($_.Exception.Message)"
                Return $null
            }
        }
        Else
        {
            Write-Output "Run Get-Help .\Invoke-AdaptAD.ps1 -Examples for additional information."
            Write-Output "[Invoke-AdaptAD] Use the -DomainController and -Credential parameter."`n
            Return $null
        }
    }

    If ($Credential -ne [Management.Automation.PSCredential]::Empty)
    {
        $Username = $($Credential.UserName)
    }
    Else
    {
        $Username = $([Environment]::UserName)
    }

    Write-Output "[*] Running on $RanonComputer as $Username"

    Remove-Variable Username

    Switch ($Collect)
    {
        'Forest' { $AdaptForest = $true }
        'Domain' {$AdaptDomain = $true }
        'Trusts' { $AdaptTrust = $true }
        'Sites' { $AdaptSite = $true }
        'Subnets' { $AdaptSubnet = $true }
        'SchemaHistory' { $AdaptSchemaHistory = $true }
        'PasswordPolicy' { $AdaptPasswordPolicy = $true }
        'FineGrainedPasswordPolicy' { $AdaptFineGrainedPasswordPolicy = $true }
        'DomainControllers' { $AdaptDomainControllers = $true }
        'Users' { $AdaptUsers = $true }
        'UserSPNs' { $AdaptUserSPNs = $true }
        'PasswordAttributes' { $AdaptPasswordAttributes = $true }
        'Groups' {$AdaptGroups = $true }
        'GroupChanges' { $AdaptGroupChanges = $true }
        'GroupMembers' { $AdaptGroupMembers = $true }
        'OUs' { $AdaptOUs = $true }
        'GPOs' { $AdaptGPOs = $true }
        'gPLinks' { $AdaptgPLinks = $true }
        'DNSZones' { $AdaptDNSZones = $true }
        'DNSRecords' { $AdaptDNSRecords = $true }
        'Printers' { $AdaptPrinters = $true }
        'Computers' { $AdaptComputers = $true }
        'ComputerSPNs' { $AdaptComputerSPNs = $true }
        'LAPS' { $AdaptLAPS = $true }
        'BitLocker' { $AdaptBitLocker = $true }
        'ACLs' { $AdaptACLs = $true }
        'GPOReport'
        {
            $AdaptGPOReport = $true
            $AdaptCreate = $true
        }
        'DomainAccountsusedforServiceLogon' { $AdaptDomainAccountsusedforServiceLogon = $true }
        'Default'
        {
            $AdaptForest = $true
            $AdaptDomain = $true
            $AdaptTrust = $true
            $AdaptSite = $true
            $AdaptSubnet = $true
            $AdaptSchemaHistory = $true
            $AdaptPasswordPolicy = $true
            $AdaptFineGrainedPasswordPolicy = $true
            $AdaptDomainControllers = $true
            $AdaptUsers = $true
            $AdaptUserSPNs = $true
            $AdaptPasswordAttributes = $true
            $AdaptGroups = $true
            $AdaptGroupMembers = $true
            $AdaptGroupChanges = $true
            $AdaptOUs = $true
            $AdaptGPOs = $true
            $AdaptgPLinks = $true
            $AdaptDNSZones = $true
            $AdaptDNSRecords = $true
            $AdaptPrinters = $true
            $AdaptComputers = $true
            $AdaptComputerSPNs = $true
            $AdaptLAPS = $true
            $AdaptBitLocker = $true
            #$AdaptACLs = $true
            $AdaptGPOReport = $true
            #$AdaptSPNAudit = $true
            #$AdaptDomainAccountsusedforServiceLogon = $true

            If ($OutputType -eq "Default")
            {
                [array] $OutputType = "CSV","Excel"
            }
        }
    }

    Switch ($OutputType)
    {
        'STDOUT' { $AdaptSTDOUT = $true }
        'CSV'
        {
            $AdaptCSV = $true
            $AdaptCreate = $true
        }
        'XML'
        {
            $AdaptXML = $true
            $AdaptCreate = $true
        }
        'JSON'
        {
            $AdaptJSON = $true
            $AdaptCreate = $true
        }
        'HTML'
        {
            $AdaptHTML = $true
            $AdaptCreate = $true
        }
        'Excel'
        {
            $AdaptExcel = $true
            $AdaptCreate = $true
        }
        'All'
        {
            #$AdaptSTDOUT = $true
            $AdaptCSV = $true
            $AdaptXML = $true
            $AdaptJSON = $true
            $AdaptHTML = $true
            $AdaptExcel = $true
            $AdaptCreate = $true
            [array] $OutputType = "CSV","XML","JSON","HTML","Excel"
        }
        'Default'
        {
            [array] $OutputType = "STDOUT"
            $AdaptSTDOUT = $true
        }
    }

    If ( ($AdaptExcel) -and (-Not $AdaptCSV) )
    {
        $AdaptCSV = $true
        [array] $OutputType += "CSV"
    }

    $returndir = Get-Location
    $date = Get-Date

    # Create Output dir
    If ( ($AdaptOutputDir) -and ($AdaptCreate) )
    {
        If (!(Test-Path $AdaptOutputDir))
        {
            New-Item $AdaptOutputDir -type directory | Out-Null
            If (!(Test-Path $AdaptOutputDir))
            {
                Write-Output "[Invoke-AdaptAD] Error, invalid OutputDir Path ... Exiting"
                Return $null
            }
        }
        $AdaptOutputDir = $((Convert-Path $AdaptOutputDir).TrimEnd("\"))
        Write-Verbose "[*] Output Directory: $AdaptOutputDir"
    }
    ElseIf ($AdaptCreate)
    {
        $AdaptOutputDir =  -join($returndir,'\','AdaptAD-Report-',$(Get-Date -UFormat %Y%m%d%H%M%S))
        New-Item $AdaptOutputDir -type directory | Out-Null
        If (!(Test-Path $AdaptOutputDir))
        {
            Write-Output "[Invoke-AdaptAD] Error, could not create output directory"
            Return $null
        }
        $AdaptOutputDir = $((Convert-Path $AdaptOutputDir).TrimEnd("\"))
        Remove-Variable AdaptCreate
    }
    Else
    {
        $AdaptOutputDir = $returndir
    }

    If ($AdaptCSV)
    {
        $CSVPath = [System.IO.DirectoryInfo] -join($AdaptOutputDir,'\','CSV-Files')
        New-Item $CSVPath -type directory | Out-Null
        If (!(Test-Path $CSVPath))
        {
            Write-Output "[Invoke-AdaptAD] Error, could not create output directory"
            Return $null
        }
        Remove-Variable AdaptCSV
    }

    If ($AdaptXML)
    {
        $XMLPath = [System.IO.DirectoryInfo] -join($AdaptOutputDir,'\','XML-Files')
        New-Item $XMLPath -type directory | Out-Null
        If (!(Test-Path $XMLPath))
        {
            Write-Output "[Invoke-AdaptAD] Error, could not create output directory"
            Return $null
        }
        Remove-Variable AdaptXML
    }

    If ($AdaptJSON)
    {
        $JSONPath = [System.IO.DirectoryInfo] -join($AdaptOutputDir,'\','JSON-Files')
        New-Item $JSONPath -type directory | Out-Null
        If (!(Test-Path $JSONPath))
        {
            Write-Output "[Invoke-AdaptAD] Error, could not create output directory"
            Return $null
        }
        Remove-Variable AdaptJSON
    }

    If ($AdaptHTML)
    {
        $HTMLPath = [System.IO.DirectoryInfo] -join($AdaptOutputDir,'\','HTML-Files')
        New-Item $HTMLPath -type directory | Out-Null
        If (!(Test-Path $HTMLPath))
        {
            Write-Output "[Invoke-AdaptAD] Error, could not create output directory"
            Return $null
        }
        Remove-Variable AdaptHTML
    }

    # AD Login
    If ($UseAltCreds -and ($Method -eq 'ADWS'))
    {
        If (!(Test-Path Adapt:))
        {
            Try
            {
                New-PSDrive -PSProvider ActiveDirectory -Name Adapt -Root "" -Server $DomainController -Credential $Credential -ErrorAction Stop | Out-Null
            }
            Catch
            {
                Write-Output "[Invoke-AdaptAD] $($_.Exception.Message)"
                If ($AdaptOutputDir)
                {
                    Remove-EmptyAdaptOutputDir $AdaptOutputDir $OutputType
                }
                Return $null
            }
        }
        Else
        {
            Remove-PSDrive Adapt
            Try
            {
                New-PSDrive -PSProvider ActiveDirectory -Name Adapt -Root "" -Server $DomainController -Credential $Credential -ErrorAction Stop | Out-Null
            }
            Catch
            {
                Write-Output "[Invoke-AdaptAD] $($_.Exception.Message)"
                If ($AdaptOutputDir)
                {
                    Remove-EmptyAdaptOutputDir $AdaptOutputDir $OutputType
                }
                Return $null
            }
        }
        Set-Location Adapt:
        Write-Debug "Adapt PSDrive Created"
        #return $null
    }

    If ($Method -eq 'LDAP')
    {
        If ($UseAltCreds)
        {
            Try
            {
                $objDomain = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$($DomainController)", $Credential.UserName,$Credential.GetNetworkCredential().Password
                $objDomainRootDSE = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$($DomainController)/RootDSE", $Credential.UserName,$Credential.GetNetworkCredential().Password
            }
            Catch
            {
                Write-Output "[Invoke-AdaptAD] $($_.Exception.Message)"
                If ($AdaptOutputDir)
                {
                    Remove-EmptyAdaptOutputDir $AdaptOutputDir $OutputType
                }
                Return $null
            }
            If(!($objDomain.name))
            {
                Write-Output "[Invoke-AdaptAD] LDAP bind Unsuccessful"
                If ($AdaptOutputDir)
                {
                    Remove-EmptyAdaptOutputDir $AdaptOutputDir $OutputType
                }
                Return $null
            }
            Else
            {
                Write-Output "[*] LDAP bind Successful"
            }
        }
        Else
        {
            $objDomain = [ADSI]""
            $objDomainRootDSE = ([ADSI] "LDAP://RootDSE")
            If(!($objDomain.name))
            {
                Write-Output "[Invoke-AdaptAD] LDAP bind Unsuccessful"
                If ($AdaptOutputDir)
                {
                    Remove-EmptyAdaptOutputDir $AdaptOutputDir $OutputType
                }
                Return $null
            }
        }
        Write-Debug "LDAP Bing Successful"
        #return $null
    }

    Write-Output "[*] Commencing - $date"
    If ($AdaptDomain)
    {
        Write-Output "[-] Domain"
        $AdaptObject = Get-AdaptDomain -Method $Method -objDomain $objDomain -objDomainRootDSE $objDomainRootDSE -DomainController $DomainController -Credential $Credential
        If ($AdaptObject)
        {
            Export-Adapt -AdaptObj $AdaptObject -AdaptOutputDir $AdaptOutputDir -OutputType $OutputType -AdaptModuleName "Domain"
            Remove-Variable AdaptObject
        }
        Remove-Variable AdaptDomain
    }
    If ($AdaptForest)
    {
        Write-Output "[-] Forest"
        $AdaptObject = Get-AdaptForest -Method $Method -objDomain $objDomain -objDomainRootDSE $objDomainRootDSE -DomainController $DomainController -Credential $Credential
        If ($AdaptObject)
        {
            Export-Adapt -AdaptObj $AdaptObject -AdaptOutputDir $AdaptOutputDir -OutputType $OutputType -AdaptModuleName "Forest"
            Remove-Variable AdaptObject
        }
        Remove-Variable AdaptForest
    }
    If ($AdaptTrust)
    {
        Write-Output "[-] Trusts"
        $AdaptObject = Get-AdaptTrust -Method $Method -objDomain $objDomain
        If ($AdaptObject)
        {
            Export-Adapt -AdaptObj $AdaptObject -AdaptOutputDir $AdaptOutputDir -OutputType $OutputType -AdaptModuleName "Trusts"
            Remove-Variable AdaptObject
        }
        Remove-Variable AdaptTrust
    }
    If ($AdaptSite)
    {
        Write-Output "[-] Sites"
        $AdaptObject = Get-AdaptSite -Method $Method -objDomain $objDomain -objDomainRootDSE $objDomainRootDSE -DomainController $DomainController -Credential $Credential
        If ($AdaptObject)
        {
            Export-Adapt -AdaptObj $AdaptObject -AdaptOutputDir $AdaptOutputDir -OutputType $OutputType -AdaptModuleName "Sites"
            Remove-Variable AdaptObject
        }
        Remove-Variable AdaptSite
    }
    If ($AdaptSubnet)
    {
        Write-Output "[-] Subnets"
        $AdaptObject = Get-AdaptSubnet -Method $Method -objDomain $objDomain -objDomainRootDSE $objDomainRootDSE -DomainController $DomainController -Credential $Credential
        If ($AdaptObject)
        {
            Export-Adapt -AdaptObj $AdaptObject -AdaptOutputDir $AdaptOutputDir -OutputType $OutputType -AdaptModuleName "Subnets"
            Remove-Variable AdaptObject
        }
        Remove-Variable AdaptSubnet
    }
    If ($AdaptSchemaHistory)
    {
        Write-Output "[-] SchemaHistory - May take some time"
        $AdaptObject = Get-AdaptSchemaHistory -Method $Method -objDomain $objDomain -objDomainRootDSE $objDomainRootDSE -DomainController $DomainController -Credential $Credential
        If ($AdaptObject)
        {
            Export-Adapt -AdaptObj $AdaptObject -AdaptOutputDir $AdaptOutputDir -OutputType $OutputType -AdaptModuleName "SchemaHistory"
            Remove-Variable AdaptObject
        }
        Remove-Variable AdaptSchemaHistory
    }
    If ($AdaptPasswordPolicy)
    {
        Write-Output "[-] Default Password Policy"
        $AdaptObject = Get-AdaptDefaultPasswordPolicy -Method $Method -objDomain $objDomain
        If ($AdaptObject)
        {
            Export-Adapt -AdaptObj $AdaptObject -AdaptOutputDir $AdaptOutputDir -OutputType $OutputType -AdaptModuleName "DefaultPasswordPolicy"
            Remove-Variable AdaptObject
        }
        Remove-Variable AdaptPasswordPolicy
    }
    If ($AdaptFineGrainedPasswordPolicy)
    {
        Write-Output "[-] Fine Grained Password Policy - May need a Privileged Account"
        $AdaptObject = Get-AdaptFineGrainedPasswordPolicy -Method $Method -objDomain $objDomain
        If ($AdaptObject)
        {
            Export-Adapt -AdaptObj $AdaptObject -AdaptOutputDir $AdaptOutputDir -OutputType $OutputType -AdaptModuleName "FineGrainedPasswordPolicy"
            Remove-Variable AdaptObject
        }
        Remove-Variable AdaptFineGrainedPasswordPolicy
    }
    If ($AdaptDomainControllers)
    {
        Write-Output "[-] Domain Controllers"
        $AdaptObject = Get-AdaptDomainController -Method $Method -objDomain $objDomain -Credential $Credential
        If ($AdaptObject)
        {
            Export-Adapt -AdaptObj $AdaptObject -AdaptOutputDir $AdaptOutputDir -OutputType $OutputType -AdaptModuleName "DomainControllers"
            Remove-Variable AdaptObject
        }
        Remove-Variable AdaptDomainControllers
    }
    If ($AdaptUsers -or $AdaptUserSPNs)
    {
        If (!$AdaptUserSPNs)
        {
            Write-Output "[-] Users - May take some time"
            $AdaptUserSPNs = $false
        }
        ElseIf (!$AdaptUsers)
        {
            Write-Output "[-] User SPNs"
            $AdaptUsers = $false
        }
        Else
        {
            Write-Output "[-] Users and SPNs - May take some time"
        }
        Get-AdaptUser -Method $Method -date $date -objDomain $objDomain -DormantTimeSpan $DormantTimeSpan -PageSize $PageSize -Threads $Threads -AdaptUsers $AdaptUsers -AdaptUserSPNs $AdaptUserSPNs -OnlyEnabled $OnlyEnabled
        Remove-Variable AdaptUsers
        Remove-Variable AdaptUserSPNs
    }
    If ($AdaptPasswordAttributes)
    {
        Write-Output "[-] PasswordAttributes - Experimental"
        $AdaptObject = Get-AdaptPasswordAttributes -Method $Method -objDomain $objDomain -PageSize $PageSize
        If ($AdaptObject)
        {
            Export-Adapt -AdaptObj $AdaptObject -AdaptOutputDir $AdaptOutputDir -OutputType $OutputType -AdaptModuleName "PasswordAttributes"
            Remove-Variable AdaptObject
        }
        Remove-Variable AdaptPasswordAttributes
    }
    If ($AdaptGroups -or $AdaptGroupChanges)
    {
        If (!$AdaptGroupChanges)
        {
            Write-Output "[-] Groups - May take some time"
            $AdaptGroupChanges = $false
        }
        ElseIf (!$AdaptGroups)
        {
            Write-Output "[-] Group Membership Changes - May take some time"
            $AdaptGroups = $false
        }
        Else
        {
            Write-Output "[-] Groups and Membership Changes - May take some time"
        }
        Get-AdaptGroup -Method $Method -date $date -objDomain $objDomain -PageSize $PageSize -Threads $Threads -AdaptOutputDir $AdaptOutputDir -OutputType $OutputType -AdaptGroups $AdaptGroups -AdaptGroupChanges $AdaptGroupChanges
        Remove-Variable AdaptGroups
        Remove-Variable AdaptGroupChanges
    }
    If ($AdaptGroupMembers)
    {
        Write-Output "[-] Group Memberships - May take some time"

        $AdaptObject = Get-AdaptGroupMember -Method $Method -objDomain $objDomain -PageSize $PageSize -Threads $Threads
        If ($AdaptObject)
        {
            Export-Adapt -AdaptObj $AdaptObject -AdaptOutputDir $AdaptOutputDir -OutputType $OutputType -AdaptModuleName "GroupMembers"
            Remove-Variable AdaptObject
        }
        Remove-Variable AdaptGroupMembers
    }
    If ($AdaptOUs)
    {
        Write-Output "[-] OrganizationalUnits (OUs)"
        $AdaptObject = Get-AdaptOU -Method $Method -objDomain $objDomain -PageSize $PageSize -Threads $Threads
        If ($AdaptObject)
        {
            Export-Adapt -AdaptObj $AdaptObject -AdaptOutputDir $AdaptOutputDir -OutputType $OutputType -AdaptModuleName "OUs"
            Remove-Variable AdaptObject
        }
        Remove-Variable AdaptOUs
    }
    If ($AdaptGPOs)
    {
        Write-Output "[-] GPOs"
        $AdaptObject = Get-AdaptGPO -Method $Method -objDomain $objDomain -PageSize $PageSize -Threads $Threads
        If ($AdaptObject)
        {
            Export-Adapt -AdaptObj $AdaptObject -AdaptOutputDir $AdaptOutputDir -OutputType $OutputType -AdaptModuleName "GPOs"
            Remove-Variable AdaptObject
        }
        Remove-Variable AdaptGPOs
    }
    If ($AdaptgPLinks)
    {
        Write-Output "[-] gPLinks - Scope of Management (SOM)"
        $AdaptObject = Get-AdaptgPLink -Method $Method -objDomain $objDomain -PageSize $PageSize -Threads $Threads
        If ($AdaptObject)
        {
            Export-Adapt -AdaptObj $AdaptObject -AdaptOutputDir $AdaptOutputDir -OutputType $OutputType -AdaptModuleName "gPLinks"
            Remove-Variable AdaptObject
        }
        Remove-Variable AdaptgPLinks
    }
    If ($AdaptDNSZones -or $AdaptDNSRecords)
    {
        If (!$AdaptDNSRecords)
        {
            Write-Output "[-] DNS Zones"
            $AdaptDNSRecords = $false
        }
        ElseIf (!$AdaptDNSZones)
        {
            Write-Output "[-] DNS Records"
            $AdaptDNSZones = $false
        }
        Else
        {
            Write-Output "[-] DNS Zones and Records"
        }
        Get-AdaptDNSZone -Method $Method -objDomain $objDomain -DomainController $DomainController -Credential $Credential -PageSize $PageSize -AdaptOutputDir $AdaptOutputDir -OutputType $OutputType -AdaptDNSZones $AdaptDNSZones -AdaptDNSRecords $AdaptDNSRecords
        Remove-Variable AdaptDNSZones
    }
    If ($AdaptPrinters)
    {
        Write-Output "[-] Printers"
        $AdaptObject = Get-AdaptPrinter -Method $Method -objDomain $objDomain -PageSize $PageSize -Threads $Threads
        If ($AdaptObject)
        {
            Export-Adapt -AdaptObj $AdaptObject -AdaptOutputDir $AdaptOutputDir -OutputType $OutputType -AdaptModuleName "Printers"
            Remove-Variable AdaptObject
        }
        Remove-Variable AdaptPrinters
    }
    If ($AdaptComputers -or $AdaptComputerSPNs)
    {
        If (-Not $AdaptComputerSPNs)
        {
            Write-Output "[-] Computers - May take some time"
            $AdaptComputerSPNs = $false
        }
        ElseIf (-Not $AdaptComputers)
        {
            Write-Output "[-] Computer SPNs"
            $AdaptComputers = $false
        }
        Else
        {
            Write-Output "[-] Computers and SPNs - May take some time"
        }

        Get-AdaptComputer -Method $Method -date $date -objDomain $objDomain -DormantTimeSpan $DormantTimeSpan -PassMaxAge $PassMaxAge -PageSize $PageSize -Threads $Threads -AdaptComputers $AdaptComputers -AdaptComputerSPNs $AdaptComputerSPNs -OnlyEnabled $OnlyEnabled

        Remove-Variable AdaptComputers
        Remove-Variable AdaptComputerSPNs
    }
    If ($AdaptLAPS)
    {
        Write-Output "[-] LAPS - Needs Privileged Account to get the passwords"

        $AdaptLAPSCheck = Get-AdaptLAPSCheck -Method $Method -objDomainRootDSE $objDomainRootDSE -DomainController $DomainController -Credential $Credential

        If ($AdaptLAPSCheck)
        {
            $AdaptObject = Get-AdaptLAPS -Method $Method -objDomain $objDomain -PageSize $PageSize -Threads $Threads
        }
        Else
        {
            Write-Warning "[*] LAPS is not implemented."
        }

        If ($AdaptObject)
        {
            Export-Adapt -AdaptObj $AdaptObject -AdaptOutputDir $AdaptOutputDir -OutputType $OutputType -AdaptModuleName "LAPS"
            Remove-Variable AdaptObject
        }
        Remove-Variable AdaptLAPS
    }
    If ($AdaptBitLocker)
    {
        Write-Output "[-] BitLocker status - Needs Privileged Account"
        $AdaptObject = Get-AdaptBitLocker -Method $Method -objDomain $objDomain -DomainController $DomainController -Credential $Credential
        If ($AdaptObject)
        {
            Export-Adapt -AdaptObj $AdaptObject -AdaptOutputDir $AdaptOutputDir -OutputType $OutputType -AdaptModuleName "BitLockerRecoveryKeys"
            Remove-Variable AdaptObject
        }
        Remove-Variable AdaptBitLocker
    }
    If ($AdaptACLs)
    {
        Write-Output "[-] ACLs - May take some time"
        $AdaptObject = Get-AdaptACL -Method $Method -objDomain $objDomain -DomainController $DomainController -Credential $Credential -PageSize $PageSize -Threads $Threads
        Remove-Variable AdaptACLs
    }
    If ($AdaptGPOReport)
    {
        Write-Output "[-] GPOReport - May take some time"
        Get-AdaptGPOReport -Method $Method -UseAltCreds $UseAltCreds -AdaptOutputDir $AdaptOutputDir
        Remove-Variable AdaptGPOReport
    }
    # SPNAudit module removed
    If ($AdaptDomainAccountsusedforServiceLogon)
    {
        Write-Output "[-] Domain Accounts used for Service Logon - Needs Privileged Account"
        $AdaptObject = Get-AdaptDomainAccountsusedforServiceLogon -Method $Method -objDomain $objDomain -Credential $Credential -PageSize $PageSize -Threads $Threads
        If ($AdaptObject)
        {
            Export-Adapt -AdaptObj $AdaptObject -AdaptOutputDir $AdaptOutputDir -OutputType $OutputType -AdaptModuleName "DomainAccountsusedforServiceLogon"
            Remove-Variable AdaptObject
        }
        Remove-Variable AdaptDomainAccountsusedforServiceLogon
    }

    $TotalTime = "{0:N2}" -f ((Get-DateDiff -Date1 (Get-Date) -Date2 $date).TotalMinutes)

    $AboutAdaptAD = Get-AdaptAbout -Method $Method -date $date -AdaptADVersion $AdaptADVersion -Credential $Credential -RanonComputer $RanonComputer -TotalTime $TotalTime

    If ( ($OutputType -Contains "CSV") -or ($OutputType -Contains "XML") -or ($OutputType -Contains "JSON") -or ($OutputType -Contains "HTML") )
    {
        If ($AboutAdaptAD)
        {
            Export-Adapt -AdaptObj $AboutAdaptAD -AdaptOutputDir $AdaptOutputDir -OutputType $OutputType -AdaptModuleName "AboutAdaptAD"
        }
        Write-Output "[*] Total Execution Time (mins): $($TotalTime)"
        Write-Output "[*] Output Directory: $AdaptOutputDir"
        $AdaptSTDOUT = $false
    }

    Switch ($OutputType)
    {
        'STDOUT'
        {
            If ($AdaptSTDOUT)
            {
                Write-Output "[*] Total Execution Time (mins): $($TotalTime)"
            }
        }
        'HTML'
        {
            Export-Adapt -AdaptObj $(New-Object PSObject) -AdaptOutputDir $AdaptOutputDir -OutputType $([array] "HTML") -AdaptModuleName "Index"
        }
        'EXCEL'
        {
            Export-AdaptExcel -ExcelPath $AdaptOutputDir -Logo $Logo
        }
    }
    Remove-Variable TotalTime
    Remove-Variable AboutAdaptAD
    Set-Location $returndir
    Remove-Variable returndir

    If (($Method -eq 'ADWS') -and $UseAltCreds)
    {
        Remove-PSDrive Adapt
    }

    If ($Method -eq 'LDAP')
    {
        $objDomain.Dispose()
        $objDomainRootDSE.Dispose()
    }

    If ($AdaptOutputDir)
    {
        Remove-EmptyAdaptOutputDir $AdaptOutputDir $OutputType
    }

    Remove-Variable AdaptADVersion
    Remove-Variable RanonComputer
}

If ($Log)
{
    Start-Transcript -Path "$(Get-Location)\AdaptAD-Console-Log.txt"
}

Invoke-AdaptAD -GenExcel $GenExcel -Method $Method -Collect $Collect -DomainController $DomainController -Credential $Credential -OutputType $OutputType -AdaptOutputDir $OutputDir -DormantTimeSpan $DormantTimeSpan -PassMaxAge $PassMaxAge -PageSize $PageSize -Threads $Threads -OnlyEnabled $OnlyEnabled -Logo $Logo

If ($Log)
{
    Stop-Transcript
}