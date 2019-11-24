<#
    .SYNOPSIS
        DSC module for the ADFS Contact Person resource

    .DESCRIPTION
        The AdfsContactPerson DSC resource manages the ADFS contact information for support isssues.

    .PARAMETER FederationServiceName
        Key - String
        Specifies the DNS name of the federation service.

    .PARAMETER Company
        Key - String
        Specifies the company name of the contact person.

    .PARAMETER EmailAddress
        Key - String[]
        Specifies an array of e-mail addresses of the contact person.

    .PARAMETER GivenName
        Key - String
        Specifies the given name, or first name of the contact person.

    .PARAMETER Surname
        Key - String
        Specifies the surname, or last name of the contact person.

    .PARAMETER TelephoneNumber
        Key - String[]
        Specifies an array of telephone numbers of the contact person.
#>

Set-StrictMode -Version 2.0

$script:dscModuleName = 'AdfsDsc'
$script:psModuleName = 'ADFS'
$script:dscResourceName = [System.IO.Path]::GetFileNameWithoutExtension($MyInvocation.MyCommand.Name)

$script:resourceModulePath = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent
$script:modulesFolderPath = Join-Path -Path $script:resourceModulePath -ChildPath 'Modules'

$script:localizationModulePath = Join-Path -Path $script:modulesFolderPath -ChildPath "$($script:DSCModuleName).Common"
Import-Module -Name (Join-Path -Path $script:localizationModulePath -ChildPath "$($script:dscModuleName).Common.psm1")

$script:localizedData = Get-LocalizedData -ResourceName $script:dscResourceName

function Get-TargetResource
{
    <#
    .SYNOPSIS
        Get-TargetResource

    .NOTES
        Used Cmdlets/Functions:

        Name                     | Module
        -------------------------|----------------
        Get-AdfsProperties       | Adfs
        Assert-Module            | AdfsDsc.Common
        Assert-AdfsService       | AdfsDsc.Common
    #>

    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $FederationServiceName
    )

    # Set Verbose and Debug parameters
    $commonParms = @{
        Verbose = $VerbosePreference
        Debug   = $DebugPreference
    }

    Write-Verbose -Message ($script:localizedData.GettingResourceMessage -f $FederationServiceName)

    # Check of the ADFS PowerShell module is installed
    Assert-Module -ModuleName $script:psModuleName

    # Check if the ADFS Service is present and running
    Assert-AdfsService @commonParms

    try
    {
        $targetResource = (Get-AdfsProperties).ContactPerson
    }
    catch
    {
        $errorMessage = $script:localizedData.GettingResourceErrorMessage -f $FederationServiceName
        New-InvalidOperationException -Message $errorMessage -Error $_
    }

    $returnValue = @{
        FederationServiceName = $FederationServiceName
        Company               = $targetResource.Company
        EmailAddress          = $targetResource.EmailAddress
        GivenName             = $targetResource.GivenName
        Surname               = $targetResource.Surname
        TelephoneNumber       = $targetResource.TelephoneNumber
    }

    $returnValue
}

function Set-TargetResource
{
    <#
    .SYNOPSIS
        Set-TargetResource

    .NOTES
        Used Cmdlets/Functions:

        Name                          | Module
        ------------------------------|----------------
        New-AdfsContactPerson         | Adfs
        Set-AdfsProperties            | Adfs
        Compare-ResourcePropertyState | AdfsDsc.Common
    #>

    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $FederationServiceName,

        [Parameter()]
        [System.String]
        $Company,

        [Parameter()]
        [System.String[]]
        $EmailAddress,

        [Parameter()]
        [System.String]
        $GivenName,

        [Parameter()]
        [System.String]
        $Surname,

        [Parameter()]
        [System.String[]]
        $TelephoneNumber
    )

    # Set Verbose and Debug parameters
    $commonParms = @{
        Verbose = $VerbosePreference
        Debug   = $DebugPreference
    }

    Write-Verbose -Message ($script:localizedData.SettingResourceMessage -f $FederationServiceName)

    # Remove any parameters not used in Splats
    [HashTable]$parameters = $PSBoundParameters
    $parameters.Remove('FederationServiceName')
    $parameters.Remove('Verbose')

    $GetTargetResourceParms = @{
        FederationServiceName = $FederationServiceName
    }
    $targetResource = Get-TargetResource @GetTargetResourceParms

    $propertiesNotInDesiredState = (
        Compare-ResourcePropertyState -CurrentValues $targetResource -DesiredValues $parameters `
            @commonParms | Where-Object -Property InDesiredState -eq $false)

    foreach ($property in $propertiesNotInDesiredState)
    {
        Write-Verbose -Message ($script:localizedData.SettingResourcePropertyMessage -f
            $FederationServiceName, $property.ParameterName, ($property.Expected -join ', '))
    }

    try
    {
        $contactPerson = New-AdfsContactPerson @parameters
    }
    catch
    {
        $errorMessage = $script:localizedData.NewAdfsContactPersonErrorMessage -f $FederationServiceName
        New-InvalidOperationException -Message $errorMessage -Error $_
    }

    try
    {
        Set-AdfsProperties -ContactPerson $contactPerson
    }
    catch
    {
        $errorMessage = $script:localizedData.SettingResourceErrorMessage -f $FederationServiceName
        New-InvalidOperationException -Message $errorMessage -Error $_
    }
}

function Test-TargetResource
{
    <#
    .SYNOPSIS
        Test-TargetResource

    .NOTES
        Used Cmdlets/Functions:

        Name                          | Module
        ------------------------------|------------------
        Compare-ResourcePropertyState | AdfsDsc.Common
    #>

    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $FederationServiceName,

        [Parameter()]
        [System.String]
        $Company,

        [Parameter()]
        [System.String[]]
        $EmailAddress,

        [Parameter()]
        [System.String]
        $GivenName,

        [Parameter()]
        [System.String]
        $Surname,

        [Parameter()]
        [System.String[]]
        $TelephoneNumber
    )

    # Set Verbose and Debug parameters
    $commonParms = @{
        Verbose = $VerbosePreference
        Debug   = $DebugPreference
    }

    Write-Verbose -Message ($script:localizedData.TestingResourceMessage -f $FederationServiceName)

    $getTargetResourceParms = @{
        FederationServiceName = $FederationServiceName
    }
    $targetResource = Get-TargetResource @getTargetResourceParms

    $propertiesNotInDesiredState = (
        Compare-ResourcePropertyState -CurrentValues $targetResource -DesiredValues $PSBoundParameters `
            @commonParms | Where-Object -Property InDesiredState -eq $false)

    if ($propertiesNotInDesiredState)
    {
        # Resource is not in desired state
        Write-Verbose -Message ($script:localizedData.ResourceNotInDesiredStateMessage -f $FederationServiceName)

        $inDesiredState = $false
    }
    else
    {
        # Resource is in desired state
        Write-Verbose -Message ($script:localizedData.ResourceInDesiredStateMessage -f $FederationServiceName)

        $inDesiredState = $true
    }

    $inDesiredState
}


Export-ModuleMember -Function *-TargetResource

