<#
    .SYNOPSIS
        DSC module for the ADFS Organization resource

    .DESCRIPTION
        The AdfsOrganization DSC resource manages the ADFS Organization information
        that is published in the federation metadata for the Federation Service.

    .PARAMETER FederationServiceName
        Key - String
        Specifies the DNS name of the federation service.

    .PARAMETER DisplayName
        Key - String
        Specifies the display name of the organization.

    .PARAMETER Name
        Key - String
        Specifies the name of the organization.

    .PARAMETER OrganizationUrl
        Key - String
        Specifies the URL of the organization.
#>

Set-StrictMode -Version Latest

$script:dscModuleName = 'AdfsDsc'
$script:PSModuleName = 'ADFS'
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
        Used Resource PowerShell Cmdlets:
        - Get-AdfsProperties - https://docs.microsoft.com/en-us/powershell/module/adfs/get-adfsproperties
    #>

    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $FederationServiceName,

        [Parameter(Mandatory = $true)]
        [System.String]
        $DisplayName,

        [Parameter(Mandatory = $true)]
        [System.String]
        $Name,

        [Parameter(Mandatory = $true)]
        [System.String]
        $OrganizationUrl
    )

    # Check of the ADFS PowerShell module is installed
    Assert-Module -ModuleName $script:PSModuleName

    # Check if the ADFS Service is present and running
    Assert-AdfsService -Verbose

    Write-Verbose -Message ($script:localizedData.GettingResourceMessage -f $FederationServiceName)

    try
    {
        $targetResource = (Get-AdfsProperties).OrganizationInfo
    }
    catch
    {
        $errorMessage = $script:localizedData.GettingResourceError -f $FederationServiceName
        New-InvalidOperationException -Message $errorMessage -Error $_
    }

    $returnValue = @{
        FederationServiceName = $FederationServiceName
        Name                  = $targetResource.Name
        DisplayName           = $targetResource.DisplayName
        OrganizationUrl       = $targetResource.OrganizationUrl
    }

    $returnValue
}

function Set-TargetResource
{
    <#
    .SYNOPSIS
        Get-TargetResource

    .NOTES
        Used Resource PowerShell Cmdlets:
        - New-AdfsOrganization - https://docs.microsoft.com/en-us/powershell/module/adfs/new-adfsorganization
        - Set-AdfsProperties   - https://docs.microsoft.com/en-us/powershell/module/adfs/set-adfsproperties
    #>

    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $FederationServiceName,

        [Parameter(Mandatory = $true)]
        [System.String]
        $DisplayName,

        [Parameter(Mandatory = $true)]
        [System.String]
        $Name,

        [Parameter(Mandatory = $true)]
        [System.String]
        $OrganizationUrl
    )

    # Remove any parameters not used in Splats
    [HashTable]$parameters = $PSBoundParameters
    $parameters.Remove('FederationServiceName')
    $parameters.Remove('Verbose')

    $GetTargetResourceParms = @{
        FederationServiceName = $FederationServiceName
        Name                  = $Name
        DisplayName           = $DisplayName
        OrganizationUrl       = $OrganizationUrl
    }
    $targetResource = Get-TargetResource @GetTargetResourceParms

    $propertiesNotInDesiredState = (
        Compare-ResourcePropertyState -CurrentValues $targetResource -DesiredValues $parameters |
            Where-Object -Property InDesiredState -eq $false)

    foreach ($property in $propertiesNotInDesiredState)
    {
        Write-Verbose -Message (
            $script:localizedData.SettingResourceMessage -f
            $FederationServiceName, $property.ParameterName, ($property.Expected -join ', '))
    }

    try
    {
        $organizationInfo = New-AdfsOrganization @parameters
    }
    catch
    {
        $errorMessage = $script:localizedData.NewAdfsOrganizationError -f $FederationServiceName
        New-InvalidOperationException -Message $errorMessage -Error $_
    }

    try
    {
        Set-AdfsProperties -OrganizationInfo $organizationInfo
    }
    catch
    {
        $errorMessage = $script:localizedData.SettingResourceError -f $FederationServiceName
        New-InvalidOperationException -Message $errorMessage -Error $_
    }
}

function Test-TargetResource
{
    <#
    .SYNOPSIS
        Test-TargetResource
    #>

    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $FederationServiceName,

        [Parameter(Mandatory = $true)]
        [System.String]
        $DisplayName,

        [Parameter(Mandatory = $true)]
        [System.String]
        $Name,

        [Parameter(Mandatory = $true)]
        [System.String]
        $OrganizationUrl
    )

    $getTargetResourceParms = @{
        FederationServiceName = $FederationServiceName
        DisplayName           = $DisplayName
        Name                  = $Name
        OrganizationUrl       = $OrganizationUrl
    }
    $targetResource = Get-TargetResource @getTargetResourceParms

    $propertiesNotInDesiredState = (
        Compare-ResourcePropertyState -CurrentValues $targetResource -DesiredValues $PSBoundParameters |
            Where-Object -Property InDesiredState -eq $false)

    if ($propertiesNotInDesiredState)
    {
        # Resource is not in desired state
        foreach ($property in $propertiesNotInDesiredState)
        {
            Write-Verbose -Message (
                $script:localizedData.ResourcePropertyNotInDesiredStateMessage -f
                $targetResource.FederationServiceName, $property.ParameterName, `
                    $property.Expected, $property.Actual)
        }
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
