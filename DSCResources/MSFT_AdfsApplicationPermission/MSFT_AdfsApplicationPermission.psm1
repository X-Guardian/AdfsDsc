<#
    .SYNOPSIS
        DSC module for the ADFS Application Permission resource

    .DESCRIPTION
        The AdfsApplicationPermission DSC resource manages Application Permissions within Active Directory Federation
        Services.

        ## Requirements

        * Target machine must be running ADFS on Windows Server 2016 or above to use this resource.

    .PARAMETER ClientRoleIdentifier
        Key - String
        Specifies a client role identifier.

    .PARAMETER ServerRoleIdentifier
        Key - String
        Specifies a server role identifier.

    .PARAMETER ScopeNames
        Write - String
        Specifies an array of scope names.

    .PARAMETER Description
        Write - String
        Specifies a description for the Application Permission.

    .PARAMETER Ensure
        Write - String
        Allowed values: Present, Absent
        Specifies whether the Application Permission should be present or absent. Default value is 'Present'.
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
        Used Resource PowerShell Cmdlets:
        - Get-AdfsApplicationPermission - https://docs.microsoft.com/en-us/powershell/module/adfs/get-adfsapplicationpermission
    #>

    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $ClientRoleIdentifier,

        [Parameter(Mandatory = $true)]
        [System.String]
        $ServerRoleIdentifier
    )

    # Check of the ADFS PowerShell module is installed
    Assert-Module -ModuleName $script:psModuleName

    # Check if the Get-AdfsApplicationPermission command is available
    Assert-Command -Module $script:psModuleName -Command 'Get-AdfsApplicationPermission'

    # Check if the ADFS Service is present and running
    Assert-AdfsService -Verbose

    Write-Verbose ($script:localizedData.GettingResourceMessage -f
        $ClientRoleIdentifier, $ServerRoleIdentifier)

    $targetResource = Get-AdfsApplicationPermission -ClientRoleIdentifiers $ClientRoleIdentifier |
        Where-Object -Property ServerRoleIdentifier -eq $ServerRoleIdentifier

    if ($targetResource)
    {
        # Resource exists
        $returnValue = @{
            ClientRoleIdentifier = $targetResource.ClientRoleIdentifier
            ServerRoleIdentifier = $targetResource.ServerRoleIdentifier
            ScopeNames           = $targetResource.ScopeNames
            Description          = $targetResource.Description
            Ensure               = 'Present'
        }
    }
    else
    {
        # Resource does not exist
        $returnValue = @{
            ClientRoleIdentifier = $ClientRoleIdentifier
            ServerRoleIdentifier = $ServerRoleIdentifier
            ScopeNames           = @()
            Description          = $null
            Ensure               = 'Absent'
        }
    }

    $returnValue
}

function Set-TargetResource
{
    <#
    .SYNOPSIS
        Set-TargetResource

    .NOTES
        Resource PowerShell Cmdlets:
        - Grant-AdfsApplicationPermission  - https://docs.microsoft.com/en-us/powershell/module/adfs/grant-adfsapplicationpermission
        - Set-AdfsApplicationPermission    - https://docs.microsoft.com/en-us/powershell/module/adfs/set-adfsapplicationpermission
        - Revoke-AdfsApplicationPermission - https://docs.microsoft.com/en-us/powershell/module/adfs/revoke-adfsapplicationpermission
    #>

    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $ClientRoleIdentifier,

        [Parameter(Mandatory = $true)]
        [System.String]
        $ServerRoleIdentifier,

        [Parameter()]
        [System.String]
        $Description,

        [Parameter()]
        [System.String[]]
        $ScopeNames,

        [Parameter()]
        [ValidateSet('Present', 'Absent')]
        [System.String]
        $Ensure = 'Present'
    )

    # Remove any parameters not used in Splats
    $parameters = $PSBoundParameters
    $parameters.Remove('Ensure')
    $parameters.Remove('Verbose')
    $parameters.Remove('ClientRoleIdentifier')
    $parameters.Remove('ServerRoleIdentifier')

    $getTargetResourceParms = @{
        ClientRoleIdentifier = $ClientRoleIdentifier
        ServerRoleIdentifier = $ServerRoleIdentifier
    }
    $targetResource = Get-TargetResource @getTargetResourceParms

    if ($targetResource.Ensure -eq 'Present')
    {
        # Resource is Present
        if ($Ensure -eq 'Present')
        {
            # Resource Should be Present
            $propertiesNotInDesiredState = (
                Compare-ResourcePropertyState -CurrentValues $targetResource -DesiredValues $parameters |
                    Where-Object -Property InDesiredState -eq $false)

            $setParameters = @{ }
            foreach ($property in $propertiesNotInDesiredState)
            {
                Write-Verbose -Message ($script:localizedData.SettingResourceMessage -f
                    $ClientRoleIdentifier, $ServerRoleIdentifier, $property.ParameterName, `
                    ($property.Expected -join ', '))
                $setParameters.add($property.ParameterName, $property.Expected)
            }

            Set-AdfsApplicationPermission `
                -TargetClientRoleIdentifier $ClientRoleIdentifier `
                -TargetServerRoleIdentifier $ServerRoleIdentifier `
                @setParameters
        }
        else
        {
            # Resource should be Absent
            Write-Verbose -Message ($script:localizedData.RemovingResourceMessage -f
                $ClientRoleIdentifier, $ServerRoleIdentifier)
            Revoke-AdfsApplicationPermission `
                -TargetClientRoleIdentifier $ClientRoleIdentifier `
                -TargetServerRoleIdentifier $ServerRoleIdentifier
        }
    }
    else
    {
        # Resource is Absent
        if ($Ensure -eq 'Present')
        {
            # Resource should be Present
                Write-Verbose -Message ($script:localizedData.AddingResourceMessage -f
                $ClientRoleIdentifier, $ServerRoleIdentifier)
                Grant-AdfsApplicationPermission `
                    -ClientRoleIdentifier $ClientRoleIdentifier `
                    -ServerRoleIdentifier $ServerRoleIdentifier `
                    @parameters
        }
        else
        {
            # Resource should be Absent
            Write-Verbose -Message ($script:localizedData.ResourceInDesiredStateMessage -f
                $ClientRoleIdentifier, $ServerRoleIdentifier)
        }
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
        $ClientRoleIdentifier,

        [Parameter(Mandatory = $true)]
        [System.String]
        $ServerRoleIdentifier,

        [Parameter()]
        [System.String]
        $Description,

        [Parameter()]
        [System.String[]]
        $ScopeNames,

        [Parameter()]
        [ValidateSet('Present', 'Absent')]
        [System.String]
        $Ensure = 'Present'
    )

    $getTargetResourceParms = @{
        ClientRoleIdentifier = $ClientRoleIdentifier
        ServerRoleIdentifier = $ServerRoleIdentifier
    }
    $targetResource = Get-TargetResource @getTargetResourceParms

    if ($targetResource.Ensure -eq 'Present')
    {
        # Resource is Present
        if ($Ensure -eq 'Present')
        {
            # Resource should be Present
            $propertiesNotInDesiredState = (
                Compare-ResourcePropertyState -CurrentValues $targetResource -DesiredValues $PSBoundParameters |
                    Where-Object -Property InDesiredState -eq $false)

            if ($propertiesNotInDesiredState)
            {
                # Resource is not in desired state
                foreach ($property in $propertiesNotInDesiredState)
                {
                    Write-Verbose -Message ($script:localizedData.ResourcePropertyNotInDesiredStateMessage -f
                        $targetResource.ClientRoleIdentifier, $targetResource.ServerRoleIdentifier, `
                            $property.ParameterName, $property.Expected, $property.Actual)
                }
                $inDesiredState = $false
            }
            else
            {
                # Resource is in desired state
                Write-Verbose -Message ($script:localizedData.ResourceInDesiredStateMessage -f
                    $targetResource.ClientRoleIdentifier, $targetResource.ServerRoleIdentifier)
                $inDesiredState = $true
            }
        }
        else
        {
            # Resource should be Absent
            Write-Verbose -Message ($script:localizedData.ResourceIsPresentButShouldBeAbsentMessage -f
                $targetResource.ClientRoleIdentifier, $targetResource.ServerRoleIdentifier)
            $inDesiredState = $false
        }
    }
    else
    {
        # Resource is Absent
        if ($Ensure -eq 'Present')
        {
            # Resource should be Present
            Write-Verbose -Message ($script:localizedData.ResourceIsAbsentButShouldBePresentMessage -f
                $ClientRoleIdentifier, $ServerRoleIdentifier)
            $inDesiredState = $false
        }
        else
        {
            # Resource should be Absent
            Write-Verbose -Message ($script:localizedData.ResourceInDesiredStateMessage -f
                $ClientRoleIdentifier, $ServerRoleIdentifier)
            $inDesiredState = $true
        }
    }

    $inDesiredState
}

Export-ModuleMember -Function *-TargetResource
