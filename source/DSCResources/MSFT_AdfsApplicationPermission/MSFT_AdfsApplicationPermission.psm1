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
        Used Cmdlets/Functions:

        Name                          | Module
        ------------------------------|----------------
        Get-AdfsApplicationPermission | Adfs
        Assert-Module                 | AdfsDsc.Common
        Assert-Command                | AdfsDsc.Common
        Assert-AdfsService            | AdfsDsc.Common
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

    # Set Verbose and Debug parameters
    $commonParms = @{
        Verbose = $VerbosePreference
        Debug   = $DebugPreference
    }

    Write-Verbose -Message ($script:localizedData.GettingResourceMessage -f
        $ClientRoleIdentifier, $ServerRoleIdentifier)

    # Check of the ADFS PowerShell module is installed
    Assert-Module -ModuleName $script:psModuleName

    # Check if the Get-AdfsApplicationPermission command is available
    Assert-Command -Module $script:psModuleName -Command 'Get-AdfsApplicationPermission'

    # Check if the ADFS Service is present and running
    Assert-AdfsService @commonParms

    try
    {
        $targetResource = Get-AdfsApplicationPermission -ClientRoleIdentifiers $ClientRoleIdentifier | `
            Where-Object -Property ServerRoleIdentifier -eq $ServerRoleIdentifier
    }
    catch
    {
        $errorMessage = ($script:localizedData.GettingResourceErrorMessage -f
            $ClientRoleIdentifier, $ServerRoleIdentifier)
        New-InvalidOperationException -Message $errorMessage -Error $_
    }

    if ($targetResource)
    {
        # Resource is Present
        Write-Debug -Message ($script:localizedData.TargetResourcePresentDebugMessage -f
            $ClientRoleIdentifier, $ServerRoleIdentifier)

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
        # Resource is Absent
        Write-Debug -Message ($script:localizedData.TargetResourceAbsentDebugMessage -f
            $ClientRoleIdentifier, $ServerRoleIdentifier)

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
        Used Cmdlets/Functions:

        Name                             | Module
        ---------------------------------|----------------
        Grant-AdfsApplicationPermission  | Adfs
        Set-AdfsApplicationPermission    | Adfs
        Revoke-AdfsApplicationPermission | Adfs
        Compare-ResourcePropertyState    | AdfsDsc.Common
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

    # Set Verbose and Debug parameters
    $commonParms = @{
        Verbose = $VerbosePreference
        Debug   = $DebugPreference
    }

    # Remove any parameters not used in Splats
    $parameters = $PSBoundParameters
    $parameters.Remove('Ensure')
    $parameters.Remove('Verbose')
    $parameters.Remove('ClientRoleIdentifier')
    $parameters.Remove('ServerRoleIdentifier')

    Write-Verbose -Message ($script:localizedData.SettingResourceMessage -f
        $ClientRoleIdentifier, $ServerRoleIdentifier)

    $getTargetResourceParms = @{
        ClientRoleIdentifier = $ClientRoleIdentifier
        ServerRoleIdentifier = $ServerRoleIdentifier
    }
    $targetResource = Get-TargetResource @getTargetResourceParms

    if ($targetResource.Ensure -eq 'Present')
    {
        # Resource is Present
        Write-Debug -Message ($script:localizedData.TargetResourcePresentDebugMessage -f
            $ClientRoleIdentifier, $ServerRoleIdentifier)

        if ($Ensure -eq 'Present')
        {
            # Resource Should be Present
            Write-Debug -Message ($script:localizedData.TargetResourceShouldBePresentDebugMessage -f
                $ClientRoleIdentifier, $ServerRoleIdentifier)

            $propertiesNotInDesiredState = (
                Compare-ResourcePropertyState -CurrentValues $targetResource -DesiredValues $parameters `
                    @commonParms | Where-Object -Property InDesiredState -eq $false)

            $setParameters = @{ }
            foreach ($property in $propertiesNotInDesiredState)
            {
                Write-Verbose -Message ($script:localizedData.SettingResourcePropertyMessage -f
                    $ClientRoleIdentifier, $ServerRoleIdentifier, $property.ParameterName, `
                    ($property.Expected -join ', '))

                $setParameters.add($property.ParameterName, $property.Expected)
            }

            try
            {
                Set-AdfsApplicationPermission `
                    -TargetClientRoleIdentifier $ClientRoleIdentifier `
                    -TargetServerRoleIdentifier $ServerRoleIdentifier `
                    @setParameters
            }
            catch
            {
                $errorMessage = ($script:localizedData.SettingResourceErrorMessage -f
                    $ClientRoleIdentifier, $ServerRoleIdentifier)
                New-InvalidOperationException -Message $errorMessage -Error $_
            }
        }
        else
        {
            # Resource should be Absent
            Write-Debug -Message ($script:localizedData.TargetResourceShouldBeAbsentDebugMessage -f
                $ClientRoleIdentifier, $ServerRoleIdentifier)

            Write-Verbose -Message ($script:localizedData.RemovingResourceMessage -f
                $ClientRoleIdentifier, $ServerRoleIdentifier)

            try
            {
                Revoke-AdfsApplicationPermission `
                    -TargetClientRoleIdentifier $ClientRoleIdentifier `
                    -TargetServerRoleIdentifier $ServerRoleIdentifier
            }
            catch
            {
                $errorMessage = ($script:localizedData.RemovingResourceErrorMessage -f
                    $ClientRoleIdentifier, $ServerRoleIdentifier)
                New-InvalidOperationException -Message $errorMessage -Error $_
            }
        }
    }
    else
    {
        # Resource is Absent
        Write-Debug -Message ($script:localizedData.TargetResourceAbsentDebugMessage -f
            $ClientRoleIdentifier, $ServerRoleIdentifier)

        if ($Ensure -eq 'Present')
        {
            # Resource should be Present
            Write-Debug -Message ($script:localizedData.TargetResourceShouldBePresentDebugMessage -f
                $ClientRoleIdentifier, $ServerRoleIdentifier)

            Write-Verbose -Message ($script:localizedData.AddingResourceMessage -f
                $ClientRoleIdentifier, $ServerRoleIdentifier)

            try
            {
                Grant-AdfsApplicationPermission `
                    -ClientRoleIdentifier $ClientRoleIdentifier `
                    -ServerRoleIdentifier $ServerRoleIdentifier `
                    @parameters
            }
            catch
            {
                $errorMessage = ($script:localizedData.AddingResourceErrorMessage -f
                    $ClientRoleIdentifier, $ServerRoleIdentifier)
                New-InvalidOperationException -Message $errorMessage -Error $_
            }

        }
        else
        {
            # Resource should be Absent
            Write-Debug -Message ($script:localizedData.TargetResourceShouldBeAbsentDebugMessage -f
                $ClientRoleIdentifier, $ServerRoleIdentifier)

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

    # Set Verbose and Debug parameters
    $commonParms = @{
        Verbose = $VerbosePreference
        Debug   = $DebugPreference
    }

    Write-Verbose -Message ($script:localizedData.TestingResourceMessage -f
        $ClientRoleIdentifier, $ServerRoleIdentifier)

    $getTargetResourceParms = @{
        ClientRoleIdentifier = $ClientRoleIdentifier
        ServerRoleIdentifier = $ServerRoleIdentifier
    }
    $targetResource = Get-TargetResource @getTargetResourceParms

    if ($targetResource.Ensure -eq 'Present')
    {
        # Resource is Present
        Write-Debug -Message ($script:localizedData.TargetResourcePresentDebugMessage -f
            $ClientRoleIdentifier, $ServerRoleIdentifier)

        if ($Ensure -eq 'Present')
        {
            # Resource should be Present
            Write-Debug -Message ($script:localizedData.TargetResourceShouldBePresentDebugMessage -f
                $ClientRoleIdentifier, $ServerRoleIdentifier)

            $propertiesNotInDesiredState = (
                Compare-ResourcePropertyState -CurrentValues $targetResource -DesiredValues $PSBoundParameters `
                    @commonParms | Where-Object -Property InDesiredState -eq $false)

            if ($propertiesNotInDesiredState)
            {
                # Resource is not in desired state
                Write-Verbose -Message ($script:localizedData.ResourceNotInDesiredStateMessage -f
                    $ClientRoleIdentifier, $ServerRoleIdentifier)

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
            Write-Debug -Message ($script:localizedData.TargetResourceShouldBeAbsentDebugMessage -f
                $ClientRoleIdentifier, $ServerRoleIdentifier)

            Write-Verbose -Message ($script:localizedData.ResourceIsPresentButShouldBeAbsentMessage -f
                $targetResource.ClientRoleIdentifier, $targetResource.ServerRoleIdentifier)

            $inDesiredState = $false
        }
    }
    else
    {
        # Resource is Absent
        Write-Debug -Message ($script:localizedData.TargetResourceAbsentDebugMessage -f
            $ClientRoleIdentifier, $ServerRoleIdentifier)

        if ($Ensure -eq 'Present')
        {
            # Resource should be Present
            Write-Debug -Message ($script:localizedData.TargetResourceShouldBePresentDebugMessage -f
                $ClientRoleIdentifier, $ServerRoleIdentifier)

            Write-Verbose -Message ($script:localizedData.ResourceIsAbsentButShouldBePresentMessage -f
                $ClientRoleIdentifier, $ServerRoleIdentifier)

            $inDesiredState = $false
        }
        else
        {
            # Resource should be Absent
            Write-Debug -Message ($script:localizedData.TargetResourceShouldBeAbsentDebugMessage -f
                $ClientRoleIdentifier, $ServerRoleIdentifier)

            Write-Verbose -Message ($script:localizedData.ResourceInDesiredStateMessage -f
                $ClientRoleIdentifier, $ServerRoleIdentifier)

            $inDesiredState = $true
        }
    }

    $inDesiredState
}

Export-ModuleMember -Function *-TargetResource
