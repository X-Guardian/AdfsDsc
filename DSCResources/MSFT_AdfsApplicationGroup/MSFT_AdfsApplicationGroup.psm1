<#
    .SYNOPSIS
        DSC module for the ADFS Application Group resource

    .DESCRIPTION
        The AdfsApplicationGroup DSC resource manages Application Groups within Active Directory Federation Services.
        These are a construct that combine trust and authorization elements into one resource.

        The `AdfsNativeClientApplication` and `AdfsWebApiApplication` resources manage applications within an
        application group.

        ## Requirements

        * Target machine must be running ADFS on Windows Server 2016 or above to use this resource.

    .PARAMETER Name
        Key - String
        Specifies a name for the application group.

    .PARAMETER Description
        Write - String
        Specifies a description for the application group.

    .PARAMETER Ensure
        Write - String
        Allowed values: Present, Absent
        Specifies whether the Application Group should be present or absent. Default value is 'Present'.
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
        Get-AdfsApplicationGroup | Adfs
        Assert-Module            | AdfsDsc.Common
        Assert-Command           | AdfsDsc.Common
        Assert-AdfsService       | AdfsDsc.Common
    #>

    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $Name
    )

    # Set Verbose and Debug parameters
    $commonParms = @{
        Verbose = $VerbosePreference
        Debug   = $DebugPreference
    }

    Write-Verbose -Message ($script:localizedData.GettingResourceMessage -f $Name)

    # Check of the Resource PowerShell module is installed
    Assert-Module -ModuleName $script:psModuleName

    # Check if the Get-AdfsApplicationGroup command is available
    Assert-Command -Module $script:psModuleName -Command 'Get-AdfsApplicationGroup'

    # Check if the ADFS Service is present and running
    Assert-AdfsService @commonParms

    try
    {
        $targetResource = Get-AdfsApplicationGroup -Name $Name
    }
    catch
    {
        $errorMessage = $script:localizedData.GettingResourceErrorMessage -f $Name
        New-InvalidOperationException -Message $errorMessage -Error $_
    }

    if ($targetResource)
    {
        # Resource is Present
        Write-Debug -Message ($script:localizedData.TargetResourcePresentDebugMessage -f $Name)

        $returnValue = @{
            Name        = $targetResource.Name
            Description = $targetResource.Description
            Ensure      = 'Present'
        }
    }
    else
    {
        # Resource is Absent
        Write-Debug -Message ($script:localizedData.TargetResourceAbsentDebugMessage -f $Name)

        $returnValue = @{
            Name        = $Name
            Description = $null
            Ensure      = 'Absent'
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

        Name                          | Module
        ------------------------------|----------------
        New-AdfsApplicationGroup      | AdfsDsc
        Set-AdfsApplicationGroup      | AdfsDsc
        Remove-AdfsApplicationGroup   | AdfsDsc
        Compare-ResourcePropertyState | AdfsDsc.Common
    #>

    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $Name,

        [Parameter()]
        [System.String]
        $Description,

        [Parameter()]
        [ValidateSet("Present", "Absent")]
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

    Write-Verbose -Message ($script:localizedData.SettingResourceMessage -f $Name)

    $GetTargetResourceParms = @{
        Name = $Name
    }
    $targetResource = Get-TargetResource @GetTargetResourceParms

    if ($targetResource.Ensure -eq 'Present')
    {
        # Resource is Present
        Write-Debug -Message ($script:localizedData.TargetResourcePresentDebugMessage -f $Name)

        if ($Ensure -eq 'Present')
        {
            # Resource should be Present
            Write-Debug -Message ($script:localizedData.TargetResourceShouldBePresentDebugMessage -f $Name)

            $propertiesNotInDesiredState = (
                Compare-ResourcePropertyState -CurrentValues $targetResource -DesiredValues $parameters `
                    @commonParms | Where-Object -Property InDesiredState -eq $false)

            $SetParameters = @{ }
            foreach ($property in $propertiesNotInDesiredState)
            {
                Write-Verbose -Message ($script:localizedData.SettingResourcePropertyMessage -f
                    $Name, $property.ParameterName, ($property.Expected -join ', '))

                $SetParameters.add($property.ParameterName, $property.Expected)
            }

            try
            {
                Set-AdfsApplicationGroup -TargetName $Name @SetParameters
            }
            catch
            {
                $errorMessage = $script:localizedData.SettingResourceErrorMessage -f $Name
                New-InvalidOperationException -Message $errorMessage -Error $_
            }
        }
        else
        {
            # Resource should be Absent
            Write-Debug -Message ($script:localizedData.TargetResourceShouldBeAbsentDebugMessage -f $Name)

            Write-Verbose -Message ($script:localizedData.RemovingResourceMessage -f $Name)

            try
            {
                Remove-AdfsApplicationGroup -TargetName $Name
            }
            catch
            {
                $errorMessage = $script:localizedData.RemovingResourceErrorMessage -f $Name
                New-InvalidOperationException -Message $errorMessage -Error $_
            }
        }
    }
    else
    {
        # Resource is Absent
        Write-Debug -Message ($script:localizedData.TargetResourceAbsentDebugMessage -f $Name)

        if ($Ensure -eq 'Present')
        {
            # Resource should be Present
            Write-Debug -Message ($script:localizedData.TargetResourceShouldBePresentDebugMessage -f $Name)

            Write-Verbose -Message ($script:localizedData.AddingResourceMessage -f $Name)

            try
            {
                New-AdfsApplicationGroup @parameters
            }
            catch
            {
                $errorMessage = $script:localizedData.AddingResourceErrorMessage -f $Name
                New-InvalidOperationException -Message $errorMessage -Error $_
            }
        }
        else
        {
            # Resource should be Absent
            Write-Debug -Message ($script:localizedData.TargetResourceShouldBeAbsentDebugMessage -f $Name)

            Write-Verbose -Message ($script:localizedData.ResourceInDesiredStateMessage -f $Name)
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
        $Name,

        [Parameter()]
        [System.String]
        $Description,

        [Parameter()]
        [ValidateSet("Present", "Absent")]
        [System.String]
        $Ensure = 'Present'
    )

    # Set Verbose and Debug parameters
    $commonParms = @{
        Verbose = $VerbosePreference
        Debug   = $DebugPreference
    }

    Write-Verbose -Message ($script:localizedData.TestingResourceMessage -f $Name)

    $getTargetResourceParms = @{
        Name = $Name
    }
    $targetResource = Get-TargetResource @getTargetResourceParms

    if ($targetResource.Ensure -eq 'Present')
    {
        # Resource is Present
        Write-Debug -Message ($script:localizedData.TargetResourcePresentDebugMessage -f $Name)

        if ($Ensure -eq 'Present')
        {
            # Resource should be Present
            Write-Debug -Message ($script:localizedData.TargetResourceShouldBePresentDebugMessage -f $Name)

            $propertiesNotInDesiredState = (
                Compare-ResourcePropertyState -CurrentValues $targetResource -DesiredValues $PSBoundParameters `
                    @commonParms | Where-Object -Property InDesiredState -eq $false)

            if ($propertiesNotInDesiredState)
            {
                # Resource is not in desired state
                Write-Verbose -Message ($script:localizedData.ResourceNotInDesiredStateMessage -f $Name)

                $inDesiredState = $false
            }
            else
            {
                # Resource is in desired state
                Write-Verbose -Message ($script:localizedData.ResourceInDesiredStateMessage -f $Name)

                $inDesiredState = $true
            }
        }
        else
        {
            # Resource should be Absent
            Write-Debug -Message ($script:localizedData.TargetResourceShouldBeAbsentDebugMessage -f $Name)

            Write-Verbose -Message ($script:localizedData.ResourceIsPresentButShouldBeAbsentMessage -f $Name)

            $inDesiredState = $false
        }
    }
    else
    {
        # Resource is Absent
        Write-Debug -Message ($script:localizedData.TargetResourceAbsentDebugMessage -f $Name)

        if ($Ensure -eq 'Present')
        {
            # Resource should be Present
            Write-Debug -Message ($script:localizedData.TargetResourceShouldBePresentDebugMessage -f $Name)

            Write-Verbose -Message ($script:localizedData.ResourceIsAbsentButShouldBePresentMessage -f $Name)

            $inDesiredState = $false
        }
        else
        {
            # Resource should be Absent
            Write-Debug -Message ($script:localizedData.TargetResourceShouldBeAbsentDebugMessage -f $Name)

            Write-Verbose ($script:localizedData.ResourceInDesiredStateMessage -f $Name)

            $inDesiredState = $true
        }
    }

    $inDesiredState
}

Export-ModuleMember -Function *-TargetResource
