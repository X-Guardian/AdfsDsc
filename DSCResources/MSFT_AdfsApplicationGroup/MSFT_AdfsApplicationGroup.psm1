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

Set-StrictMode -Version Latest

$script:dscModuleName = 'AdfsDsc'
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
        - Get-AdfsApplicationGroup - https://docs.microsoft.com/en-us/powershell/module/adfs/get-adfsapplicationgroup
    #>

    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $Name
    )

    # Check of the ADFS PowerShell module is installed
    Assert-Module -ModuleName 'ADFS'

    # Check if the Get-AdfsApplicationGroup command is available
    Assert-Command -Module 'ADFS' -Command 'Get-AdfsApplicationGroup'

    # Check if the ADFS Service is present and running
    Assert-AdfsService -Verbose

    Write-Verbose ($script:localizedData.GettingResourceMessage -f $Name)

    $targetResource = Get-AdfsApplicationGroup -Name $Name

    if ($targetResource)
    {
        # Resource exists
        $returnValue = @{
            Name        = $targetResource.Name
            Description = $targetResource.Description
            Ensure      = 'Present'
        }
    }
    else
    {
        # Resource does not exist
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
        Used Resource PowerShell Cmdlets:
        - New-AdfsApplicationGroup    - https://docs.microsoft.com/en-us/powershell/module/adfs/new-adfsapplicationgroup
        - Set-AdfsApplicationGroup    - https://docs.microsoft.com/en-us/powershell/module/adfs/set-adfsapplicationgroup
        - Remove-AdfsApplicationGroup - https://docs.microsoft.com/en-us/powershell/module/adfs/remove-adfsapplicationgroup
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

    # Remove any parameters not used in Splats
    $parameters = $PSBoundParameters
    $parameters.Remove('Ensure')
    $parameters.Remove('Verbose')

    $GetTargetResourceParms = @{
        Name = $Name
    }
    $targetResource = Get-TargetResource @GetTargetResourceParms

    if ($Ensure -eq 'Present')
    {
        # Resource should exist
        if ($TargetResource.Ensure -eq 'Present')
        {
            # Resource exists
            $propertiesNotInDesiredState = (
                Compare-ResourcePropertyState -CurrentValues $targetResource -DesiredValues $parameters |
                    Where-Object -Property InDesiredState -eq $false)

            $SetParameters = New-Object -TypeName System.Collections.Hashtable
            foreach ($property in $propertiesNotInDesiredState)
            {
                Write-Verbose -Message ($script:localizedData.SettingResourceMessage -f
                    $Name, $property.ParameterName, ($property.Expected -join ', '))
                $SetParameters.add($property.ParameterName, $property.Expected)
            }

            Set-AdfsApplicationGroup -TargetName $Name @SetParameters
        }
        else
        {
            # Resource does not exist
            Write-Verbose -Message ($script:localizedData.AddingResourceMessage -f $Name)
            New-AdfsApplicationGroup @parameters
        }
    }
    else
    {
        # Resource should not exist
        if ($TargetResource.Ensure -eq 'Present')
        {
            # Resource exists
            Write-Verbose -Message ($script:localizedData.RemovingResourceMessage -f $Name)
            Remove-AdfsApplicationGroup -TargetName $Name
        }
        else
        {
            # Resource does not exist
            Write-Verbose -Message ($script:localizedData.ResourceInDesiredStateMessage -f $Name)
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
        $Name,

        [Parameter()]
        [System.String]
        $Description,

        [Parameter()]
        [ValidateSet("Present", "Absent")]
        [System.String]
        $Ensure = 'Present'
    )

    $targetResource = Get-TargetResource -Name $Name

    $inDesiredState = $true

    if ($targetResource.Ensure -eq 'Present')
    {
        # Resource exists
        if ($Ensure -eq 'Present')
        {
            # Resource should exist
            $propertiesNotInDesiredState = (
                Compare-ResourcePropertyState -CurrentValues $targetResource -DesiredValues $PSBoundParameters |
                    Where-Object -Property InDesiredState -eq $false)
            if ($propertiesNotInDesiredState)
            {
                # Resource is not in desired state
                foreach ($property in $propertiesNotInDesiredState)
                {
                    Write-Verbose -Message ($script:localizedData.ResourcePropertyNotInDesiredStateMessage -f
                        $targetResource.Name, $property.ParameterName)
                }
                $inDesiredState = $false
            }
            else
            {
                # Resource is in desired state
                Write-Verbose -Message ($script:localizedData.ResourceInDesiredStateMessage -f
                    $targetResource.Name)
                $inDesiredState = $true
            }
        }
        else
        {
            # Resource should not exist
            Write-Verbose -Message ($script:localizedData.ResourceExistsButShouldNotMessage -f
                $targetResource.Name)
            $inDesiredState = $false
        }
    }
    else
    {
        # Resource does not exist
        if ($Ensure -eq 'Present')
        {
            # Resource should exist
            Write-Verbose -Message ($script:localizedData.ResourceDoesNotExistButShouldMessage -f
                $targetResource.Name)
            $inDesiredState = $false
        }
        else
        {
            # Resource should not exist
            Write-Verbose ($script:localizedData.ResourceDoesNotExistAndShouldNotMessage -f
                $targetResource.Name)
            $inDesiredState = $true
        }
    }


    $inDesiredState
}

Export-ModuleMember -Function *-TargetResource
