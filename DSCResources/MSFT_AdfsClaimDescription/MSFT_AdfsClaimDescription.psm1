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
        - Get-AdfsClaimDescription - https://docs.microsoft.com/en-us/powershell/module/adfs/get-adfsclaimdescription
    #>

    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $Name,

        [Parameter(Mandatory = $true)]
        [System.String]
        $ClaimType
    )

    # Check of the Resource PowerShell module is installed
    Assert-Module -ModuleName $script:psModuleName

    # Check if the ADFS Service is present and running
    Assert-AdfsService -Verbose

    Write-Verbose ($script:localizedData.GettingResourceMessage -f $Name)

    $targetResource = Get-AdfsClaimDescription -Name $Name

    if ($targetResource)
    {
        # Resource exists
        $returnValue = @{
            Name       = $targetResource.Name
            ClaimType  = $targetResource.ClaimType
            IsAccepted = $targetResource.IsAccepted
            IsOffered  = $targetResource.IsOffered
            IsRequired = $targetResource.IsRequired
            Notes      = $targetResource.Notes
            ShortName  = $targetResource.ShortName
            Ensure     = 'Present'
        }
    }
    else
    {
        # Resource does not exist
        $returnValue = @{
            Name       = $Name
            ClaimType  = $ClaimType
            IsAccepted = $false
            IsOffered  = $false
            IsRequired = $false
            Notes      = $null
            ShortName  = $null
            Ensure     = 'Absent'
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
        - Add-AdfsClaimDescription    - https://docs.microsoft.com/en-us/powershell/module/adfs/add-adfsclaimdescription
        - Set-AdfsClaimDescription    - https://docs.microsoft.com/en-us/powershell/module/adfs/set-adfsclaimdescription
        - Remove-AdfsClaimDescription - https://docs.microsoft.com/en-us/powershell/module/adfs/remove-adfsclaimdescription
    #>

    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $Name,

        [Parameter(Mandatory = $true)]
        [System.String]
        $ClaimType,

        [Parameter()]
        [System.Boolean]
        $IsAccepted,

        [Parameter()]
        [System.Boolean]
        $IsOffered,

        [Parameter()]
        [System.Boolean]
        $IsRequired,

        [Parameter()]
        [System.String]
        $Notes,

        [Parameter()]
        [System.String]
        $ShortName,

        [Parameter()]
        [ValidateSet("Present", "Absent")]
        [System.String]
        $Ensure = 'Present'
    )

    # Remove any parameters not used in Splats
    $parameters = $PSBoundParameters
    $parameters.Remove('Ensure')
    $parameters.Remove('Verbose')
    $parameters.Remove($Name)

    $GetTargetResourceParms = @{
        Name      = $Name
        ClaimType = $ClaimType
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

            $SetParameters = @{ }
            foreach ($property in $propertiesNotInDesiredState)
            {
                Write-Verbose -Message ($script:localizedData.SettingResourceMessage -f
                    $Name, $property.ParameterName, ($property.Expected -join ', '))
                $SetParameters.add($property.ParameterName, $property.Expected)
            }

            Set-AdfsClaimDescription -TargetName $Name @SetParameters
        }
        else
        {
            # Resource does not exist
            Write-Verbose -Message ($script:localizedData.AddingResourceMessage -f $Name)
            Add-AdfsClaimDescription @parameters
        }
    }
    else
    {
        # Resource should not exist
        if ($TargetResource.Ensure -eq 'Present')
        {
            # Resource exists
            Write-Verbose -Message ($script:localizedData.RemovingResourceMessage -f $Name)
            Remove-AdfsClaimDescription -TargetName $Name
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

        [Parameter(Mandatory = $true)]
        [System.String]
        $ClaimType,

        [Parameter()]
        [System.Boolean]
        $IsAccepted,

        [Parameter()]
        [System.Boolean]
        $IsOffered,

        [Parameter()]
        [System.Boolean]
        $IsRequired,

        [Parameter()]
        [System.String]
        $Notes,

        [Parameter()]
        [System.String]
        $ShortName,

        [Parameter()]
        [ValidateSet("Present", "Absent")]
        [System.String]
        $Ensure = 'Present'
    )

    $getTargetResourceParms = @{
        Name      = $Name
        ClaimType = $ClaimType
    }
    $targetResource = Get-TargetResource @getTargetResourceParms

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
                    Write-Verbose -Message (
                        $script:localizedData.ResourcePropertyNotInDesiredStateMessage -f
                        $targetResource.Name, $property.ParameterName, `
                            $property.Expected, $property.Actual)
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
