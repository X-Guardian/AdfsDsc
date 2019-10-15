<#
    .SYNOPSIS
        DSC module for the ADFS Native Client Application resource

    .DESCRIPTION
        The AdfsNativeClientApplication DSC resource manages Native Client Applications within Active Directory
        Federation Services. Native Client Applications are a construct that represents a native application that runs
        on a phone, tablet or PC and needs to authenticate a user with ADFS.

        ## Requirements

        * Target machine must be running ADFS on Windows Server 2016 or above to use this resource.

    .PARAMETER Name
        Key - String
        Specifies the name for the native client application.

    .PARAMETER Identifier
        Required - String
        Specifies the identifier for the native client application.

    .PARAMETER ApplicationGroupIdentifier
        Required - String
        Specifies the ID of an application group.

    .PARAMETER RedirectUri
        Write - String
        Specifies an array of redirection URIs for the OAuth 2.0 client to register with AD FS. The redirection URI is
        specified by the OAuth 2.0 client when it requests authorization to access a resource in ADFS.

    .PARAMETER Description
        Write - String
        Specifies a description for the native client application.

    .PARAMETER LogoutUri
        Write - String
        Specifies the logout URI for the OAuth 2.0 client to register with the AD FS. When AD FS initiates a logout it
        redirects the client's user-agent to this URI by rendering this URI in an iframe. The value of this parameter
        must be an absolute URI, may include a query component, and must not include a fragment component.

    .PARAMETER Ensure
        Write - String
        Allowed values: Present, Absent
        Specifies whether the ADFS native client application should be present or absent. Default value is 'Present'.
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
        - Get-AdfsNativeClientApplication - https://docs.microsoft.com/en-us/powershell/module/adfs/get-adfsnativeclientapplication
    #>

    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $ApplicationGroupIdentifier,

        [Parameter(Mandatory = $true)]
        [System.String]
        $Name,

        [Parameter(Mandatory = $true)]
        [System.String]
        $Identifier
    )

    # Check of the ADFS PowerShell module is installed
    Assert-Module -ModuleName 'ADFS'

    # Check if the Get-AdfsNativeClientApplication command is available
    Assert-Command -Module 'ADFS' -Command 'Get-AdfsNativeClientApplication'

    # Check if the ADFS Service is present and running
    Assert-AdfsService -Verbose

    Write-Verbose -Message ($script:localizedData.GettingResourceMessage -f $Name)

    $targetResource = Get-AdfsNativeClientApplication -Name $Name

    if ($targetResource)
    {
        # Resource exists
        $returnValue = @{
            ApplicationGroupIdentifier = $targetResource.ApplicationGroupIdentifier
            Name                       = $targetResource.Name
            Identifier                 = $targetResource.Identifier
            RedirectUri                = $targetResource.RedirectUri
            Description                = $targetResource.Description
            LogoutUri                  = $targetResource.LogoutUri
            Ensure                     = 'Present'
        }
    }
    else
    {
        # Resource does not exist
        $returnValue = @{
            ApplicationGroupIdentifier = $ApplicationGroupIdentifier
            Name                       = $Name
            Identifier                 = $Identifier
            RedirectUri                = @()
            Description                = $null
            LogoutUri                  = $null
            Ensure                     = 'Absent'

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
        - Add-AdfsNativeClientApplication    - https://docs.microsoft.com/en-us/powershell/module/adfs/add-adfsnativeclientapplication
        - Remove-AdfsNativeClientApplication - https://docs.microsoft.com/en-us/powershell/module/adfs/remove-adfsnativeclientapplication
        - Set-AdfsNativeClientApplication    - https://docs.microsoft.com/en-us/powershell/module/adfs/set-adfsnativeclientapplication
    #>

    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $ApplicationGroupIdentifier,

        [Parameter(Mandatory = $true)]
        [System.String]
        $Name,

        [Parameter(Mandatory = $true)]
        [System.String]
        $Identifier,

        [Parameter()]
        [System.String[]]
        $RedirectUri,

        [Parameter()]
        [System.String]
        $Description,

        [Parameter()]
        [System.String]
        $LogoutUri,

        [Parameter()]
        [ValidateSet("Present", "Absent")]
        [System.String]
        $Ensure = 'Present'
    )

    # Remove any parameters not used in Splats
    [HashTable]$parameters = $PSBoundParameters
    $parameters.Remove('Ensure')
    $parameters.Remove('Verbose')

    $GetTargetResourceParms = @{
        Name                       = $Name
        ApplicationGroupIdentifier = $ApplicationGroupIdentifier
        Identifier                 = $Identifier
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

            if ($propertiesNotInDesiredState |
                    Where-Object -Property ParameterName -eq 'ApplicationGroupIdentifier')
            {
                Write-Verbose -Message ($script:localizedData.RemovingResourceMessage -f
                    $Name, $targetResource.ApplicationGroupIdentifier)
                Remove-AdfsNativeClientApplication -TargetName $Name
                Write-Verbose -Message ($script:localizedData.AddingResourceMessage -f
                    $Name, $ApplicationGroupIdentifier)
                Add-AdfsNativeClientApplication @parameters -Verbose:$false
                break
            }

            $SetParameters = New-Object -TypeName System.Collections.Hashtable
            foreach ($property in $propertiesNotInDesiredState)
            {
                Write-Verbose -Message ($script:localizedData.SettingResourceMessage -f
                    $Name, $property.ParameterName, ($property.Expected -join ', '))
                $SetParameters.add($property.ParameterName, $property.Expected)
            }
            Set-AdfsNativeClientApplication -TargetName $Name @SetParameters
        }
        else
        {
            # Resource does not exist
            Write-Verbose -Message ($script:localizedData.AddingResourceMessage -f
                $Name, $ApplicationGroupIdentifier)
            Add-AdfsNativeClientApplication @parameters -Verbose:$false
        }
    }
    else
    {
        # Resource should not exist
        if ($TargetResource.Ensure -eq 'Present')
        {
            # Resource exists
            Write-Verbose -Message ($script:localizedData.RemovingResourceMessage -f
                $Name, $ApplicationGroupIdentifier)
            Remove-AdfsNativeClientApplication -TargetName $Name
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
        $ApplicationGroupIdentifier,

        [Parameter(Mandatory = $true)]
        [System.String]
        $Name,

        [Parameter(Mandatory = $true)]
        [System.String]
        $Identifier,

        [Parameter()]
        [System.String[]]
        $RedirectUri,

        [Parameter()]
        [System.String]
        $Description,

        [Parameter()]
        [System.String]
        $LogoutUri,

        [Parameter()]
        [ValidateSet("Present", "Absent")]
        [System.String]
        $Ensure = 'Present'
    )

    [HashTable]$parameters = $PSBoundParameters
    $parameters.Remove('Ensure')

    $GetTargetResourceParms = @{
        Name                       = $Name
        ApplicationGroupIdentifier = $ApplicationGroupIdentifier
        Identifier                 = $Identifier
    }
    $targetResource = Get-TargetResource @GetTargetResourceParms

    if ($targetResource.Ensure -eq 'Present')
    {
        # Resource exists
        if ($Ensure -eq 'Present')
        {
            # Resource should exist
            $propertiesNotInDesiredState = (
                Compare-ResourcePropertyState -CurrentValues $targetResource -DesiredValues $parameters |
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
