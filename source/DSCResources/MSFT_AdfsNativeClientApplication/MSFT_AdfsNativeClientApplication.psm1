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

        Name                            | Module
        --------------------------------|----------------
        Get-AdfsNativeClientApplication | Adfs
        Assert-Module                   | AdfsDsc.Common
        Assert-Command                  | AdfsDsc.Common
        Assert-AdfsService              | AdfsDsc.Common
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

    # Set Verbose and Debug parameters
    $commonParms = @{
        Verbose = $VerbosePreference
        Debug   = $DebugPreference
    }

    Write-Verbose -Message ($script:localizedData.GettingResourceMessage -f $Name)

    # Check of the Resource PowerShell module is installed
    Assert-Module -ModuleName $script:psModuleName

    # Check if the Get-AdfsNativeClientApplication command is available
    Assert-Command -Module $script:psModuleName -Command 'Get-AdfsNativeClientApplication'

    # Check if the ADFS Service is present and running
    Assert-AdfsService @commonParms

    try
    {
        $targetResource = Get-AdfsNativeClientApplication -Name $Name
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
        # Resource is Absent
        Write-Debug -Message ($script:localizedData.TargetResourceAbsentDebugMessage -f $Name)

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
        Used Cmdlets/Functions:

        Name                                   | Module
        ---------------------------------------|----------------
        Add-AdfsNativeClientApplication        | Adfs
        Remove-AdfsNativeClientApplication     | Adfs
        Set-AdfsNativeClientApplication        | Adfs
        Compare-ResourcePropertyState          | AdfsDsc.Common
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

    # Set Verbose and Debug parameters
    $commonParms = @{
        Verbose = $VerbosePreference
        Debug   = $DebugPreference
    }

    # Remove any parameters not used in Splats
    [HashTable]$parameters = $PSBoundParameters
    $parameters.Remove('Ensure')
    $parameters.Remove('Verbose')

    Write-Verbose -Message ($script:localizedData.SettingResourceMessage -f $Name)

    $GetTargetResourceParms = @{
        Name                       = $Name
        ApplicationGroupIdentifier = $ApplicationGroupIdentifier
        Identifier                 = $Identifier
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

            if ($propertiesNotInDesiredState |
                Where-Object -Property ParameterName -eq 'ApplicationGroupIdentifier')
            {
                Write-Verbose -Message ($script:localizedData.RemovingResourceMessage -f
                    $Name, $targetResource.ApplicationGroupIdentifier)

                try
                {
                    Remove-AdfsNativeClientApplication -TargetName $Name
                }
                catch
                {
                    $errorMessage = $script:localizedData.RemovingResourceErrorMessage -f $Name
                    New-InvalidOperationException -Message $errorMessage -Error $_
                }

                Write-Verbose -Message ($script:localizedData.AddingResourceMessage -f
                    $Name, $ApplicationGroupIdentifier)

                try
                {
                    Add-AdfsNativeClientApplication @parameters -Verbose:$false
                }
                catch
                {
                    $errorMessage = $script:localizedData.AddingResourceErrorMessage -f $Name
                    New-InvalidOperationException -Message $errorMessage -Error $_
                }

                break
            }

            $SetParameters = @{ }
            foreach ($property in $propertiesNotInDesiredState)
            {
                Write-Verbose -Message ($script:localizedData.SettingResourcePropertyMessage -f
                    $Name, $property.ParameterName, ($property.Expected -join ', '))

                $SetParameters.add($property.ParameterName, $property.Expected)
            }

            try
            {
                Set-AdfsNativeClientApplication -TargetName $Name @SetParameters
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

            Write-Verbose -Message ($script:localizedData.RemovingResourceMessage -f
                $Name, $ApplicationGroupIdentifier)

            try
            {
                Remove-AdfsNativeClientApplication -TargetName $Name
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

            Write-Verbose -Message ($script:localizedData.AddingResourceMessage -f
                $Name, $ApplicationGroupIdentifier)

            try
            {
                Add-AdfsNativeClientApplication @parameters -Verbose:$false
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

    # Set Verbose and Debug parameters
    $commonParms = @{
        Verbose = $VerbosePreference
        Debug   = $DebugPreference
    }

    Write-Verbose -Message ($script:localizedData.TestingResourceMessage -f $Name)

    $getTargetResourceParms = @{
        Name                       = $Name
        ApplicationGroupIdentifier = $ApplicationGroupIdentifier
        Identifier                 = $Identifier
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

            Write-Verbose -Message ($script:localizedData.ResourceIsPresentButShouldBeAbsentMessage -f
                $targetResource.Name)

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

            Write-Verbose -Message ($script:localizedData.ResourceIsAbsentButShouldBePresentMessage -f
                $targetResource.Name)

            $inDesiredState = $false
        }
        else
        {
            # Resource should be Absent
            Write-Debug -Message ($script:localizedData.TargetResourceShouldBeAbsentDebugMessage -f $Name)

            Write-Verbose ($script:localizedData.ResourceInDesiredStateMessage -f
                $targetResource.Name)

            $inDesiredState = $true
        }
    }

    $inDesiredState
}

Export-ModuleMember -Function *-TargetResource
