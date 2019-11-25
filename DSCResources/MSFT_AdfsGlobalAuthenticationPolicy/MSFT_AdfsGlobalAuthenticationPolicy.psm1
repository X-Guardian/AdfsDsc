<#
    .SYNOPSIS
        DSC module for the ADFS Global Authentication Policy resource

    .DESCRIPTION
        The AdfsGlobalAuthenticationPolicy DSC resource manages the global authentication policy, which includes the
        providers currently allowed as additional providers in the AdditionalAuthenticationProvider property.

    .PARAMETER FederationServiceName
        Key - String
        Specifies the DNS name of the federation service.

    .PARAMETER AdditionalAuthenticationProvider
        Write - String
        Specifies an array of names of external authentication providers to add to the global policy.

    .PARAMETER AllowAdditionalAuthenticationAsPrimary
        Write - Boolean
        Specifying this parameter configures an external authentication provider for second stage authentication in the
        global policy.

    .PARAMETER ClientAuthenticationMethods
        Write - String
        Allowed values: ClientSecretPostAuthentication, ClientSecretBasicAuthentication,
                        PrivateKeyJWTBearerAuthentication, WindowsIntegratedAuthentication, None

        Specifying this parameter configures an external authentication provider, for second stage authentication, in
        the global policy

    .PARAMETER EnablePaginatedAuthenticationPages
        Write - Boolean
        Enable the paginated authentication sign-in experience. This is only supported on Windows Server 2019 and
        above.

    .PARAMETER DeviceAuthenticationEnabled
        Write - Boolean
        Specifies whether device authentication is enabled for the global policy.

    .PARAMETER DeviceAuthenticationMethod
        Write - String
        Allowed values: All, ClientTLS, SignedToken
        Specifying this parameter configures an external authentication provider, for second stage authentication, in
        the global policy.

    .PARAMETER PrimaryExtranetAuthenticationProvider
        Write - String
        Specifies an array of names of authentication providers for the primary extranet to add to the global policy.

    .PARAMETER PrimaryIntranetAuthenticationProvider
        Write - String
        Specifies an array of names of authentication providers for the primary intranet to add to the global policy.

    .PARAMETER WindowsIntegratedFallbackEnabled
        Write - Boolean
        Specifies whether fallback to Integrated Windows Authentication is enabled on the intranet.
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

        Name                               | Module
        -----------------------------------|----------------
        Get-AdfsGlobalAuthenticationPolicy | Adfs
        Assert-Module                      | AdfsDsc.Common
        Assert-AdfsService                 | AdfsDsc.Common
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

    # Check of the Resource PowerShell module is installed
    Assert-Module -ModuleName $script:psModuleName

    # Check if the ADFS Service is present and running
    Assert-AdfsService @commonParms

    try
    {
        $targetResource = Get-AdfsGlobalAuthenticationPolicy
    }
    catch
    {
        $errorMessage = $script:localizedData.GettingResourceErrorMessage -f $FederationServiceName
        New-InvalidOperationException -Message $errorMessage -Error $_
    }

    $returnValue = @{
        FederationServiceName                  = $FederationServiceName
        AdditionalAuthenticationProvider       = @($targetResource.AdditionalAuthenticationProvider)
        AllowAdditionalAuthenticationAsPrimary = $targetResource.AllowAdditionalAuthenticationAsPrimary
        ClientAuthenticationMethods            = $targetResource.ClientAuthenticationMethods -split (', ')
        EnablePaginatedAuthenticationPages     = $targetResource.EnablePaginatedAuthenticationPages
        DeviceAuthenticationEnabled            = $targetResource.DeviceAuthenticationEnabled
        DeviceAuthenticationMethod             = $targetResource.DeviceAuthenticationMethod
        PrimaryExtranetAuthenticationProvider  = @($targetResource.PrimaryExtranetAuthenticationProvider)
        PrimaryIntranetAuthenticationProvider  = @($targetResource.PrimaryIntranetAuthenticationProvider)
        WindowsIntegratedFallbackEnabled       = $targetResource.WindowsIntegratedFallbackEnabled
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

        Name                               | Module
        -----------------------------------|----------------
        Set-AdfsGlobalAuthenticationPolicy | Adfs
        Compare-ResourcePropertyState      | AdfsDsc.Common
    #>

    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $FederationServiceName,

        [Parameter()]
        [System.String[]]
        $AdditionalAuthenticationProvider,

        [Parameter()]
        [System.Boolean]
        $AllowAdditionalAuthenticationAsPrimary,

        [Parameter()]
        [ValidateSet('ClientSecretPostAuthentication',
            'ClientSecretBasicAuthentication',
            'PrivateKeyJWTBearerAuthentication',
            'WindowsIntegratedAuthentication',
            'None')]
        [System.String[]]
        $ClientAuthenticationMethods,

        [Parameter()]
        [System.Boolean]
        $EnablePaginatedAuthenticationPages,

        [Parameter()]
        [System.Boolean]
        $DeviceAuthenticationEnabled,

        [Parameter()]
        [ValidateSet('All', 'ClientTLS', 'SignedToken')]
        [System.String]
        $DeviceAuthenticationMethod,

        [Parameter()]
        [System.String[]]
        $PrimaryExtranetAuthenticationProvider,

        [Parameter()]
        [System.String[]]
        $PrimaryIntranetAuthenticationProvider,

        [Parameter()]
        [System.Boolean]
        $WindowsIntegratedFallbackEnabled
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

    $SetParameters = @{ }
    foreach ($property in $propertiesNotInDesiredState)
    {
        Write-Verbose -Message ($script:localizedData.SettingResourcePropertyMessage -f
            $FederationServiceName, $property.ParameterName, ($property.Expected -join ', '))

        $SetParameters.add($property.ParameterName, $property.Expected)
    }

    if ($setParameters.Count -gt 0)
    {
        try
        {
            Set-AdfsGlobalAuthenticationPolicy @setParameters
        }
        catch
        {
            $errorMessage = $script:localizedData.SettingResourceErrorMessage -f $FederationServiceName
            New-InvalidOperationException -Message $errorMessage -Error $_
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
        $FederationServiceName,

        [Parameter()]
        [System.String[]]
        $AdditionalAuthenticationProvider,

        [Parameter()]
        [System.Boolean]
        $AllowAdditionalAuthenticationAsPrimary,

        [Parameter()]
        [ValidateSet('ClientSecretPostAuthentication',
            'ClientSecretBasicAuthentication',
            'PrivateKeyJWTBearerAuthentication',
            'WindowsIntegratedAuthentication',
            'None')]
        [System.String[]]
        $ClientAuthenticationMethods,

        [Parameter()]
        [System.Boolean]
        $EnablePaginatedAuthenticationPages,

        [Parameter()]
        [System.Boolean]
        $DeviceAuthenticationEnabled,

        [Parameter()]
        [ValidateSet('All', 'ClientTLS', 'SignedToken')]
        [System.String]
        $DeviceAuthenticationMethod,

        [Parameter()]
        [System.String[]]
        $PrimaryExtranetAuthenticationProvider,

        [Parameter()]
        [System.String[]]
        $PrimaryIntranetAuthenticationProvider,

        [Parameter()]
        [System.Boolean]
        $WindowsIntegratedFallbackEnabled
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
