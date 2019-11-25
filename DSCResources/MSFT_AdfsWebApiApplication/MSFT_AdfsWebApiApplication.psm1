<#
    .SYNOPSIS
        DSC module for the Adfs Web API Application resource

    .DESCRIPTION
        The AdfsWebApiApplication DSC resource manages Web API Applications within Active Directory Federation
        Services. Web Api Applications are a construct that represents a web API secured by ADFS.

        ## Requirements

        * Target machine must be running ADFS on Windows Server 2016 or above to use this resource.

    .PARAMETER Name
        Key - String
        Specifies a name for the Web API application.

    .PARAMETER ApplicationGroupIdentifier
        Required - String
        Specifies the ID of an application group for the Web API application.

    .PARAMETER Identifier
        Required - String
        Specifies an identifier for the Web API application.

    .PARAMETER AccessControlPolicyName
        Write - String
        Specifies the name of an access control policy.

    .PARAMETER AccessControlPolicyParameters
        Write - MSFT_AccessControlPolicyParameters
        Specifies the parameters and their values to pass to the Access Control Policy.

    .PARAMETER AdditionalAuthenticationRules
        Write - String
        Specifies additional authentication rules.

    .PARAMETER AllowedAuthenticationClassReferences
        Write - String
        Specifies an array of allow authentication class references.

    .PARAMETER AllowedClientTypes
        Write - String
        Allowed values: None, Public, Confidential
        Specifies allowed client types.

    .PARAMETER AlwaysRequireAuthentication
        Write - Boolean
        Indicates that this Web API application role always requires authentication, even if it previously
        authenticated credentials for access. Specify this parameter to require users to always supply credentials to
        access sensitive resources.

    .PARAMETER ClaimsProviderName
        Write - String
        Specifies an array of claims provider names that you can configure for a relying party trust for Home Realm
        Discovery (HRD) scenario.

    .PARAMETER DelegationAuthorizationRules
        Write - String
        Specifies delegation authorization rules.

    .PARAMETER Description
        Write - String
        Specifies a description for the Web API application.

    .PARAMETER ImpersonationAuthorizationRules
        Write - String
        Specifies the impersonation authorization rules.

    .PARAMETER IssuanceAuthorizationRules
        Write - String
        Specifies the issuance authorization rules.

    .PARAMETER IssuanceTransformRules
        Write - String
        Specifies the issuance transform rules.

    .PARAMETER IssueOAuthRefreshTokensTo
        Write - String
        Allowed values: NoDevice, WorkplaceJoinedDevices, AllDevices
        Specifies the refresh token issuance device types.

    .PARAMETER NotBeforeSkew
        Write - Sint32
        Specifies the not before skew value.

    .PARAMETER RefreshTokenProtectionEnabled
        Write - Boolean
        Indicates whether refresh token protection is enabled.

    .PARAMETER RequestMFAFromClaimsProviders
        Write - Boolean
        Indicates that the request MFA from claims providers option is used.

    .PARAMETER TokenLifetime
        Write - Sint32
        Specifies the token lifetime.

    .PARAMETER Ensure
        Write - String
        Allowed values: Present, Absent
        Specifies whether the Web API application should be present or absent. Default value is 'Present'.
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

        Name                                     | Module
        -----------------------------------------|----------------
        Get-AdfsWebApiApplication                | Adfs
        Assert-Module                            | AdfsDsc.Common
        Assert-Command                           | AdfsDsc.Common
        Assert-AdfsService                       | AdfsDsc.Common
        ConvertFrom-IssuanceTransformRule        | AdfsDsc.Common
        ConvertFrom-AccessControlPolicyParameter | AdfsDsc.Common
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
        $ApplicationGroupIdentifier,

        [Parameter(Mandatory = $true)]
        [System.String[]]
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

    # Check if the Get-AdfsWebApiApplication command is available
    Assert-Command -Module $script:psModuleName -Command 'Get-AdfsWebApiApplication'

    # Check if the ADFS Service is present and running
    Assert-AdfsService @commonParms

    try
    {
        $targetResource = Get-AdfsWebApiApplication -Name $Name
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

        $AccessControlPolicyParameters = ConvertFrom-AccessControlPolicyParameter `
            -Policy $targetResource.AccessControlPolicyParameters @commonParms

        $IssuanceTransformRules = ConvertFrom-IssuanceTransformRule `
            -Rule $targetResource.IssuanceTransformRules @commonParms

        $returnValue = @{
            Name                                 = $targetResource.Name
            ApplicationGroupIdentifier           = $targetResource.ApplicationGroupIdentifier
            Identifier                           = @($targetResource.Identifier)
            AccessControlPolicyName              = $targetResource.AccessControlPolicyName
            AccessControlPolicyParameters        = $AccessControlPolicyParameters
            AdditionalAuthenticationRules        = $targetResource.AdditionalAuthenticationRules
            AlwaysRequireAuthentication          = $targetResource.AlwaysRequireAuthentication
            AllowedClientTypes                   = @($targetResource.AllowedClientTypes)
            AllowedAuthenticationClassReferences = @($targetResource.AllowedAuthenticationClassReferences)
            ClaimsProviderName                   = @($targetResource.ClaimsProviderName)
            DelegationAuthorizationRules         = $targetResource.DelegationAuthorizationRules
            Description                          = $targetResource.Description
            ImpersonationAuthorizationRules      = $targetResource.ImpersonationAuthorizationRules
            IssuanceAuthorizationRules           = $targetResource.IssuanceAuthorizationRules
            IssuanceTransformRules               = @($IssuanceTransformRules)
            IssueOAuthRefreshTokensTo            = $targetResource.IssueOAuthRefreshTokensTo
            NotBeforeSkew                        = $targetResource.NotBeforeSkew
            RefreshTokenProtectionEnabled        = $targetResource.RefreshTokenProtectionEnabled
            RequestMFAFromClaimsProviders        = $targetResource.RequestMFAFromClaimsProviders
            TokenLifetime                        = $targetResource.TokenLifetime
            Ensure                               = 'Present'
        }
    }
    else
    {
        # Resource is Absent
        Write-Debug -Message ($script:localizedData.TargetResourceAbsentDebugMessage -f $Name)

        $returnValue = @{
            Name                                 = $Name
            ApplicationGroupIdentifier           = $ApplicationGroupIdentifier
            Identifier                           = @($Identifier)
            AccessControlPolicyName              = $null
            AccessControlPolicyParameters        = $null
            AdditionalAuthenticationRules        = $null
            AllowedAuthenticationClassReferences = @()
            AllowedClientTypes                   = @('None')
            AlwaysRequireAuthentication          = $null
            ClaimsProviderName                   = @()
            DelegationAuthorizationRules         = $null
            Description                          = $null
            ImpersonationAuthorizationRules      = $null
            IssuanceAuthorizationRules           = $null
            IssuanceTransformRules               = $null
            IssueOAuthRefreshTokensTo            = 'NoDevice'
            NotBeforeSkew                        = 0
            RefreshTokenProtectionEnabled        = $false
            RequestMFAFromClaimsProviders        = $false
            TokenLifetime                        = 0
            Ensure                               = 'Absent'
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
        Add-AdfsWebApiApplication              | Adfs
        Remove-AdfsWebApiApplication           | Adfs
        Set-AdfsWebApiApplication              | Adfs
        Compare-IssuanceTransformRule          | AdfsDsc.Common
        Compare-AccessControlPolicyParameter   | AdfsDsc.Common
        Compare-ResourcePropertyState          | AdfsDsc.Common
        ConvertTo-IssuanceTransformRule        | AdfsDsc.Common
        ConvertTo-AccessControlPolicyParameter | AdfsDsc.Common
    #>

    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $Name,

        [Parameter(Mandatory = $true)]
        [System.String]
        $ApplicationGroupIdentifier,

        [Parameter(Mandatory = $true)]
        [System.String[]]
        $Identifier,

        [Parameter()]
        [System.String]
        $AccessControlPolicyName,

        [Parameter()]
        [Microsoft.Management.Infrastructure.CimInstance]
        $AccessControlPolicyParameters,

        [Parameter()]
        [System.String]
        $AdditionalAuthenticationRules,

        [Parameter()]
        [System.String[]]
        $AllowedAuthenticationClassReferences,

        [Parameter()]
        [ValidateSet('None', 'Public', 'Confidential')]
        [System.String[]]
        $AllowedClientTypes,

        [Parameter()]
        [System.Boolean]
        $AlwaysRequireAuthentication,

        [Parameter()]
        [System.String[]]
        $ClaimsProviderName,

        [Parameter()]
        [System.String]
        $DelegationAuthorizationRules,

        [Parameter()]
        [System.String]
        $Description,

        [Parameter()]
        [System.String]
        $ImpersonationAuthorizationRules,

        [Parameter()]
        [System.String]
        $IssuanceAuthorizationRules,

        [Parameter()]
        [Microsoft.Management.Infrastructure.CimInstance[]]
        $IssuanceTransformRules,

        [Parameter()]
        [ValidateSet('NoDevice', 'WorkplaceJoinedDevices', 'AllDevices')]
        [System.String]
        $IssueOAuthRefreshTokensTo,

        [Parameter()]
        [System.Int32]
        $NotBeforeSkew,

        [Parameter()]
        [System.Boolean]
        $RefreshTokenProtectionEnabled,

        [Parameter()]
        [System.Boolean]
        $RequestMFAFromClaimsProviders,

        [Parameter()]
        [System.Int32]
        $TokenLifetime,

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
    [HashTable]$parameters = $PSBoundParameters
    $parameters.Remove('Ensure')
    $parameters.Remove('Verbose')

    Write-Verbose -Message ($script:localizedData.SettingResourceMessage -f $Name)

    $GetTargetResourceParms = @{
        ApplicationGroupIdentifier = $ApplicationGroupIdentifier
        Name                       = $Name
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

            $propertiesNotInDesiredState = @()

            if ($PSBoundParameters.Keys.Contains('IssuanceTransformRules'))
            {
                $propertiesNotInDesiredState += (
                    Compare-IssuanceTransformRule -CurrentValue $targetResource.IssuanceTransformRules `
                        -DesiredValue $IssuanceTransformRules -ParameterName 'IssuanceTransformRules' `
                        @commonParms | Where-Object -Property InDesiredState -eq $false)
            }

            if ($PSBoundParameters.Keys.Contains('AccessControlPolicyParameters'))
            {
                $propertiesNotInDesiredState += (
                    Compare-AccessControlPolicyParameter -CurrentValue $targetResource.AccessControlPolicyParameters `
                        -DesiredValue $AccessControlPolicyParameters -ParameterName 'AccessControlPolicyParameters' `
                        @commonParms | Where-Object -Property InDesiredState -eq $false)
            }

            $propertiesNotInDesiredState += (
                Compare-ResourcePropertyState -CurrentValues $targetResource -DesiredValues $parameters `
                    -IgnoreProperties 'IssuanceTransformRules', 'AccessControlPolicyParameters' `
                    @commonParms | Where-Object -Property InDesiredState -eq $false)

            if ($propertiesNotInDesiredState |
                Where-Object -Property ParameterName -eq 'ApplicationGroupIdentifier')
            {
                Write-Verbose -Message ($script:localizedData.RemovingResourceMessage -f
                    $Name, $targetResource.ApplicationGroupIdentifier)

                try
                {
                    Remove-AdfsWebApiApplication -TargetName $Name
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
                    Add-AdfsWebApiApplication @parameters -Verbose:$false
                }
                catch
                {
                    $errorMessage = $script:localizedData.AddingResourceErrorMessage -f $Name
                    New-InvalidOperationException -Message $errorMessage -Error $_
                }

                break
            }

            $setParameters = @{ }
            foreach ($property in $propertiesNotInDesiredState)
            {
                Write-Verbose -Message ($script:localizedData.SettingResourcePropertyMessage -f
                    $Name, $property.ParameterName, ($property.Expected -join ', '))

                if ($property.ParameterName -eq 'IssuanceTransformRules')
                {
                    # Custom processing for 'IssuanceTransformRules' property
                    $setParameters.Add($property.ParameterName, ($IssuanceTransformRules |
                            ConvertTo-IssuanceTransformRule @commonParms))
                }
                elseif ($property.ParameterName -eq 'AccessControlPolicyParameters')
                {
                    # Custom processing for 'AccessControlPolicyParameters' property
                    $setParameters.Add($property.ParameterName, ($AccessControlPolicyParameters |
                            ConvertTo-AccessControlPolicyParameter @commonParms))
                }
                else
                {
                    $setParameters.add($property.ParameterName, $property.Expected)
                }
            }

            try
            {
                Set-AdfsWebApiApplication -TargetName $Name @setParameters
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
                Remove-AdfsWebApiApplication -TargetName $Name
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

            if ($parameters.ContainsKey('IssuanceTransformRules'))
            {
                # Custom processing for 'IssuanceTransformRules' property
                $parameters.IssuanceTransformRules = ($parameters.IssuanceTransformRules |
                    ConvertTo-IssuanceTransformRule @commonParms)
            }

            if ($parameters.ContainsKey('AccessControlPolicyParameters'))
            {
                # Custom processing for 'AccessControlPolicyParameters' property
                $parameters.AccessControlPolicyParameters = ($parameters.AccessControlPolicyParameters |
                    ConvertTo-AccessControlPolicyParameter @commonParms)
            }

            Write-Verbose -Message ($script:localizedData.AddingResourceMessage -f
                $Name, $ApplicationGroupIdentifier)

            try
            {
                Add-AdfsWebApiApplication @parameters -Verbose:$false
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

        Name                                 | Module
        -------------------------------------|------------------
        Compare-IssuanceTransformRule        | AdfsDsc.Common
        Compare-AccessControlPolicyParameter | AdfsDsc.Common
        Compare-ResourcePropertyState        | AdfsDsc.Common
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
        $ApplicationGroupIdentifier,

        [Parameter(Mandatory = $true)]
        [System.String[]]
        $Identifier,

        [Parameter()]
        [System.String]
        $AccessControlPolicyName,

        [Parameter()]
        [Microsoft.Management.Infrastructure.CimInstance]
        $AccessControlPolicyParameters,

        [Parameter()]
        [System.String]
        $AdditionalAuthenticationRules,

        [Parameter()]
        [System.String[]]
        $AllowedAuthenticationClassReferences,

        [Parameter()]
        [ValidateSet('None', 'Public', 'Confidential')]
        [System.String[]]
        $AllowedClientTypes,

        [Parameter()]
        [System.Boolean]
        $AlwaysRequireAuthentication,

        [Parameter()]
        [System.String[]]
        $ClaimsProviderName,

        [Parameter()]
        [System.String]
        $DelegationAuthorizationRules,

        [Parameter()]
        [System.String]
        $Description,

        [Parameter()]
        [System.String]
        $ImpersonationAuthorizationRules,

        [Parameter()]
        [System.String]
        $IssuanceAuthorizationRules,

        [Parameter()]
        [Microsoft.Management.Infrastructure.CimInstance[]]
        $IssuanceTransformRules,

        [Parameter()]
        [ValidateSet('NoDevice', 'WorkplaceJoinedDevices', 'AllDevices')]
        [System.String]
        $IssueOAuthRefreshTokensTo,

        [Parameter()]
        [System.Int32]
        $NotBeforeSkew,

        [Parameter()]
        [System.Boolean]
        $RefreshTokenProtectionEnabled,

        [Parameter()]
        [System.Boolean]
        $RequestMFAFromClaimsProviders,

        [Parameter()]
        [System.Int32]
        $TokenLifetime,

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

            $propertiesNotInDesiredState = @()

            if ($PSBoundParameters.Keys.Contains('IssuanceTransformRules'))
            {
                $propertiesNotInDesiredState += (
                    Compare-IssuanceTransformRule -CurrentValue $targetResource.IssuanceTransformRules `
                        -DesiredValue $IssuanceTransformRules -ParameterName 'IssuanceTransformRules' `
                        @commonParms | Where-Object -Property InDesiredState -eq $false)
            }

            if ($PSBoundParameters.Keys.Contains('AccessControlPolicyParameters'))
            {
                $propertiesNotInDesiredState += (
                    Compare-AccessControlPolicyParameter -CurrentValue $targetResource.AccessControlPolicyParameters `
                        -DesiredValue $AccessControlPolicyParameters -ParameterName 'AccessControlPolicyParameters' `
                        @commonParms | Where-Object -Property InDesiredState -eq $false)
            }

            $propertiesNotInDesiredState += (
                Compare-ResourcePropertyState -CurrentValues $targetResource -DesiredValues $PSBoundParameters `
                    -IgnoreProperties 'IssuanceTransformRules', 'AccessControlPolicyParameters' `
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

            Write-Verbose -Message ($script:localizedData.ResourceInDesiredStateMessage -f $Name)

            $inDesiredState = $true
        }
    }

    $inDesiredState
}

Export-ModuleMember -Function *-TargetResource
