<#
    .SYNOPSIS
        DSC module for the Web API Application resource

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

    .PARAMETER Description
        Write - String
        Specifies a description for the Web API application.

    .PARAMETER Ensure
        Write - String
        Allowed values: Present, Absent
        Specifies whether the Web API application should be present or absent. Default value is 'Present'.

    .PARAMETER AllowedAuthenticationClassReferences
        Write - String
        Specifies an array of allow authentication class references.

    .PARAMETER ClaimsProviderName
        Write - String
        Specifies an array of claims provider names that you can configure for a relying party trust for Home Realm
        Discovery (HRD) scenario.

    .PARAMETER IssuanceAuthorizationRules
        Write - String
        Specifies the issuance authorization rules.

    .PARAMETER DelegationAuthorizationRules
        Write - String
        Specifies delegation authorization rules.

    .PARAMETER ImpersonationAuthorizationRules
        Write - String
        Specifies the impersonation authorization rules.

    .PARAMETER IssuanceTransformRules
        Write - String
        Specifies the issuance transform rules.

    .PARAMETER AdditionalAuthenticationRules
        Write - String
        Specifies additional authentication rules.

    .PARAMETER AccessControlPolicyName
        Write - String
        Specifies the name of an access control policy.

    .PARAMETER NotBeforeSkew
        Write - Sint32
        Specifies the not before skew value.

    .PARAMETER TokenLifetime
        Write - Sint32
        Specifies the token lifetime.

    .PARAMETER AlwaysRequireAuthentication
        Write - Boolean
        Indicates that this Web API application role always requires authentication, even if it previously
        authenticated credentials for access. Specify this parameter to require users to always supply credentials to
        access sensitive resources.

    .PARAMETER AllowedClientTypes
        Write - String
        Allowed values: None, Public, Confidential
        Specifies allowed client types.

    .PARAMETER IssueOAuthRefreshTokensTo
        Write - String
        Allowed values: NoDevice, WorkplaceJoinedDevices, AllDevices
        Specifies the refresh token issuance device types.

    .PARAMETER RefreshTokenProtectionEnabled
        Write - Boolean
        Indicates whether refresh token protection is enabled.

    .PARAMETER RequestMFAFromClaimsProviders
        Write - Boolean
        Indicates that the request MFA from claims providers option is used.
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
        - Get-AdfsWebApiApplication - https://docs.microsoft.com/en-us/powershell/module/adfs/get-adfswebApiapplication
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

    # Check of the Resource PowerShell module is installed
    Assert-Module -ModuleName $script:psModuleName

    # Check if the Get-AdfsWebApiApplication command is available
    Assert-Command -Module $script:psModuleName -Command 'Get-AdfsWebApiApplication'

    # Check if the ADFS Service is present and running
    Assert-AdfsService -Verbose

    Write-Verbose -Message ($script:localizedData.GettingResourceMessage -f $Name)

    $targetResource = Get-AdfsWebApiApplication -Name $Name

    if ($targetResource)
    {
        # Resource exists
        $returnValue = @{
            Name                                 = $targetResource.Name
            ApplicationGroupIdentifier           = $targetResource.ApplicationGroupIdentifier
            Identifier                           = $targetResource.Identifier
            Description                          = $targetResource.Description
            AllowedAuthenticationClassReferences = $targetResource.AllowedAuthenticationClassReferences
            ClaimsProviderName                   = $targetResource.ClaimsProviderName
            IssuanceAuthorizationRules           = $targetResource.IssuanceAuthorizationRules
            DelegationAuthorizationRules         = $targetResource.DelegationAuthorizationRules
            ImpersonationAuthorizationRules      = $targetResource.ImpersonationAuthorizationRules
            IssuanceTransformRules               = $targetResource.IssuanceTransformRules
            AdditionalAuthenticationRules        = $targetResource.AdditionalAuthenticationRules
            AccessControlPolicyName              = $targetResource.AccessControlPolicyName
            NotBeforeSkew                        = $targetResource.NotBeforeSkew
            TokenLifetime                        = $targetResource.TokenLifetime
            AlwaysRequireAuthentication          = $targetResource.AlwaysRequireAuthentication
            AllowedClientTypes                   = $targetResource.AllowedClientTypes
            IssueOAuthRefreshTokensTo            = $targetResource.IssueOAuthRefreshTokensTo
            RefreshTokenProtectionEnabled        = $targetResource.RefreshTokenProtectionEnabled
            RequestMFAFromClaimsProviders        = $targetResource.RequestMFAFromClaimsProviders
            Ensure                               = 'Present'
        }
    }
    else
    {
        # Resource does not exist
        $returnValue = @{
            Name                                 = $Name
            ApplicationGroupIdentifier           = $ApplicationGroupIdentifier
            Identifier                           = $Identifier
            Description                          = $null
            AllowedAuthenticationClassReferences = @()
            ClaimsProviderName                   = @()
            IssuanceAuthorizationRules           = $null
            DelegationAuthorizationRules         = $null
            ImpersonationAuthorizationRules      = $null
            IssuanceTransformRules               = $null
            AdditionalAuthenticationRules        = $null
            AccessControlPolicyName              = $null
            NotBeforeSkew                        = 0
            TokenLifetime                        = 0
            AlwaysRequireAuthentication          = $null
            AllowedClientTypes                   = 'None'
            IssueOAuthRefreshTokensTo            = 'NoDevice'
            RefreshTokenProtectionEnabled        = $false
            RequestMFAFromClaimsProviders        = $false
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
        Used Resource PowerShell Cmdlets:
        - Add-AdfsWebApiApplication    - https://docs.microsoft.com/en-us/powershell/module/adfs/add-adfswebApiapplication
        - Remove-AdfsWebApiApplication - https://docs.microsoft.com/en-us/powershell/module/adfs/remove-adfswebApiapplication
        - Set-AdfsWebApiApplication    - https://docs.microsoft.com/en-us/powershell/module/adfs/set-adfswebApiapplication
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
        $Description,

        [Parameter()]
        [ValidateSet('Present', 'Absent')]
        [System.String]
        $Ensure = 'Present',

        [Parameter()]
        [System.String[]]
        $AllowedAuthenticationClassReferences,

        [Parameter()]
        [System.String[]]
        $ClaimsProviderName,

        [Parameter()]
        [System.String]
        $IssuanceAuthorizationRules,

        [Parameter()]
        [System.String]
        $DelegationAuthorizationRules,

        [Parameter()]
        [System.String]
        $ImpersonationAuthorizationRules,

        [Parameter()]
        [System.String]
        $IssuanceTransformRules,

        [Parameter()]
        [System.String]
        $AdditionalAuthenticationRules,

        [Parameter()]
        [System.String]
        $AccessControlPolicyName,

        [Parameter()]
        [System.Int32]
        $NotBeforeSkew,

        [Parameter()]
        [System.Int32]
        $TokenLifetime,

        [Parameter()]
        [System.Boolean]
        $AlwaysRequireAuthentication,

        [Parameter()]
        [ValidateSet('None', 'Public', 'Confidential')]
        [System.String]
        $AllowedClientTypes,

        [Parameter()]
        [ValidateSet('NoDevice', 'WorkplaceJoinedDevices', 'AllDevices')]
        [System.String]
        $IssueOAuthRefreshTokensTo,

        [Parameter()]
        [System.Boolean]
        $RefreshTokenProtectionEnabled,

        [Parameter()]
        [System.Boolean]
        $RequestMFAFromClaimsProviders
    )

    # Remove any parameters not used in Splats
    [HashTable]$parameters = $PSBoundParameters
    $parameters.Remove('Ensure')
    $parameters.Remove('Verbose')

    $GetTargetResourceParms = @{
        ApplicationGroupIdentifier = $ApplicationGroupIdentifier
        Name                       = $Name
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
                Remove-AdfsWebApiApplication -TargetName $Name
                Write-Verbose -Message ($script:localizedData.AddingResourceMessage -f
                    $Name, $ApplicationGroupIdentifier)
                Add-AdfsWebApiApplication @parameters -Verbose:$false
                break
            }
            $setParameters = @{ }
            foreach ($property in $propertiesNotInDesiredState)
            {
                Write-Verbose -Message ($script:localizedData.SettingResourceMessage -f
                    $Name, $property.ParameterName, ($property.Expected -join ', '))
                $setParameters.add($property.ParameterName, $property.Expected)
            }
            Set-AdfsWebApiApplication -TargetName $Name @setParameters
        }
        else
        {
            # Resource does not exist
            Write-Verbose -Message ($script:localizedData.AddingResourceMessage -f
                $Name, $ApplicationGroupIdentifier)
            Add-AdfsWebApiApplication @parameters -Verbose:$false
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
            Remove-AdfsWebApiApplication -TargetName $Name
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
        $ApplicationGroupIdentifier,

        [Parameter(Mandatory = $true)]
        [System.String[]]
        $Identifier,

        [Parameter()]
        [System.String]
        $Description,

        [Parameter()]
        [ValidateSet('Present', 'Absent')]
        [System.String]
        $Ensure = 'Present',

        [Parameter()]
        [System.String[]]
        $AllowedAuthenticationClassReferences,

        [Parameter()]
        [System.String[]]
        $ClaimsProviderName,

        [Parameter()]
        [System.String]
        $IssuanceAuthorizationRules,

        [Parameter()]
        [System.String]
        $DelegationAuthorizationRules,

        [Parameter()]
        [System.String]
        $ImpersonationAuthorizationRules,

        [Parameter()]
        [System.String]
        $IssuanceTransformRules,

        [Parameter()]
        [System.String]
        $AdditionalAuthenticationRules,

        [Parameter()]
        [System.String]
        $AccessControlPolicyName,

        [Parameter()]
        [System.Int32]
        $NotBeforeSkew,

        [Parameter()]
        [System.Int32]
        $TokenLifetime,

        [Parameter()]
        [System.Boolean]
        $AlwaysRequireAuthentication,

        [Parameter()]
        [ValidateSet('None', 'Public', 'Confidential')]
        [System.String]
        $AllowedClientTypes,

        [Parameter()]
        [ValidateSet('NoDevice', 'WorkplaceJoinedDevices', 'AllDevices')]
        [System.String]
        $IssueOAuthRefreshTokensTo,

        [Parameter()]
        [System.Boolean]
        $RefreshTokenProtectionEnabled,

        [Parameter()]
        [System.Boolean]
        $RequestMFAFromClaimsProviders
    )

    $getTargetResourceParms = @{
        Name                       = $Name
        ApplicationGroupIdentifier = $ApplicationGroupIdentifier
        Identifier                 = $Identifier
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
            Write-Verbose -Message ($script:localizedData.ResourceDoesNotExistAndShouldNotMessage -f
                $targetResource.Name)
            $inDesiredState = $true
        }
    }

    $inDesiredState
}

Export-ModuleMember -Function *-TargetResource
