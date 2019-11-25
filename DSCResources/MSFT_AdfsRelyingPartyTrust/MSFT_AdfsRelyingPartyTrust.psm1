<#
    .SYNOPSIS
        DSC module for the ADFS Relying Party Trust resource

    .DESCRIPTION
        The AdfsRelyingPartyTrust DSC resource manages the relying party trusts of the Federation Service.

    .PARAMETER Name
        Key - String
        Specifies the friendly name of this relying party trust.

    .PARAMETER AccessControlPolicyName
        Write - String
        Specifies the name of an access control policy.

    .PARAMETER AccessControlPolicyParameters
        Write - MSFT_AccessControlPolicyParameters
        Specifies the parameters and their values to pass to the Access Control Policy.

    .PARAMETER AdditionalAuthenticationRules
        Write - String
        Specifies the additional authorization rules to require additional authentication based on user, device and
        location attributes after the completion of the first step of authentication. Note: These rules must only be
        configured after there is at least one authentication provider enabled for additional authentication.

    .PARAMETER AdditionalWSFedEndpoint
        Write - String
        Specifies an array of alternate return addresses for the application. This is typically used when the
        application wants to indicate to AD FS what the return URL should be on successful token generation. AD FS
        requires that all acceptable URLs are entered as trusted information by the administrator.

    .PARAMETER AllowedAuthenticationClassReferences
        Write - String
        Specifies an array of allow authentication class references.

    .PARAMETER AllowedClientTypes
        Write - String
        Allowed values: None, Public, Confidential
        Specifies allowed client types.

    .PARAMETER AlwaysRequireAuthentication
        Write - Boolean
        Indicates to always require authentication.

    .PARAMETER AutoUpdateEnabled
        Write - Boolean
        Indicates whether changes to the federation metadata by the MetadataURL parameter apply automatically to the
        configuration of the trust relationship. If this parameter has a value of True, partner claims, certificates,
        and endpoints are updated automatically.

    .PARAMETER ClaimAccepted
        Write - String
        Specifies an array of claims that this relying party accepts.

    .PARAMETER ClaimsProviderName
        Write - String
        Specifies the name of the claim provider.

    .PARAMETER DelegationAuthorizationRules
        Write - String
        Specifies the delegation authorization rules for issuing claims to this relying party.

    .PARAMETER Enabled
        Write - Boolean
        Indicates whether the relying party trust is enabled.

    .PARAMETER EnableJWT
        Write - Boolean
        Indicates whether the JSON Web Token (JWT) format should be used to issue a token on a WS-Federation request.
        By default, SAML tokens are issued over WS-Federation.

    .PARAMETER EncryptClaims
        Write - Boolean
        Indicates whether the claims that are sent to the relying party are encrypted.

    .PARAMETER EncryptedNameIdRequired
        Write - Boolean
        Indicates whether the relying party requires that the NameID claim be encrypted.

    .PARAMETER EncryptionCertificate
        ** Not Currently Implemented **
        Specifies the certificate to be used for encrypting claims that are issued to this relying party. Encrypting
        claims is optional.

    .PARAMETER EncryptionCertificateRevocationCheck
        Write - String
        Allowed values: None, CheckEndCert, CheckEndCertCacheOnly, CheckChain, CheckChainCacheOnly,
                        CheckChainExcludeRoot, CheckChainExcludeRootCacheOnly

        Specifies the type of validation that should occur for the encryption certificate it is used for encrypting
        claims to the relying party.

    .PARAMETER Identifier
        Write - String
        Specifies the unique identifiers for this relying party trust. No other trust can use an identifier from this
        list. Uniform Resource Identifiers (URIs) are often used as unique identifiers for a relying party trust, but
        you can use any string of characters.

    .PARAMETER ImpersonationAuthorizationRules
        Write - String
        Specifies the impersonation authorization rules for issuing claims to this relying party.

    .PARAMETER IssuanceAuthorizationRules
        Write - String
        Specifies the issuance authorization rules for issuing claims to this relying party.

    .PARAMETER IssuanceTransformRules
        Write - MSFT_AdfsIssuanceTransformRule
        Specifies the issuance transform rules for issuing claims to this relying party.

    .PARAMETER IssueOAuthRefreshTokensTo
        Write - String
        Allowed values: NoDevice, WorkplaceJoinedDevices, AllDevices
        Specifies the refresh token issuance device types.

    .PARAMETER MetadataUrl
        Write - String
        Specifies a URL at which the federation metadata for this relying party trust is available.

    .PARAMETER MonitoringEnabled
        Write - Boolean
        Indicates whether periodic monitoring of this relying party federation metadata is enabled. The MetadataUrl
        parameter specifies the URL of the relying party federation metadata.

    .PARAMETER NotBeforeSkew
        Write - Sint32
        Specifies the skew, as in integer, for the time stamp that marks the beginning of the validity period.

    .PARAMETER Notes
        Write - String
        Specifies notes for this relying party trust.

    .PARAMETER ProtocolProfile
        Write - String
        Allowed values: SAML, WsFederation, WsFed-SAML
        Specifies which protocol profiles the relying party supports.

    .PARAMETER RefreshTokenProtectionEnabled
        Write - Boolean
        Indicates whether refresh token protection is enabled.

    .PARAMETER RequestMFAFromClaimsProviders
        Write - Boolean
        Indicates that the request MFA from claims providers option is used.

    .PARAMETER RequestSigningCertificate
        ** Not Currently Implemented **
        Specifies an array of certificates to be used to verify the signature on a request from the relying party.

    .PARAMETER SamlEndpoint
        Write - MSFT_AdfsSamlEndpoint
        Specifies an array of Security Assertion Markup Language (SAML) protocol endpoints for this relying party.

    .PARAMETER SamlResponseSignature
        Write - String
        Allowed values: AssertionOnly, MessageAndAssertion, MessageOnly
        Specifies the response signature or signatures that the relying party expects.

    .PARAMETER SignatureAlgorithm
        Write - String
        Allowed values: http://www.w3.org/2000/09/xmldsig#rsa-sha1, http://www.w3.org/2001/04/xmldsig-more#rsa-sha256
        Specifies the signature algorithm that the relying party uses for signing and verification.

    .PARAMETER SignedSamlRequestsRequired
        Write - Boolean
        Indicates whether the Federation Service requires signed SAML protocol requests from the relying party. If you
        specify a value of True, the Federation Service rejects unsigned SAML protocol requests.

    .PARAMETER SigningCertificateRevocationCheck
        Write - String
        Allowed values: None, CheckEndCert, CheckEndCertCacheOnly, CheckChain, CheckChainCacheOnly,
                        CheckChainExcludeRoot, CheckChainExcludeRootCacheOnly

        Specifies the type of certificate validation that occur when signatures on requests from the relying party are
        verified.

    .PARAMETER TokenLifetime
        Write - Sint32
        Specifies the duration, in minutes, for which the claims that are issued to the relying party are valid.

    .PARAMETER WSFedEndpoint
        Write - String
        Specifies the WS-Federation Passive URL for this relying party.

    .PARAMETER Ensure
        Write - String
        Allowed values: Present, Absent
        Specifies whether to remove or add the relying party trust.

    .NOTES
        Todo:
            - SamlEndpoint Parameter
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
        Get-AdfsRelyingPartyTrust                | Adfs
        Assert-Module                            | AdfsDsc.Common
        Assert-Command                           | AdfsDsc.Common
        Assert-AdfsService                       | AdfsDsc.Common
        ConvertFrom-IssuanceTransformRule        | AdfsDsc.Common
        ConvertFrom-AccessControlPolicyParameter | AdfsDsc.Common
        ConvertFrom-SamlEndpoint                 | AdfsDsc.Common
    #>

    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $Name
    )

    $CommonParms = @{
        Verbose = $VerbosePreference
        Debug   = $DebugPreference
    }

    Write-Verbose -Message ($script:localizedData.GettingResourceMessage -f $Name)

    # Check of the Resource PowerShell module is installed
    Assert-Module -ModuleName $script:psModuleName

    # Check if the Get-AdfsRelyingPartyTrust cmdlet is available
    Assert-Command -Module $script:psModuleName -Command 'Get-AdfsRelyingPartyTrust'

    # Check if the ADFS Service is present and running
    Assert-AdfsService @CommonParms

    try
    {
        $targetResource = Get-AdfsRelyingPartyTrust -Name $Name
    }
    catch
    {
        $errorMessage = $script:localizedData.GettingResourceErrorMessage -f $Name
        New-InvalidOperationException -Message $errorMessage -Error $_
    }

    if ($targetResource)
    {
        $claimAcceptedDescriptions = @()
        foreach ($claim in $targetResource.ClaimsAccepted)
        {
            try
            {
                $claimDescription = Get-AdfsClaimDescription -ClaimType $claim.ClaimType
            }
            catch
            {
                $errorMessage = ($script:localizedData.GettingClaimDescriptionErrorMessage -f
                    $claim.ClaimType, $Name)
                New-InvalidOperationException -Message $errorMessage -Error $_
            }

            $claimAcceptedDescriptions += $claimDescription.ShortName
        }

        # Resource is Present
        Write-Debug -Message ($script:localizedData.TargetResourcePresentDebugMessage -f $Name)

        $AccessControlPolicyParameters = ConvertFrom-AccessControlPolicyParameter `
            -Policy $targetResource.AccessControlPolicyParameters @CommonParms

        $IssuanceTransformRules = ConvertFrom-IssuanceTransformRule `
            -Rule $targetResource.IssuanceTransformRules @CommonParms

        $SamlEndpoint = ConvertFrom-SamlEndpoint `
            -SamlEndpoint $targetResource.SamlEndpoints @CommonParms

        $returnValue = @{
            Name                                 = $targetResource.Name
            AccessControlPolicyName              = $targetResource.AccessControlPolicyName
            AccessControlPolicyParameters        = $AccessControlPolicyParameters
            AdditionalAuthenticationRules        = $targetResource.AdditionalAuthenticationRules
            AdditionalWSFedEndpoint              = @($targetResource.AdditionalWSFedEndpoint)
            AllowedAuthenticationClassReferences = $targetResource.AllowedAuthenticationClassReferences
            AllowedClientTypes                   = @($targetResource.AllowedClientTypes)
            AlwaysRequireAuthentication          = $targetResource.AlwaysRequireAuthentication
            AutoUpdateEnabled                    = $targetResource.AutoUpdateEnabled
            ClaimAccepted                        = $claimAcceptedDescriptions
            ClaimsProviderName                   = @($targetResource.ClaimsProviderName)
            DelegationAuthorizationRules         = $targetResource.DelegationAuthorizationRules
            Enabled                              = $targetResource.Enabled
            EnableJWT                            = $targetResource.EnableJWT
            EncryptClaims                        = $targetResource.EncryptClaims
            EncryptedNameIdRequired              = $targetResource.EncryptedNameIdRequired
            EncryptionCertificateRevocationCheck = $targetResource.EncryptionCertificateRevocationCheck
            Identifier                           = @($targetResource.Identifier)
            ImpersonationAuthorizationRules      = $targetResource.ImpersonationAuthorizationRules
            IssuanceAuthorizationRules           = $targetResource.IssuanceAuthorizationRules
            IssuanceTransformRules               = @($IssuanceTransformRules)
            IssueOAuthRefreshTokensTo            = $targetResource.IssueOAuthRefreshTokensTo
            MetadataUrl                          = $targetResource.MetadataUrl
            MonitoringEnabled                    = $targetResource.MonitoringEnabled
            NotBeforeSkew                        = $targetResource.NotBeforeSkew
            Notes                                = $targetResource.Notes
            ProtocolProfile                      = $targetResource.ProtocolProfile
            RefreshTokenProtectionEnabled        = $targetResource.RefreshTokenProtectionEnabled
            RequestMFAFromClaimsProviders        = $targetResource.RequestMFAFromClaimsProviders
            SamlEndpoint                         = @($SamlEndpoint)
            SamlResponseSignature                = $targetResource.SamlResponseSignature
            SignatureAlgorithm                   = $targetResource.SignatureAlgorithm
            SignedSamlRequestsRequired           = $targetResource.SignedSamlRequestsRequired
            SigningCertificateRevocationCheck    = $targetResource.SigningCertificateRevocationCheck
            TokenLifetime                        = $targetResource.TokenLifetime
            WSFedEndpoint                        = $targetResource.WSFedEndpoint
            Ensure                               = 'Present'
        }
    }
    else
    {
        # Resource is Absent
        Write-Debug -Message ($script:localizedData.TargetResourceAbsentDebugMessage -f $Name)

        $returnValue = @{
            Name                                 = $Name
            AccessControlPolicyName              = $null
            AccessControlPolicyParameters        = $null
            AdditionalAuthenticationRules        = $null
            AdditionalWSFedEndpoint              = @()
            AllowedAuthenticationClassReferences = @()
            AllowedClientTypes                   = @('None')
            AlwaysRequireAuthentication          = $false
            AutoUpdateEnabled                    = $false
            ClaimAccepted                        = @()
            ClaimsProviderName                   = @()
            DelegationAuthorizationRules         = $null
            Enabled                              = $false
            EnableJWT                            = $false
            EncryptClaims                        = $false
            EncryptedNameIdRequired              = $false
            EncryptionCertificateRevocationCheck = 'CheckEndCert'
            Identifier                           = @()
            ImpersonationAuthorizationRules      = $null
            IssuanceAuthorizationRules           = $null
            IssuanceTransformRules               = $null
            IssueOAuthRefreshTokensTo            = 'NoDevice'
            MetadataUrl                          = $null
            MonitoringEnabled                    = $false
            NotBeforeSkew                        = 0
            Notes                                = $null
            ProtocolProfile                      = 'SAML'
            RefreshTokenProtectionEnabled        = $false
            RequestMFAFromClaimsProviders        = $false
            SamlEndpoint                         = $null
            SamlResponseSignature                = 'AssertionOnly'
            SignatureAlgorithm                   = 'http://www.w3.org/2000/09/xmldsig#rsa-sha1'
            SignedSamlRequestsRequired           = $false
            SigningCertificateRevocationCheck    = 'CheckEndCert'
            TokenLifetime                        = 0
            WSFedEndpoint                        = $null
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
        Add-AdfsRelyingPartyTrust              | Adfs
        Remove-AdfsRelyingPartyTrust           | Adfs
        Set-AdfsRelyingPartyTrust              | Adfs
        Get-AdfsClaimDescription               | Adfs
        Enable-AdfsRelyingPartyTrust           | Adfs
        Disable-AdfsRelyingPartyTrust          | Adfs
        Compare-IssuanceTransformRule          | AdfsDsc.Common
        Compare-AccessControlPolicyParameter   | AdfsDsc.Common
        Compare-ResourcePropertyState          | AdfsDsc.Common
        Compare-SamlEndpoint                   | AdfsDsc.Common
        ConvertTo-IssuanceTransformRule        | AdfsDsc.Common
        ConvertTo-AccessControlPolicyParameter | AdfsDsc.Common
        ConvertTo-SamlEndpoint                 | AdfsDsc.Common
    #>

    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $Name,

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
        $AdditionalWSFedEndpoint,

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
        [System.Boolean]
        $AutoUpdateEnabled,

        [Parameter()]
        [System.String[]]
        $ClaimAccepted,

        [Parameter()]
        [System.String[]]
        $ClaimsProviderName,

        [Parameter()]
        [System.String]
        $DelegationAuthorizationRules,

        [Parameter()]
        [System.Boolean]
        $Enabled,

        [Parameter()]
        [System.Boolean]
        $EnableJWT,

        [Parameter()]
        [System.Boolean]
        $EncryptClaims,

        [Parameter()]
        [System.Boolean]
        $EncryptedNameIdRequired,

        [Parameter()]
        [ValidateSet('None',
            'CheckEndCert',
            'CheckEndCertCacheOnly',
            'CheckChain',
            'CheckChainCacheOnly',
            'CheckChainExcludeRoot',
            'CheckChainExcludeRootCacheOnly')]
        [System.String]
        $EncryptionCertificateRevocationCheck,

        [Parameter()]
        [System.String[]]
        $Identifier,

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
        [System.String]
        $MetadataUrl,

        [Parameter()]
        [System.Boolean]
        $MonitoringEnabled,

        [Parameter()]
        [System.Int32]
        $NotBeforeSkew,

        [Parameter()]
        [System.String]
        $Notes,

        [Parameter()]
        [ValidateSet('SAML', 'WsFederation', 'WsFed-SAML')]
        [System.String]
        $ProtocolProfile,

        [Parameter()]
        [System.Boolean]
        $RefreshTokenProtectionEnabled,

        [Parameter()]
        [System.Boolean]
        $RequestMFAFromClaimsProviders,

        [Parameter()]
        [Microsoft.Management.Infrastructure.CimInstance[]]
        $SamlEndpoint,

        [Parameter()]
        [ValidateSet('AssertionOnly', 'MessageAndAssertion', 'MessageOnly')]
        [System.String]
        $SamlResponseSignature,

        [Parameter()]
        [ValidateSet('http://www.w3.org/2000/09/xmldsig#rsa-sha1',
            'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256')]
        [System.String]
        $SignatureAlgorithm,

        [Parameter()]
        [System.Boolean]
        $SignedSamlRequestsRequired,

        [Parameter()]
        [ValidateSet('None',
            'CheckEndCert',
            'CheckEndCertCacheOnly',
            'CheckChain',
            'CheckChainCacheOnly',
            'CheckChainExcludeRoot',
            'CheckChainExcludeRootCacheOnly')]
        [System.String]
        $SigningCertificateRevocationCheck,

        [Parameter()]
        [System.Int32]
        $TokenLifetime,

        [Parameter()]
        [System.String]
        $WSFedEndpoint,

        [Parameter()]
        [ValidateSet('Present', 'Absent')]
        [System.String]
        $Ensure = 'Present'
    )

    # Set Verbose and Debug parameters
    $CommonParms = @{
        Verbose = $VerbosePreference
        Debug   = $DebugPreference
    }

    # Remove any parameters not used in Splats
    [HashTable]$parameters = $PSBoundParameters
    $parameters.Remove('Ensure')
    $parameters.Remove('Verbose')

    Write-Verbose -Message ($script:localizedData.SettingResourceMessage -f $Name)

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

            if ($PSBoundParameters.Keys.Contains('SamlEndpoint'))
            {
                $propertiesNotInDesiredState += (
                    Compare-SamlEndpoint -CurrentValue $targetResource.SamlEndpoint `
                        -DesiredValue $SamlEndpoint -ParameterName 'SamlEndpoint' `
                        @commonParms | Where-Object -Property InDesiredState -eq $false)
            }

            $propertiesNotInDesiredState += (
                Compare-ResourcePropertyState -CurrentValues $targetResource -DesiredValues $parameters `
                    -IgnoreProperties 'IssuanceTransformRules', 'AccessControlPolicyParameters', 'SamlEndpoint' `
                    @commonParms | Where-Object -Property InDesiredState -eq $false)

            $SetParameters = @{ }
            foreach ($property in $propertiesNotInDesiredState)
            {
                Write-Verbose -Message ($script:localizedData.SettingResourcePropertyMessage -f
                    $Name, $property.ParameterName, ($property.Expected -join ', '))

                if ($property.ParameterName -eq 'ClaimAccepted')
                {
                    # Custom processing for 'ClaimAccepted' property
                    $claimAcceptedDescriptions = @()
                    foreach ($claim in $property.Expected)
                    {
                        try
                        {
                            $claimAcceptedDescriptions += Get-AdfsClaimDescription -ShortName $claim
                        }
                        catch
                        {
                            $errorMessage = ($script:localizedData.GettingClaimDescriptionErrorMessage -f
                                $claim, $Name)
                            New-InvalidOperationException -Message $errorMessage -Error $_
                        }
                    }
                    $SetParameters.Add($property.ParameterName, $claimAcceptedDescriptions)
                }
                elseif ($property.ParameterName -eq 'Enabled')
                {
                    # Custom processing for 'Enabled' property
                    if ($property.Expected -eq $true)
                    {
                        try
                        {
                            Enable-AdfsRelyingPartyTrust -TargetName $Name
                        }
                        catch
                        {
                            $errorMessage = $script:localizedData.EnablingResourceErrorMessage -f $Name
                            New-InvalidOperationException -Message $errorMessage -Error $_
                        }
                    }
                    else
                    {
                        try
                        {
                            Disable-AdfsRelyingPartyTrust -TargetName $Name
                        }
                        catch
                        {
                            $errorMessage = $script:localizedData.DisablingResourceErrorMessage -f $Name
                            New-InvalidOperationException -Message $errorMessage -Error $_
                        }
                    }
                }
                elseif ($property.ParameterName -eq 'IssuanceTransformRules')
                {
                    # Custom processing for 'IssuanceTransformRules' property
                    $setParameters.Add($property.ParameterName, ($IssuanceTransformRules |
                            ConvertTo-IssuanceTransformRule @CommonParms))
                }
                elseif ($property.ParameterName -eq 'AccessControlPolicyParameters')
                {
                    # Custom processing for 'AccessControlPolicyParameters' property
                    $setParameters.Add($property.ParameterName, ($AccessControlPolicyParameters |
                            ConvertTo-AccessControlPolicyParameter @CommonParms))
                }
                elseif ($property.ParameterName -eq 'SamlEndpoint')
                {
                    # Custom processing for 'SamlEndpoint' property
                    $setParameters.Add($property.ParameterName, ($SamlEndpoint |
                            ConvertTo-SamlEndpoint @CommonParms))
                }
                else
                {
                    $SetParameters.Add($property.ParameterName, $property.Expected)
                }
            }

            if ($setParameters.count -gt 0)
            {
                try
                {
                    Set-AdfsRelyingPartyTrust -TargetName $Name @setParameters
                }
                catch
                {
                    $errorMessage = $script:localizedData.SettingResourceErrorMessage -f $Name
                    New-InvalidOperationException -Message $errorMessage -Error $_
                }
            }
        }
        else
        {
            # Resource should be Absent
            Write-Debug -Message ($script:localizedData.TargetResourceShouldBeAbsentDebugMessage -f $Name)

            Write-Verbose -Message ($script:localizedData.RemovingResourceMessage -f $Name)

            try
            {
                Remove-AdfsRelyingPartyTrust -TargetName $Name
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

            if ($parameters.ContainsKey('ClaimAccepted'))
            {
                $claimAcceptedDescriptions = @()
                foreach ($claim in $parameters.ClaimAccepted)
                {
                    try
                    {
                        $claimAcceptedDescriptions += Get-AdfsClaimDescription -ShortName $claim
                    }
                    catch
                    {
                        $errorMessage = ($script:localizedData.GettingClaimDescriptionErrorMessage -f
                            $claim, $Name)
                        New-InvalidOperationException -Message $errorMessage -Error $_
                    }
                }

                $parameters.ClaimAccepted = $claimAcceptedDescriptions
            }

            if ($parameters.ContainsKey('IssuanceTransformRules'))
            {
                # Custom processing for 'IssuanceTransformRules' property
                $parameters.IssuanceTransformRules = ($parameters.IssuanceTransformRules |
                    ConvertTo-IssuanceTransformRule @CommonParms)
            }

            if ($parameters.ContainsKey('AccessControlPolicyParameters'))
            {
                # Custom processing for 'AccessControlPolicyParameters' property
                $parameters.AccessControlPolicyParameters = ($parameters.AccessControlPolicyParameters |
                    ConvertTo-AccessControlPolicyParameter @CommonParms)
            }

            if ($parameters.ContainsKey('SamlEndpoint'))
            {
                # Custom processing for 'SamlEndpoint' property
                $parameters.SamlEndpoint = ($parameters.SamlEndpoint |
                    ConvertTo-SamlEndpoint @CommonParms)
            }

            Write-Verbose -Message ($script:localizedData.AddingResourceMessage -f $Name)

            try
            {
                Add-AdfsRelyingPartyTrust @parameters -Verbose:$false
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
        Compare-SamlEndpoint                 | AdfsDsc.Common
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
        $AccessControlPolicyName,

        [Parameter()]
        [Microsoft.Management.Infrastructure.CimInstance]
        $AccessControlPolicyParameters,

        [Parameter()]
        [System.String]
        $AdditionalAuthenticationRules,

        [Parameter()]
        [System.String[]]
        $AdditionalWSFedEndpoint,

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
        [System.Boolean]
        $AutoUpdateEnabled,

        [Parameter()]
        [System.String[]]
        $ClaimAccepted,

        [Parameter()]
        [System.String[]]
        $ClaimsProviderName,

        [Parameter()]
        [System.String]
        $DelegationAuthorizationRules,

        [Parameter()]
        [System.Boolean]
        $Enabled,

        [Parameter()]
        [System.Boolean]
        $EnableJWT,

        [Parameter()]
        [System.Boolean]
        $EncryptClaims,

        [Parameter()]
        [System.Boolean]
        $EncryptedNameIdRequired,

        [Parameter()]
        [ValidateSet('None',
            'CheckEndCert',
            'CheckEndCertCacheOnly',
            'CheckChain',
            'CheckChainCacheOnly',
            'CheckChainExcludeRoot',
            'CheckChainExcludeRootCacheOnly')]
        [System.String]
        $EncryptionCertificateRevocationCheck,

        [Parameter()]
        [System.String[]]
        $Identifier,

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
        [System.String]
        $MetadataUrl,

        [Parameter()]
        [System.Boolean]
        $MonitoringEnabled,

        [Parameter()]
        [System.Int32]
        $NotBeforeSkew,

        [Parameter()]
        [System.String]
        $Notes,

        [Parameter()]
        [ValidateSet('SAML', 'WsFederation', 'WsFed-SAML')]
        [System.String]
        $ProtocolProfile,

        [Parameter()]
        [System.Boolean]
        $RefreshTokenProtectionEnabled,

        [Parameter()]
        [System.Boolean]
        $RequestMFAFromClaimsProviders,

        [Parameter()]
        [Microsoft.Management.Infrastructure.CimInstance[]]
        $SamlEndpoint,

        [Parameter()]
        [ValidateSet('AssertionOnly', 'MessageAndAssertion', 'MessageOnly')]
        [System.String]
        $SamlResponseSignature,

        [Parameter()]
        [ValidateSet('http://www.w3.org/2000/09/xmldsig#rsa-sha1',
            'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256')]
        [System.String]
        $SignatureAlgorithm,

        [Parameter()]
        [System.Boolean]
        $SignedSamlRequestsRequired,

        [Parameter()]
        [ValidateSet('None',
            'CheckEndCert',
            'CheckEndCertCacheOnly',
            'CheckChain',
            'CheckChainCacheOnly',
            'CheckChainExcludeRoot',
            'CheckChainExcludeRootCacheOnly')]
        [System.String]
        $SigningCertificateRevocationCheck,

        [Parameter()]
        [System.Int32]
        $TokenLifetime,

        [Parameter()]
        [System.String]
        $WSFedEndpoint,

        [Parameter()]
        [ValidateSet('Present', 'Absent')]
        [System.String]
        $Ensure = 'Present'
    )

    # Set Verbose and Debug parameters
    $CommonParms = @{
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

            if ($PSBoundParameters.Keys.Contains('SamlEndpoint'))
            {
                $propertiesNotInDesiredState += (
                    Compare-SamlEndpoint -CurrentValue $targetResource.SamlEndpoint `
                        -DesiredValue $SamlEndpoint -ParameterName 'SamlEndpoint' `
                        @commonParms | Where-Object -Property InDesiredState -eq $false)
            }

            $propertiesNotInDesiredState += (
                Compare-ResourcePropertyState -CurrentValues $targetResource -DesiredValues $PSBoundParameters `
                    -IgnoreProperties 'IssuanceTransformRules', 'AccessControlPolicyParameters', 'SamlEndpoint' `
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
