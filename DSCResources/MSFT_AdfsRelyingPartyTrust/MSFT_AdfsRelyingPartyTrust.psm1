<#
    .SYNOPSIS
        DSC module for the ADFS Relying Party Trust resource

    .DESCRIPTION
        The AdfsRelyingPartyTrust DSC resource manages the relying party trusts of the Federation Service.

    .PARAMETER Name
        Key - String
        Specifies the friendly name of this relying party trust.

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
                        CheckChainExcludingRoot, CheckChainExcludingRootCacheOnly

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
        Write - String
        Specifies the issuance transform rules for issuing claims to this relying party.

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

    .PARAMETER RequestSigningCertificate
        ** Not Currently Implemented **
        Specifies an array of certificates to be used to verify the signature on a request from the relying party.

    .PARAMETER SamlEndpoint
        ** Not Currently Implemented **
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
                        CheckChainExcludingRoot, CheckChainExcludingRootCacheOnly

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
        Used Resource PowerShell Cmdlets:
        - Get-AdfsRelyingPartyTrust - https://docs.microsoft.com/en-us/powershell/module/adfs/get-adfsrelyingpartytrust
    #>

    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $Name
    )

    # Check of the Resource PowerShell module is installed
    Assert-Module -ModuleName $script:psModuleName

    # Check if the Get-AdfsRelyingPartyTrust cmdlet is available
    Assert-Command -Module $script:psModuleName -Command 'Get-AdfsRelyingPartyTrust'

    # Check if the ADFS Service is present and running
    Assert-AdfsService -Verbose

    Write-Verbose -Message ($script:localizedData.GettingResourceMessage -f $Name)
    $targetResource = Get-AdfsRelyingPartyTrust -Name $Name

    if ($targetResource)
    {
        $claimAccepted = @()
        foreach ($claimDescription in $targetResource.ClaimsAccepted)
        {
            $claim = Get-AdfsClaimDescription -ClaimType $claimDescription.ClaimType
            $claimAccepted += $claim.ShortName
        }

        # Resource exists
        $returnValue = @{
            Name                                 = $targetResource.Name
            AdditionalAuthenticationRules        = $targetResource.AdditionalAuthenticationRules
            AdditionalWSFedEndpoint              = @($targetResource.AdditionalWSFedEndpoint)
            AutoUpdateEnabled                    = $targetResource.AutoUpdateEnabled
            ClaimAccepted                        = $claimAccepted
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
            IssuanceTransformRules               = $targetResource.IssuanceTransformRules
            MetadataUrl                          = $targetResource.MetadataUrl
            MonitoringEnabled                    = $targetResource.MonitoringEnabled
            NotBeforeSkew                        = $targetResource.NotBeforeSkew
            Notes                                = $targetResource.Notes
            ProtocolProfile                      = $targetResource.ProtocolProfile
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
        # Resource does not exist
        $returnValue = @{
            Name                                 = $Name
            AdditionalAuthenticationRules        = $null
            AdditionalWSFedEndpoint              = @()
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
            MetadataUrl                          = $null
            MonitoringEnabled                    = $false
            NotBeforeSkew                        = 0
            Notes                                = $null
            ProtocolProfile                      = 'SAML'
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
        Used Resource PowerShell Cmdlets:
        - Add-AdfsRelyingPartyTrust    - https://docs.microsoft.com/en-us/powershell/module/adfs/add-adfsrelyingpartytrust
        - Remove-AdfsRelyingPartyTrust - https://docs.microsoft.com/en-us/powershell/module/adfs/remove-adfsrelyingpartytrust
        - Set-AdfsRelyingPartyTrust    - https://docs.microsoft.com/en-us/powershell/module/adfs/set-adfsrelyingpartytrust
    #>

    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $Name,

        [Parameter()]
        [System.String]
        $AdditionalAuthenticationRules,

        [Parameter()]
        [System.String[]]
        $AdditionalWSFedEndpoint,

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
            'CheckChainExcludingRoot',
            'CheckChainExcludingRootCacheOnly')]
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
        [System.String]
        $IssuanceTransformRules,

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
            'CheckChainExcludingRoot',
            'CheckChainExcludingRootCacheOnly')]
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

    # Remove any parameters not used in Splats
    [HashTable]$parameters = $PSBoundParameters
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

            $SetParameters = @{ }
            foreach ($property in $propertiesNotInDesiredState)
            {
                Write-Verbose -Message ($script:localizedData.SettingResourceMessage -f
                    $Name, $property.ParameterName, ($property.Expected -join ', '))
                if ($property.ParameterName -eq 'ClaimAccepted')
                {
                    # Custom processing for 'ClaimAccepted' property
                    $ClaimAcceptedDescriptions = @()
                    foreach ($claim in $property.Expected)
                    {
                        $ClaimAcceptedDescriptions += Get-AdfsClaimDescription -ShortName $claim
                    }
                    $SetParameters.Add($property.ParameterName, $ClaimAcceptedDescriptions)
                }
                elseif ($property.ParameterName -eq 'Enabled')
                {
                    # Custom processing for 'Enabled' property
                    if ($property.Expected -eq $true)
                    {
                        Enable-AdfsRelyingPartyTrust -TargetName $Name
                    }
                    else
                    {
                        Disable-AdfsRelyingPartyTrust -TargetName $Name
                    }
                }
                else
                {
                    $SetParameters.Add($property.ParameterName, $property.Expected)
                }
            }

            if ($setParameters.count -gt 0)
            {
                Set-AdfsRelyingPartyTrust -TargetName $Name @setParameters
            }
        }
        else
        {
            # Resource does not exist
            if ($parameters.ContainsKey('ClaimAccepted'))
            {
                $ClaimAcceptedDescriptions = @()
                foreach ($claim in $parameters.ClaimAccepted)
                {
                    $ClaimAcceptedDescriptions += Get-AdfsClaimDescription -ShortName $claim
                }

                $parameters.ClaimAccepted = $ClaimAcceptedDescriptions
            }

            Write-Verbose -Message ($script:localizedData.AddingResourceMessage -f $Name)
            Add-AdfsRelyingPartyTrust @parameters -Verbose:$false
        }
    }
    else
    {
        # Resource should not exist
        if ($TargetResource.Ensure -eq 'Present')
        {
            # Resource exists
            Write-Verbose -Message ($script:localizedData.RemovingResourceMessage -f $Name)
            Remove-AdfsRelyingPartyTrust -TargetName $Name
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
        $AdditionalAuthenticationRules,

        [Parameter()]
        [System.String[]]
        $AdditionalWSFedEndpoint,

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
            'CheckChainExcludingRoot',
            'CheckChainExcludingRootCacheOnly')]
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
        [System.String]
        $IssuanceTransformRules,

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
            'CheckChainExcludingRoot',
            'CheckChainExcludingRootCacheOnly')]
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

    $getTargetResourceParms = @{
        Name = $Name
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
