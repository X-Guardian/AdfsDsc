<#
    .SYNOPSIS
        AdfsRelyingPartyTrust DSC Resource Integration test Configuration.

    .NOTES
        The AdfsRelyingPartyTrust resource has a dependency on an AdfsApplicationGroup resource
#>

#region HEADER
# Integration Test Config Template Version: 1.2.1
#endregion

$configFile = [System.IO.Path]::ChangeExtension($MyInvocation.MyCommand.Path, 'json')
if (Test-Path -Path $configFile)
{
    $ConfigurationData = Get-Content -Path $configFile | ConvertFrom-Json
}
else
{
    $ConfigurationData = @{
        AllNodes                                           = @(
            @{
                NodeName        = 'localhost'
                CertificateFile = $env:DscPublicCertificatePath
            }
        )

        AdfsRelyingPartyTrust                              = @{
            Name                                 = 'DscRelyingPartyTrust1'
            AccessControlPolicyName              = 'Permit specific group'
            Notes                                = 'This is the DscRelyingPartyTrust1 Description'
            WSFedEndpoint                        = 'https://mail.fabrikam.com/owa'
            Identifier                           = 'https://mail.fabrikam.com/owa'
            ProtocolProfile                      = 'WsFed-SAML'
            EncryptionCertificateRevocationCheck = 'CheckChainExcludeRoot'
            EncryptedNameIdRequired              = $false
            SignedSamlRequestsRequired           = $false
            SamlResponseSignature                = 'AssertionOnly'
            SignatureAlgorithm                   = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256'
            TokenLifetime                        = 0
            MonitoringEnabled                    = $false
            EncryptClaims                        = $true
            EnableJWT                            = $false
        }

        AdfsRelyingPartyTrustAccessControlPolicyParameters = @{
            GroupParameter = 'GTECK\DscRelyingPartyTrust1 Users'
        }

    }
}

Configuration MSFT_AdfsRelyingPartyTrust_Init_Config
{
    <#
        .SYNOPSIS
            Initialises the Integration test resources
    #>

    Import-DscResource -ModuleName 'AdfsDsc'

    node $AllNodes.NodeName
    {
        AdfsRelyingPartyTrust 'Integration_Test'
        {
            Name   = $ConfigurationData.AdfsRelyingPartyTrust.Name
            Ensure = 'Absent'
        }
    }
}

Configuration MSFT_AdfsRelyingPartyTrust_WSFed_Config
{
    <#
        .SYNOPSIS
            Manages an ADFS RelyingPartyTrust
    #>

    Import-DscResource -ModuleName 'AdfsDsc'

    node $AllNodes.NodeName
    {
        AdfsRelyingPartyTrust 'Integration_Test'
        {
            Name                                 = $ConfigurationData.AdfsRelyingPartyTrust.Name
            AccessControlPolicyName              = $ConfigurationData.AdfsRelyingPartyTrust.AccessControlPolicyName
            Notes                                = $ConfigurationData.AdfsRelyingPartyTrust.Notes
            WSFedEndpoint                        = $ConfigurationData.AdfsRelyingPartyTrust.WSFedEndpoint
            Identifier                           = $ConfigurationData.AdfsRelyingPartyTrust.Identifier
            ProtocolProfile                      = $ConfigurationData.AdfsRelyingPartyTrust.ProtocolProfile
            EncryptionCertificateRevocationCheck = $ConfigurationData.AdfsRelyingPartyTrust.EncryptionCertificateRevocationCheck
            EncryptedNameIdRequired              = $ConfigurationData.AdfsRelyingPartyTrust.EncryptedNameIdRequired
            SignedSamlRequestsRequired           = $ConfigurationData.AdfsRelyingPartyTrust.SignedSamlRequestsRequired
            SamlResponseSignature                = $ConfigurationData.AdfsRelyingPartyTrust.SamlResponseSignature
            SignatureAlgorithm                   = $ConfigurationData.AdfsRelyingPartyTrust.SignatureAlgorithm
            TokenLifetime                        = $ConfigurationData.AdfsRelyingPartyTrust.TokenLifetime
            MonitoringEnabled                    = $ConfigurationData.AdfsRelyingPartyTrust.MonitoringEnabled
            EncryptClaims                        = $ConfigurationData.AdfsRelyingPartyTrust.EncryptClaims
            EnableJWT                            = $ConfigurationData.AdfsRelyingPartyTrust.EnableJWT
            AccessControlPolicyParameters        = MSFT_AdfsAccessControlPolicyParameters
            {
                GroupParameter = $ConfigurationData.AdfsRelyingPartyTrustAccessControlPolicyParameters.GroupParameter
            }
            IssuanceTransformRules               = @(
                MSFT_AdfsIssuanceTransformRule
                {
                    TemplateName   = 'LdapClaims'
                    Name           = 'DscRelyingPartyTrust1 Ldap Claims'
                    LdapMapping    = @(
                        MSFT_AdfsLdapMapping
                        {
                            LdapAttribute     = 'mail'
                            OutgoingClaimType = 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress'
                        }
                        MSFT_AdfsLdapMapping
                        {
                            LdapAttribute     = 'sn'
                            OutgoingClaimType = 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname'
                        }
                    )
                    AttributeStore = 'Active Directory'
                }
                MSFT_AdfsIssuanceTransformRule
                {
                    TemplateName       = 'EmitGroupClaims'
                    Name               = 'DscRelyingPartyTrust1 Group Claim'
                    GroupName          = 'DscRelyingPartyTrust1 Users'
                    OutgoingClaimType  = 'http://schemas.microsoft.com/ws/2008/06/identity/claims/role'
                    OutgoingClaimValue = 'User'
                }
                MSFT_AdfsIssuanceTransformRule
                {
                    TemplateName = 'CustomClaims'
                    Name         = 'DscRelyingPartyTrust1 Custom Claim'
                    CustomRule   = 'c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/groupsid", Value == "S-1-5-21-2624039266-918686060-4041204886-1128", Issuer == "AD AUTHORITY"]
 => issue(Type = "http://schemas.microsoft.com/ws/2008/06/identity/claims/role", Value = "IDScan User", Issuer = c.Issuer, OriginalIssuer = c.OriginalIssuer, ValueType = c.ValueType);'
                }
            )
            SamlEndpoint                         = @(
                MSFT_AdfsSamlEndpoint
                {
                    Binding   = 'POST'
                    Index     = 0
                    IsDefault = $false
                    Protocol  = 'SAMLAssertionConsumer'
                    Uri       = 'https://example.com'
                }
            )
        }
    }
}
