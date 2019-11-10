$Global:DSCModuleName = 'AdfsDsc'
$Global:PSModuleName = 'ADFS'
$Global:DSCResourceName = 'MSFT_AdfsRelyingPartyTrust'

$moduleRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $Script:MyInvocation.MyCommand.Path))
if ( (-not (Test-Path -Path (Join-Path -Path $moduleRoot -ChildPath 'DSCResource.Tests'))) -or `
    (-not (Test-Path -Path (Join-Path -Path $moduleRoot -ChildPath 'DSCResource.Tests\TestHelper.psm1'))) )
{
    & git @('clone', 'https://github.com/PowerShell/DscResource.Tests.git',
        (Join-Path -Path $moduleRoot -ChildPath '\DSCResource.Tests\'))
}

Import-Module (Join-Path -Path $moduleRoot -ChildPath 'DSCResource.Tests\TestHelper.psm1') -Force

$TestEnvironment = Initialize-TestEnvironment `
    -DSCModuleName $Global:DSCModuleName `
    -DSCResourceName $Global:DSCResourceName `
    -TestType Unit

try
{
    InModuleScope $Global:DSCResourceName {
        # Import Stub Module
        Import-Module (Join-Path -Path $PSScriptRoot -ChildPath "Stubs\$($Global:PSModuleName)Stub.psm1") -Force

        # Define Resource Commands
        $ResourceCommand = @{
            Get    = 'Get-AdfsRelyingPartyTrust'
            Set    = 'Set-AdfsRelyingPartyTrust'
            Add    = 'Add-AdfsRelyingPartyTrust'
            Remove = 'Remove-AdfsRelyingPartyTrust'
        }

        $mockClaim = @{
            ClaimType = 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress'
            ShortName = 'email'
        }

        $mockChangedClaim = @{
            ClaimType = 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn'
            ShortName = 'upn'
        }

        $mockClaimAccepted = @{
            ClaimType = $mockClaim.ClaimType
        }

        $mockChangedClaimAccepted = @{
            ClaimType = $mockChangedClaim.ClaimType
        }

        $mockLdapAttributes = @(
            'mail'
            'sn'
        )

        $mockOutgoingClaimTypes = @(
            'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress'
            'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname'
        )

        $MSFT_AdfsLdapMappingProperties = @(
            @{
                LdapAttribute     = $mockLdapAttributes[0]
                OutgoingClaimType = $mockOutgoingClaimTypes[0]
            }
            @{
                LdapAttribute     = $mockLdapAttributes[1]
                OutgoingClaimType = $mockOutgoingClaimTypes[1]
            }
        )

        $mockTemplateName = 'LdapClaims'
        $mockRuleName = 'Test'

        $mockLdapMapping = [CIMInstance[]]@(
            New-CimInstance -ClassName MSFT_AdfsLdapMapping `
                -Namespace root/microsoft/Windows/DesiredStateConfiguration `
                -Property $MSFT_AdfsLdapMappingProperties[0] -ClientOnly
            New-CimInstance -ClassName MSFT_AdfsLdapMapping `
                -Namespace root/microsoft/Windows/DesiredStateConfiguration `
                -Property $MSFT_AdfsLdapMappingProperties[1] -ClientOnly
        )

        $mockMSFT_AdfsIssuanceTransformRuleProperties = @{
            TemplateName   = $mockTemplateName
            Name           = $mockRuleName
            AttributeStore = 'Active Directory'
            LdapMapping    = $mockLdapMapping
        }


        $mockIssuanceTransformRules = [CIMInstance[]]@(
            New-CimInstance -ClassName MSFT_AdfsIssuanceTransformRule `
                -Namespace root/microsoft/Windows/DesiredStateConfiguration `
                -Property $mockMSFT_AdfsIssuanceTransformRuleProperties -ClientOnly
        )

        $mockLdapClaimsTransformRule = @(
            '@RuleTemplate = "{0}"' -f $mockTemplateName
            '@RuleName = "{0}"' -f $mockRuleName
            'c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname", Issuer == "AD AUTHORITY"]'
            '=> issue(store = "Active Directory", types = ("{1}", "{2}"), query = ";{3},{4};{0}", param = c.Value);' -f `
                '{0}', $mockOutgoingClaimTypes[0], $mockOutgoingClaimTypes[1], $mockLdapAttributes[0], $mockLdapAttributes[1]
        ) | Out-String

        $mockResource = @{
            Name                                 = 'Outlook Web App'
            AdditionalAuthenticationRules        = ''
            AdditionalWSFedEndpoint              = ''
            AllowedAuthenticationClassReferences = ''
            AllowedClientTypes                   = 'Public', 'Confidential'
            AlwaysRequireAuthentication          = $true
            AutoUpdateEnabled                    = $true
            ClaimAccepted                        = $mockClaim.ShortName
            ClaimsProviderName                   = @()
            DelegationAuthorizationRules         = 'rule'
            Enabled                              = $true
            EnableJWT                            = $true
            EncryptClaims                        = $true
            EncryptedNameIdRequired              = $true
            EncryptionCertificateRevocationCheck = 'CheckEndCert'
            Identifier                           = 'https://mail.contoso.com/owa'
            ImpersonationAuthorizationRules      = ''
            IssuanceAuthorizationRules           = ''
            IssuanceTransformRules               = $mockIssuanceTransformRules
            IssueOAuthRefreshTokensTo            = 'AllDevices'
            MetadataUrl                          = 'https://fabrikam.com/metadata'
            MonitoringEnabled                    = $true
            NotBeforeSkew                        = 1
            Notes                                = 'This is a trust for https://mail.contoso.com/owa'
            ProtocolProfile                      = 'SAML'
            RefreshTokenProtectionEnabled        = $true
            RequestMFAFromClaimsProviders        = $false
            SamlResponseSignature                = 'AssertionOnly'
            SignatureAlgorithm                   = 'http://www.w3.org/2000/09/xmldsig#rsa-sha1'
            SignedSamlRequestsRequired           = $true
            SigningCertificateRevocationCheck    = 'CheckEndCert'
            TokenLifetime                        = 1
            WSFedEndpoint                        = 'https://mail.contoso.com/owa'
            Ensure                               = 'Present'
        }

        $mockAbsentResource = @{
            Name                                 = 'Outlook Web App'
            AdditionalAuthenticationRules        = $null
            AdditionalWSFedEndpoint              = @()
            AllowedAuthenticationClassReferences = $null
            AllowedClientTypes                   = 'None'
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
            SamlResponseSignature                = 'AssertionOnly'
            SignatureAlgorithm                   = 'http://www.w3.org/2000/09/xmldsig#rsa-sha1'
            SignedSamlRequestsRequired           = $false
            SigningCertificateRevocationCheck    = 'CheckEndCert'
            TokenLifetime                        = 0
            WSFedEndpoint                        = $null
            Ensure                               = 'Absent'
        }

        $mockMSFT_AdfsLdapMappingChangedProperties = @{
            LdapAttribute     = 'givenname'
            OutgoingClaimType = 'givenName'
        }

        $mockLdapChangedMapping = [CIMInstance[]]@(
            New-CimInstance -ClassName MSFT_AdfsLdapMapping `
                -Namespace root/microsoft/Windows/DesiredStateConfiguration `
                -Property $mockMSFT_AdfsLdapMappingChangedProperties -ClientOnly
        )

        $mockMSFT_AdfsIssuanceTransformChangedRuleProperties = @{
            TemplateName   = 'LdapClaims'
            Name           = 'Test2'
            AttributeStore = 'ActiveDirectory'
            LdapMapping    = $mockLdapChangedMapping
        }

        $mockIssuanceTransformChangedRules = [CIMInstance[]]@(
            New-CimInstance -ClassName MSFT_AdfsIssuanceTransformRule `
                -Namespace root/microsoft/Windows/DesiredStateConfiguration `
                -Property $mockMSFT_AdfsIssuanceTransformChangedRuleProperties -ClientOnly
        )

        $mockChangedResource = @{
            AdditionalAuthenticationRules        = 'changed'
            AdditionalWSFedEndpoint              = 'changed'
            AllowedAuthenticationClassReferences = 'changed'
            AllowedClientTypes                   = 'Confidential'
            AlwaysRequireAuthentication          = $false
            AutoUpdateEnabled                    = $false
            ClaimAccepted                        = $mockChangedClaim.ShortName
            ClaimsProviderName                   = 'changed'
            DelegationAuthorizationRules         = 'changed'
            EnableJWT                            = $false
            EncryptClaims                        = $false
            EncryptedNameIdRequired              = $false
            EncryptionCertificateRevocationCheck = 'CheckChain'
            Identifier                           = 'https://mail.fabrikam.com/owa'
            ImpersonationAuthorizationRules      = 'changed'
            IssuanceAuthorizationRules           = 'changed'
            IssuanceTransformRules               = $mockIssuanceTransformChangedRules
            IssueOAuthRefreshTokensTo            = 'NoDevice'
            MetadataUrl                          = 'changed'
            MonitoringEnabled                    = $false
            NotBeforeSkew                        = 0
            Notes                                = 'This is a trust for https://mail.fabrikam.com/owa'
            ProtocolProfile                      = 'WsFederation'
            RefreshTokenProtectionEnabled        = $false
            RequestMFAFromClaimsProviders        = $true
            SamlResponseSignature                = 'MessageOnly'
            SignatureAlgorithm                   = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256'
            SignedSamlRequestsRequired           = $false
            SigningCertificateRevocationCheck    = 'CheckChain'
            TokenLifetime                        = 0
            WSFedEndpoint                        = 'https://mail.fabrikam.com/owa'
        }

        $mockGetTargetResourceResult = @{
            Name                                 = $mockResource.Name
            AdditionalAuthenticationRules        = $mockResource.AdditionalAuthenticationRules
            AdditionalWSFedEndpoint              = $mockResource.AdditionalWSFedEndpoint
            AllowedAuthenticationClassReferences = $mockResource.AllowedAuthenticationClassReferences
            AllowedClientTypes                   = $mockResource.AllowedClientTypes
            AlwaysRequireAuthentication          = $mockResource.AlwaysRequireAuthentication
            AutoUpdateEnabled                    = $mockResource.AutoUpdateEnabled
            ClaimAccepted                        = $mockResource.ClaimAccepted
            ClaimsProviderName                   = $mockResource.ClaimsProviderName
            DelegationAuthorizationRules         = $mockResource.DelegationAuthorizationRules
            Enabled                              = $mockResource.Enabled
            EnableJWT                            = $mockResource.EnableJWT
            EncryptClaims                        = $mockResource.EncryptClaims
            EncryptedNameIdRequired              = $mockResource.EncryptedNameIdRequired
            EncryptionCertificateRevocationCheck = $mockResource.EncryptionCertificateRevocationCheck
            Identifier                           = $mockResource.Identifier
            ImpersonationAuthorizationRules      = $mockResource.ImpersonationAuthorizationRules
            IssuanceAuthorizationRules           = $mockResource.IssuanceAuthorizationRules
            IssuanceTransformRules               = $mockResource.IssuanceTransformRules
            IssueOAuthRefreshTokensTo            = $mockResource.IssueOAuthRefreshTokensTo
            MetadataUrl                          = $mockResource.MetadataUrl
            MonitoringEnabled                    = $mockResource.MonitoringEnabled
            NotBeforeSkew                        = $mockResource.NotBeforeSkew
            Notes                                = $mockResource.Notes
            ProtocolProfile                      = $mockResource.ProtocolProfile
            RefreshTokenProtectionEnabled        = $mockResource.RefreshTokenProtectionEnabled
            RequestMFAFromClaimsProviders        = $mockResource.RequestMFAFromClaimsProviders
            SamlResponseSignature                = $mockResource.SamlResponseSignature
            SignatureAlgorithm                   = $mockResource.SignatureAlgorithm
            SignedSamlRequestsRequired           = $mockResource.SignedSamlRequestsRequired
            SigningCertificateRevocationCheck    = $mockResource.SigningCertificateRevocationCheck
            TokenLifetime                        = $mockResource.TokenLifetime
            WSFedEndpoint                        = $mockResource.WSFedEndpoint
        }

        $mockGetTargetResourcePresentResult = $mockGetTargetResourceResult.Clone()
        $mockGetTargetResourcePresentResult.Ensure = 'Present'

        $mockGetTargetResourceAbsentResult = $mockGetTargetResourceResult.Clone()
        $mockGetTargetResourceAbsentResult.Ensure = 'Absent'

        $mockGetAdfsClaimDescriptionResult = New-MockObject -Type Microsoft.IdentityServer.Management.Resources.ClaimDescription

        Describe "$Global:DSCResourceName\Get-TargetResource" -Tag 'Get' {
            BeforeAll {
                $getTargetResourceParameters = @{
                    Name = $mockResource.Name
                }

                $mockGetResourceCommandResult = @{
                    Name                                 = $mockResource.Name
                    AdditionalAuthenticationRules        = $mockResource.AdditionalAuthenticationRules
                    AdditionalWSFedEndpoint              = $mockResource.AdditionalWSFedEndpoint
                    AllowedAuthenticationClassReferences = $mockResource.AllowedAuthenticationClassReferences
                    AllowedClientTypes                   = $mockResource.AllowedClientTypes
                    AlwaysRequireAuthentication          = $mockResource.AlwaysRequireAuthentication
                    AutoUpdateEnabled                    = $mockResource.AutoUpdateEnabled
                    ClaimsAccepted                       = $mockClaimAccepted
                    ClaimsProviderName                   = $mockResource.ClaimsProviderName
                    DelegationAuthorizationRules         = $mockResource.DelegationAuthorizationRules
                    Enabled                              = $mockResource.Enabled
                    EnableJWT                            = $mockResource.EnableJWT
                    EncryptClaims                        = $mockResource.EncryptClaims
                    EncryptedNameIdRequired              = $mockResource.EncryptedNameIdRequired
                    EncryptionCertificateRevocationCheck = $mockResource.EncryptionCertificateRevocationCheck
                    Identifier                           = $mockResource.Identifier
                    ImpersonationAuthorizationRules      = $mockResource.ImpersonationAuthorizationRules
                    IssuanceAuthorizationRules           = $mockResource.IssuanceAuthorizationRules
                    IssuanceTransformRules               = $mockLdapClaimsTransformRule
                    IssueOAuthRefreshTokensTo            = $mockResource.IssueOAuthRefreshTokensTo
                    MetadataUrl                          = $mockResource.MetadataUrl
                    MonitoringEnabled                    = $mockResource.MonitoringEnabled
                    NotBeforeSkew                        = $mockResource.NotBeforeSkew
                    Notes                                = $mockResource.Notes
                    ProtocolProfile                      = $mockResource.ProtocolProfile
                    RefreshTokenProtectionEnabled        = $mockResource.RefreshTokenProtectionEnabled
                    RequestMFAFromClaimsProviders        = $mockResource.RequestMFAFromClaimsProviders
                    SamlResponseSignature                = $mockResource.SamlResponseSignature
                    SignatureAlgorithm                   = $mockResource.SignatureAlgorithm
                    SignedSamlRequestsRequired           = $mockResource.SignedSamlRequestsRequired
                    SigningCertificateRevocationCheck    = $mockResource.SigningCertificateRevocationCheck
                    TokenLifetime                        = $mockResource.TokenLifetime
                    WSFedEndpoint                        = $mockResource.WSFedEndpoint
                }

                Mock -CommandName Assert-Module
                Mock -CommandName Assert-Command
                Mock -CommandName Assert-AdfsService
                Mock -CommandName Get-AdfsClaimDescription -MockWith { $mockClaim }
            }

            Context 'When the Resource is Present' {
                BeforeAll {
                    Mock -CommandName $ResourceCommand.Get -MockWith { $mockGetResourceCommandResult }

                    $result = Get-TargetResource @getTargetResourceParameters
                }

                foreach ($property in $mockResource.Keys)
                {
                    It "Should return the correct $property property" {
                        $result.$property | ConvertTo-Json | Should -Be ($mockResource.$property | ConvertTo-Json)
                    }
                }

                It 'Should call the expected mocks' {
                    Assert-MockCalled -CommandName Assert-Module `
                        -ParameterFilter { $ModuleName -eq $Global:PSModuleName } `
                        -Exactly -Times 1
                    Assert-MockCalled -CommandName Assert-Command `
                        -ParameterFilter { $Module -eq $Global:PSModuleName -and $Command -eq $ResourceCommand.Get } `
                        -Exactly -Times 1
                    Assert-MockCalled -CommandName Assert-AdfsService -Exactly -Times 1
                    Assert-MockCalled -CommandName $ResourceCommand.Get `
                        -ParameterFilter { $Name -eq $getTargetResourceParameters.Name } `
                        -Exactly -Times 1
                }
            }

            Context 'When the Resource is Absent' {
                BeforeAll {
                    Mock -CommandName $ResourceCommand.Get

                    $result = Get-TargetResource @getTargetResourceParameters
                }

                foreach ($property in $mockAbsentResource.Keys)
                {
                    It "Should return the correct $property property" {
                        $result.$property | Should -Be $mockAbsentResource.$property
                    }
                }

                It 'Should call the expected mocks' {
                    Assert-MockCalled -CommandName Assert-Module `
                        -ParameterFilter { $ModuleName -eq $Global:PSModuleName } `
                        -Exactly -Times 1
                    Assert-MockCalled -CommandName Assert-Command `
                        -ParameterFilter { $Module -eq $Global:PSModuleName -and $Command -eq $ResourceCommand.Get } `
                        -Exactly -Times 1
                    Assert-MockCalled -CommandName Assert-AdfsService -Exactly -Times 1
                    Assert-MockCalled -CommandName $ResourceCommand.Get `
                        -ParameterFilter { $Name -eq $getTargetResourceParameters.Name } `
                        -Exactly -Times 1
                }
            }
        }

        Describe "$Global:DSCResourceName\Set-TargetResource" -Tag 'Set' {
            BeforeAll {
                $setTargetResourceParameters = @{
                    Name                                 = $mockResource.Name
                    AdditionalAuthenticationRules        = $mockResource.AdditionalAuthenticationRules
                    AdditionalWSFedEndpoint              = $mockResource.AdditionalWSFedEndpoint
                    AutoUpdateEnabled                    = $mockResource.AutoUpdateEnabled
                    AllowedAuthenticationClassReferences = $mockResource.AllowedAuthenticationClassReferences
                    AllowedClientTypes                   = $mockResource.AllowedClientTypes
                    AlwaysRequireAuthentication          = $mockResource.AlwaysRequireAuthentication
                    ClaimAccepted                        = $mockResource.ClaimAccepted
                    ClaimsProviderName                   = $mockResource.ClaimsProviderName
                    DelegationAuthorizationRules         = $mockResource.DelegationAuthorizationRules
                    EnableJWT                            = $mockResource.EnableJWT
                    EncryptClaims                        = $mockResource.EncryptClaims
                    EncryptedNameIdRequired              = $mockResource.EncryptedNameIdRequired
                    EncryptionCertificateRevocationCheck = $mockResource.EncryptionCertificateRevocationCheck
                    Identifier                           = $mockResource.Identifier
                    ImpersonationAuthorizationRules      = $mockResource.ImpersonationAuthorizationRules
                    IssuanceAuthorizationRules           = $mockResource.IssuanceAuthorizationRules
                    IssuanceTransformRules               = $mockResource.IssuanceTransformRules
                    IssueOAuthRefreshTokensTo            = $mockResource.IssueOAuthRefreshTokensTo
                    MonitoringEnabled                    = $mockResource.MonitoringEnabled
                    NotBeforeSkew                        = $mockResource.NotBeforeSkew
                    Notes                                = $mockResource.Notes
                    ProtocolProfile                      = $mockResource.ProtocolProfile
                    RefreshTokenProtectionEnabled        = $mockResource.RefreshTokenProtectionEnabled
                    RequestMFAFromClaimsProviders        = $mockResource.RequestMFAFromClaimsProviders
                    SamlResponseSignature                = $mockResource.SamlResponseSignature
                    SignatureAlgorithm                   = $mockResource.SignatureAlgorithm
                    SignedSamlRequestsRequired           = $mockResource.SignedSamlRequestsRequired
                    SigningCertificateRevocationCheck    = $mockResource.SigningCertificateRevocationCheck
                    TokenLifetime                        = $mockResource.TokenLifetime
                    WSFedEndpoint                        = $mockResource.WSFedEndpoint
                }

                $setTargetResourcePresentParameters = $setTargetResourceParameters.Clone()
                $setTargetResourcePresentParameters.Ensure = 'Present'

                $setTargetResourceAbsentParameters = $setTargetResourceParameters.Clone()
                $setTargetResourceAbsentParameters.Ensure = 'Absent'

                Mock -CommandName $ResourceCommand.Set
                Mock -CommandName $ResourceCommand.Add
                Mock -CommandName $ResourceCommand.Remove
                Mock -CommandName Enable-AdfsRelyingPartyTrust
                Mock -CommandName Disable-AdfsRelyingPartyTrust
            }

            Context 'When the Resource is Present' {
                BeforeAll {
                    Mock -CommandName Get-TargetResource -MockWith { $mockGetTargetResourcePresentResult }
                }

                Context 'When the Resource should be Present' {
                    BeforeAll {
                        Mock -CommandName Get-AdfsClaimDescription -MockWith { $mockGetAdfsClaimDescriptionResult }
                    }

                    foreach ($property in $mockChangedResource.Keys)
                    {
                        Context "When $property has changed" {
                            BeforeAll {
                                $setTargetResourceParametersChangedProperty = $setTargetResourcePresentParameters.Clone()
                                $setTargetResourceParametersChangedProperty.$property = $mockChangedResource.$property
                            }

                            It 'Should not throw' {
                                { Set-TargetResource @setTargetResourceParametersChangedProperty } | Should -Not -Throw
                            }

                            It 'Should call the correct mocks' {
                                Assert-MockCalled -CommandName Get-TargetResource `
                                    -ParameterFilter { `
                                        $Name -eq $setTargetResourceParametersChangedProperty.Name } `
                                    -Exactly -Times 1
                                Assert-MockCalled -CommandName $ResourceCommand.Set `
                                    -ParameterFilter { `
                                        $TargetName -eq $setTargetResourceParametersChangedProperty.Name } `
                                    -Exactly -Times 1
                                Assert-MockCalled -CommandName $ResourceCommand.Add -Exactly -Times 0
                                Assert-MockCalled -CommandName $ResourceCommand.Remove -Exactly -Times 0
                                Assert-MockCalled -CommandName Enable-AdfsRelyingPartyTrust -Exactly -Times 0
                                Assert-MockCalled -CommandName Disable-AdfsRelyingPartyTrust -Exactly -Times 0
                            }
                        }
                    }

                    Context 'When Enabled property has changed to true' {
                        BeforeAll {
                            $setTargetResourceParametersChangedProperty = $setTargetResourcePresentParameters.Clone()
                            $setTargetResourceParametersChangedProperty.Enabled = $true
                            $mockGetTargetResourceEnabledResult = $mockGetTargetResourcePresentResult.Clone()
                            $mockGetTargetResourceEnabledResult.Enabled = $false

                            Mock -CommandName Get-TargetResource -MockWith { $mockGetTargetResourceEnabledResult }
                        }

                        It 'Should not throw' {
                            { Set-TargetResource @setTargetResourceParametersChangedProperty } | Should -Not -Throw
                        }

                        It 'Should call the correct mocks' {
                            Assert-MockCalled -CommandName Get-TargetResource `
                                -ParameterFilter { $Name -eq $setTargetResourceParametersChangedProperty.Name } `
                                -Exactly -Times 1
                            Assert-MockCalled -CommandName Enable-AdfsRelyingPartyTrust `
                                -ParameterFilter { $TargetName -eq $setTargetResourceParametersChangedProperty.Name } `
                                -Exactly -Times 1
                            Assert-MockCalled -CommandName Disable-AdfsRelyingPartyTrust -Exactly -Times 0
                            Assert-MockCalled -CommandName $ResourceCommand.Set -Exactly -Times 0
                            Assert-MockCalled -CommandName $ResourceCommand.Add -Exactly -Times 0
                            Assert-MockCalled -CommandName $ResourceCommand.Remove -Exactly -Times 0
                        }
                    }

                    Context 'When Enabled property has changed to false' {
                        BeforeAll {
                            $setTargetResourceParametersChangedProperty = $setTargetResourcePresentParameters.Clone()
                            $setTargetResourceParametersChangedProperty.Enabled = $false
                            $mockGetTargetResourceDisabledResult = $mockGetTargetResourcePresentResult.Clone()
                            $mockGetTargetResourceDisabledResult.Enabled = $true

                            Mock -CommandName Get-TargetResource -MockWith { $mockGetTargetResourceDisabledResult }
                        }

                        It 'Should not throw' {
                            { Set-TargetResource @setTargetResourceParametersChangedProperty } | Should -Not -Throw
                        }

                        It 'Should call the correct mocks' {
                            Assert-MockCalled -CommandName Get-TargetResource `
                                -ParameterFilter { $Name -eq $setTargetResourceParametersChangedProperty.Name } `
                                -Exactly -Times 1
                            Assert-MockCalled -CommandName Disable-AdfsRelyingPartyTrust `
                                -ParameterFilter { $TargetName -eq $setTargetResourceParametersChangedProperty.Name } `
                                -Exactly -Times 1
                            Assert-MockCalled -CommandName Enable-AdfsRelyingPartyTrust -Exactly -Times 0
                            Assert-MockCalled -CommandName $ResourceCommand.Set -Exactly -Times 0
                            Assert-MockCalled -CommandName $ResourceCommand.Add -Exactly -Times 0
                            Assert-MockCalled -CommandName $ResourceCommand.Remove -Exactly -Times 0
                        }
                    }
                }

                Context 'When the Resource should be Absent' {
                    It 'Should not throw' {
                        { Set-TargetResource @setTargetResourceAbsentParameters } | Should -Not -Throw
                    }

                    It 'Should call the expected mocks' {
                        Assert-MockCalled -CommandName Get-TargetResource `
                            -ParameterFilter { $Name -eq $setTargetResourceAbsentParameters.Name } `
                            -Exactly -Times 1
                        Assert-MockCalled -CommandName $ResourceCommand.Remove `
                            -ParameterFilter { $TargetName -eq $setTargetResourceAbsentParameters.Name } `
                            -Exactly -Times 1
                        Assert-MockCalled -CommandName $ResourceCommand.Set -Exactly -Times 0
                        Assert-MockCalled -CommandName $ResourceCommand.Add -Exactly -Times 0
                        Assert-MockCalled -CommandName Enable-AdfsRelyingPartyTrust -Exactly -Times 0
                        Assert-MockCalled -CommandName Disable-AdfsRelyingPartyTrust -Exactly -Times 0
                    }
                }
            }

            Context 'When the Resource is Absent' {
                BeforeAll {
                    Mock -CommandName Get-TargetResource -MockWith { $mockGetTargetResourceAbsentResult }
                }

                Context 'When the Resource should be Present' {
                    BeforeAll {
                        Mock -CommandName Get-AdfsClaimDescription -MockWith { $mockGetAdfsClaimDescriptionResult }
                    }

                    It 'Should not throw' {
                        { Set-TargetResource @setTargetResourcePresentParameters } | Should -Not -Throw
                    }

                    It 'Should call the expected mocks' {
                        Assert-MockCalled -CommandName Get-TargetResource `
                            -ParameterFilter { $Name -eq $setTargetResourcePresentParameters.Name } `
                            -Exactly -Times 1
                        Assert-MockCalled -CommandName $ResourceCommand.Add `
                            -ParameterFilter { $Name -eq $setTargetResourcePresentParameters.Name } `
                            -Exactly -Times 1
                        Assert-MockCalled -CommandName $ResourceCommand.Set -Exactly -Times 0
                        Assert-MockCalled -CommandName $ResourceCommand.Remove -Exactly -Times 0
                        Assert-MockCalled -CommandName Enable-AdfsRelyingPartyTrust -Exactly -Times 0
                        Assert-MockCalled -CommandName Disable-AdfsRelyingPartyTrust -Exactly -Times 0
                    }
                }

                Context 'When the Resource should be Absent' {
                    It 'Should not throw' {
                        { Set-TargetResource @setTargetResourceAbsentParameters } | Should -Not -Throw
                    }

                    It 'Should call the expected mocks' {
                        Assert-MockCalled -CommandName Get-TargetResource `
                            -ParameterFilter { $Name -eq $setTargetResourceAbsentParameters.Name } `
                            -Exactly -Times 1
                        Assert-MockCalled -CommandName $ResourceCommand.Remove -Exactly -Times 0
                        Assert-MockCalled -CommandName $ResourceCommand.Add -Exactly -Times 0
                        Assert-MockCalled -CommandName $ResourceCommand.Set -Exactly -Times 0
                        Assert-MockCalled -CommandName Enable-AdfsRelyingPartyTrust -Exactly -Times 0
                        Assert-MockCalled -CommandName Disable-AdfsRelyingPartyTrust -Exactly -Times 0
                    }
                }
            }
        }

        Describe "$Global:DSCResourceName\Test-TargetResource" -Tag 'Test' {
            BeforeAll {
                $testTargetResourceParameters = @{
                    Name                                 = $mockResource.Name
                    AdditionalAuthenticationRules        = $mockResource.AdditionalAuthenticationRules
                    AdditionalWSFedEndpoint              = $mockResource.AdditionalWSFedEndpoint
                    AutoUpdateEnabled                    = $mockResource.AutoUpdateEnabled
                    AllowedAuthenticationClassReferences = $mockResource.AllowedAuthenticationClassReferences
                    AllowedClientTypes                   = $mockResource.AllowedClientTypes
                    AlwaysRequireAuthentication          = $mockResource.AlwaysRequireAuthentication
                    ClaimAccepted                        = $mockResource.ClaimAccepted
                    ClaimsProviderName                   = $mockResource.ClaimsProviderName
                    DelegationAuthorizationRules         = $mockResource.DelegationAuthorizationRules
                    EnableJWT                            = $mockResource.EnableJWT
                    EncryptClaims                        = $mockResource.EncryptClaims
                    EncryptedNameIdRequired              = $mockResource.EncryptedNameIdRequired
                    EncryptionCertificateRevocationCheck = $mockResource.EncryptionCertificateRevocationCheck
                    Identifier                           = $mockResource.Identifier
                    ImpersonationAuthorizationRules      = $mockResource.ImpersonationAuthorizationRules
                    IssuanceAuthorizationRules           = $mockResource.IssuanceAuthorizationRules
                    IssuanceTransformRules               = $mockResource.IssuanceTransformRules
                    IssueOAuthRefreshTokensTo            = $mockResource.IssueOAuthRefreshTokensTo
                    MonitoringEnabled                    = $mockResource.MonitoringEnabled
                    NotBeforeSkew                        = $mockResource.NotBeforeSkew
                    Notes                                = $mockResource.Notes
                    ProtocolProfile                      = $mockResource.ProtocolProfile
                    RefreshTokenProtectionEnabled        = $mockResource.RefreshTokenProtectionEnabled
                    RequestMFAFromClaimsProviders        = $mockResource.RequestMFAFromClaimsProviders
                    SamlResponseSignature                = $mockResource.SamlResponseSignature
                    SignatureAlgorithm                   = $mockResource.SignatureAlgorithm
                    SignedSamlRequestsRequired           = $mockResource.SignedSamlRequestsRequired
                    SigningCertificateRevocationCheck    = $mockResource.SigningCertificateRevocationCheck
                    TokenLifetime                        = $mockResource.TokenLifetime
                    WSFedEndpoint                        = $mockResource.WSFedEndpoint
                }

                $testTargetResourcePresentParameters = $testTargetResourceParameters.Clone()
                $testTargetResourcePresentParameters.Ensure = 'Present'

                $testTargetResourceAbsentParameters = $testTargetResourceParameters.Clone()
                $testTargetResourceAbsentParameters.Ensure = 'Absent'
            }

            Context 'When the Resource is Present' {
                BeforeAll {
                    Mock -CommandName Get-TargetResource -MockWith { $mockGetTargetResourcePresentResult }
                }

                Context 'When the Resource should be Present' {
                    It 'Should not throw' {
                        { Test-TargetResource @testTargetResourcePresentParameters } | Should -Not -Throw
                    }

                    It 'Should call the expected mocks' {
                        Assert-MockCalled -CommandName Get-TargetResource `
                            -ParameterFilter { $Name -eq $testTargetResourcePresentParameters.Name } `
                            -Exactly -Times 1
                    }

                    foreach ($property in $mockChangedResource.Keys)
                    {
                        Context "When the $property resource property is not in the desired state" {
                            BeforeAll {
                                $testTargetResourceNotInDesiredStateParameters = $testTargetResourcePresentParameters.Clone()
                                $testTargetResourceNotInDesiredStateParameters.$property = $mockChangedResource.$property
                            }

                            It 'Should return the desired result' {
                                Test-TargetResource @testTargetResourceNotInDesiredStateParameters | Should -Be $false
                            }
                        }
                    }

                    Context 'When all the resource properties are in the desired state' {
                        It 'Should return the desired result' {
                            Test-TargetResource @testTargetResourcePresentParameters | Should -Be $true
                        }
                    }
                }

                Context 'When the Resource should be Absent' {
                    BeforeAll {
                        Mock -CommandName Get-TargetResource -MockWith { $mockGetTargetResourcePresentResult }
                    }

                    It 'Should return the desired result' {
                        Test-TargetResource @testTargetResourceAbsentParameters | Should -Be $false
                    }

                    It 'Should call the expected mocks' {
                        Assert-MockCalled -CommandName Get-TargetResource `
                            -ParameterFilter { $Name -eq $testTargetResourceAbsentParameters.Name } `
                            -Exactly -Times 1
                    }
                }
            }

            Context 'When the Resource is Absent' {
                BeforeAll {
                    Mock -CommandName Get-TargetResource -MockWith { $mockGetTargetResourceAbsentResult }
                }

                Context 'When the Resource should be Present' {
                    It 'Should return the desired result' {
                        Test-TargetResource @testTargetResourcePresentParameters | Should -Be $false
                    }

                    It 'Should call the expected mocks' {
                        Assert-MockCalled -CommandName Get-TargetResource `
                            -ParameterFilter { $Name -eq $testTargetResourcePresentParameters.Name } `
                            -Exactly -Times 1
                    }
                }

                Context 'When the Resource should be Absent' {
                    It 'Should return the desired result' {
                        Test-TargetResource @testTargetResourceAbsentParameters | Should -Be $true
                    }

                    It 'Should call the expected mocks' {
                        Assert-MockCalled -CommandName Get-TargetResource `
                            -ParameterFilter { $Name -eq $testTargetResourceAbsentParameters.Name } `
                            -Exactly -Times 1
                    }
                }
            }
        }
    }
}
finally
{
    Restore-TestEnvironment -TestEnvironment $TestEnvironment
}
