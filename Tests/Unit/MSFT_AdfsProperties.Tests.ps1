$Global:DSCModuleName = 'AdfsDsc'
$Global:PSModuleName = 'ADFS'
$Global:DSCResourceName = 'MSFT_AdfsProperties'

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
            Get = 'Get-AdfsProperties'
            Set = 'Set-AdfsProperties'
        }

        $mockResource = @{
            FederationServiceName                      = 'sts.contoso.com'
            AcceptableIdentifiers                      = @()
            AdditionalErrorPageInfo                    = 'Private'
            ArtifactDbConnection                       = 'Data Source=np:\\.\pipe\microsoft##wid\tsql\query;Initial Catalog=AdfsArtifactStore;Integrated Security=True'
            AuditLevel                                 = 'Basic'
            AuthenticationContextOrder                 = 'urn:oasis:names:tc:SAML:2.0:ac:classes:Password', 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport', 'urn:oasis:names:tc:SAML:2.0:ac:classes:TLSClient', 'urn:oasis:names:tc:SAML:2.0:ac:classes:X509', 'urn:federation:authentication:windows', 'urn:oasis:names:tc:SAML:2.0:ac:classes:Kerberos'
            AutoCertificateRollover                    = $true
            CertificateCriticalThreshold               = 2
            CertificateDuration                        = 365
            CertificateGenerationThreshold             = 20
            CertificatePromotionThreshold              = 5
            CertificateRolloverInterval                = 720
            CertificateThresholdMultiplier             = 1440
            EnableOAuthDeviceFlow                      = $true
            HostName                                   = 'sts.contoso.com'
            HttpPort                                   = 80
            HttpsPort                                  = 443
            IntranetUseLocalClaimsProvider             = $false
            TlsClientPort                              = 49443
            Identifier                                 = 'http://sts.contoso.com/adfs/services/trust'
            LogLevel                                   = 'Errors', 'FailureAudits', 'Information', 'Verbose', 'SuccessAudits', 'Warnings', 'None'
            MonitoringInterval                         = 1440
            NetTcpPort                                 = 1501
            NtlmOnlySupportedClientAtProxy             = $false
            PreventTokenReplays                        = $false
            ExtendedProtectionTokenCheck               = 'Allow'
            ProxyTrustTokenLifetime                    = 21600
            ReplayCacheExpirationInterval              = 60
            SignedSamlRequestsRequired                 = $false
            SamlMessageDeliveryWindow                  = 5
            SignSamlAuthnRequests                      = $false
            SsoLifetime                                = 480
            PersistentSsoLifetimeMins                  = 129600
            KmsiLifetimeMins                           = 1440
            EnablePersistentSso                        = $true
            PersistentSsoCutoffTime                    = '01/01/0001 00:00:00'
            EnableKmsi                                 = $false
            WIASupportedUserAgents                     = 'MSAuthHost/1.0/In-Domain', 'MSIE 6.0', 'MSIE 7.0', 'MSIE 8.0', 'MSIE 9.0', 'MSIE 10.0', 'Trident/7.0', 'MSIPC', 'Windows Rights Management Client', 'MS_WorkFoldersClient', '=~Windows\s*NT.*Edge'
            BrowserSsoSupportedUserAgents              = 'Windows NT 1', 'Windows Phone 1'
            BrowserSsoEnabled                          = $true
            LoopDetectionTimeIntervalInSeconds         = 20
            LoopDetectionMaximumTokensIssuedInInterval = 5
            EnableLoopDetection                        = $true
            ExtranetLockoutMode                        = 'ADFSSmartLockoutLogOnly'
            ExtranetLockoutThreshold                   = '2147483647'
            ExtranetLockoutThresholdFamiliarLocation   = '2147483647'
            EnableExtranetLockout                      = $false
            ExtranetObservationWindow                  = '00:30:00'
            ExtranetLockoutRequirePDC                  = $true
            SendClientRequestIdAsQueryStringParameter  = $false
            GlobalRelyingPartyClaimsIssuancePolicy     = ''
            EnableLocalAuthenticationTypes             = $true
            EnableRelayStateForIdpInitiatedSignOn      = $false
            DelegateServiceAdministration              = 'contoso\adfsadmins'
            AllowSystemServiceAdministration           = $false
            AllowLocalAdminsServiceAdministration      = $true
            DeviceUsageWindowInDays                    = 7
            EnableIdPInitiatedSignonPage               = $false
            IgnoreTokenBinding                         = $false
            IdTokenIssuer                              = 'https://sts.contoso.com/adfs'
            PromptLoginFederation                      = 'FallbackToProtocolSpecificParameters'
            PromptLoginFallbackAuthenticationType      = 'urn:oasis:names:tc:SAML:1.0:am:password'
        }

        $mockChangedResource = @{
            AcceptableIdentifiers                      = 'Changed'
            AdditionalErrorPageInfo                    = 'None'
            ArtifactDbConnection                       = 'Data Source=np:\\.\pipe\microsoft##wid\tsql\query;Initial Catalog=AdfsArtifactStore;Integrated Security=False'
            AuditLevel                                 = 'None'
            AuthenticationContextOrder                 = 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport', 'urn:oasis:names:tc:SAML:2.0:ac:classes:TLSClient', 'urn:oasis:names:tc:SAML:2.0:ac:classes:X509', 'urn:federation:authentication:windows', 'urn:oasis:names:tc:SAML:2.0:ac:classes:Kerberos', 'urn:oasis:names:tc:SAML:2.0:ac:classes:Password'
            AutoCertificateRollover                    = $false
            CertificateCriticalThreshold               = 4
            CertificateDuration                        = 730
            CertificateGenerationThreshold             = 40
            CertificatePromotionThreshold              = 10
            CertificateRolloverInterval                = 14400
            CertificateThresholdMultiplier             = 2880
            EnableOAuthDeviceFlow                      = $false
            HostName                                   = 'sts.fabrikam.com'
            HttpPort                                   = 81
            HttpsPort                                  = 444
            IntranetUseLocalClaimsProvider             = $true
            TlsClientPort                              = 49444
            Identifier                                 = 'http://sts.fabrikam.com/adfs/services/trust'
            LogLevel                                   = 'Errors', 'FailureAudits', 'Information', 'SuccessAudits', 'Warnings', 'None'
            MonitoringInterval                         = 2880
            NetTcpPort                                 = 1502
            NtlmOnlySupportedClientAtProxy             = $true
            PreventTokenReplays                        = $true
            ExtendedProtectionTokenCheck               = 'None'
            ProxyTrustTokenLifetime                    = 21800
            ReplayCacheExpirationInterval              = 120
            SignedSamlRequestsRequired                 = $true
            SamlMessageDeliveryWindow                  = 10
            SignSamlAuthnRequests                      = $true
            SsoLifetime                                = 960
            PersistentSsoLifetimeMins                  = 129000
            KmsiLifetimeMins                           = 2880
            EnablePersistentSso                        = $false
            PersistentSsoCutoffTime                    = '01/01/1970 00:00:00'
            EnableKmsi                                 = $true
            WIASupportedUserAgents                     = 'MSAuthHost/1.0/In-Domain', 'MSIE 7.0', 'MSIE 8.0', 'MSIE 9.0', 'MSIE 10.0', 'Trident/7.0', 'MSIPC', 'Windows Rights Management Client', 'MS_WorkFoldersClient', '=~Windows\s*NT.*Edge'
            BrowserSsoSupportedUserAgents              = 'Windows NT 1'
            BrowserSsoEnabled                          = $false
            LoopDetectionTimeIntervalInSeconds         = 30
            LoopDetectionMaximumTokensIssuedInInterval = 10
            EnableLoopDetection                        = $false
            ExtranetLockoutMode                        = 'ADFSSmartLockoutEnforce'
            ExtranetLockoutThreshold                   = '5'
            ExtranetLockoutThresholdFamiliarLocation   = '5'
            EnableExtranetLockout                      = $true
            ExtranetObservationWindow                  = '01:00:00'
            ExtranetLockoutRequirePDC                  = $false
            SendClientRequestIdAsQueryStringParameter  = $true
            GlobalRelyingPartyClaimsIssuancePolicy     = 'NewPolicy'
            EnableLocalAuthenticationTypes             = $false
            EnableRelayStateForIdpInitiatedSignOn      = $true
            DelegateServiceAdministration              = 'fabrikam\adfsadmins'
            AllowSystemServiceAdministration           = $true
            AllowLocalAdminsServiceAdministration      = $false
            DeviceUsageWindowInDays                    = 14
            EnableIdPInitiatedSignonPage               = $true
            IgnoreTokenBinding                         = $true
            IdTokenIssuer                              = 'https://sts.fabrikam.com/adfs'
            PromptLoginFederation                      = 'Disabled'
            PromptLoginFallbackAuthenticationType      = 'urn:oasis:names:tc:SAML:1.0:am:password2'
        }

        $mockGetTargetResourceResult = @{
            FederationServiceName                      = $mockResource.FederationServiceName
            AcceptableIdentifiers                      = $mockResource.AcceptableIdentifiers
            AdditionalErrorPageInfo                    = $mockResource.AdditionalErrorPageInfo
            ArtifactDbConnection                       = $mockResource.ArtifactDbConnection
            AuditLevel                                 = $mockResource.AuditLevel
            AuthenticationContextOrder                 = $mockResource.AuthenticationContextOrder
            AutoCertificateRollover                    = $mockResource.AutoCertificateRollover
            CertificateCriticalThreshold               = $mockResource.CertificateCriticalThreshold
            CertificateDuration                        = $mockResource.CertificateDuration
            CertificateGenerationThreshold             = $mockResource.CertificateGenerationThreshold
            CertificatePromotionThreshold              = $mockResource.CertificatePromotionThreshold
            CertificateRolloverInterval                = $mockResource.CertificateRolloverInterval
            CertificateThresholdMultiplier             = $mockResource.CertificateThresholdMultiplier
            EnableOAuthDeviceFlow                      = $mockResource.EnableOAuthDeviceFlow
            HostName                                   = $mockResource.HostName
            HttpPort                                   = $mockResource.HttpPort
            HttpsPort                                  = $mockResource.HttpsPort
            IntranetUseLocalClaimsProvider             = $mockResource.IntranetUseLocalClaimsProvider
            TlsClientPort                              = $mockResource.TlsClientPort
            Identifier                                 = $mockResource.Identifier
            LogLevel                                   = $mockResource.LogLevel
            MonitoringInterval                         = $mockResource.MonitoringInterval
            NetTcpPort                                 = $mockResource.NetTcpPort
            NtlmOnlySupportedClientAtProxy             = $mockResource.NtlmOnlySupportedClientAtProxy
            PreventTokenReplays                        = $mockResource.PreventTokenReplays
            ExtendedProtectionTokenCheck               = $mockResource.ExtendedProtectionTokenCheck
            ProxyTrustTokenLifetime                    = $mockResource.ProxyTrustTokenLifetime
            ReplayCacheExpirationInterval              = $mockResource.ReplayCacheExpirationInterval
            SignedSamlRequestsRequired                 = $mockResource.SignedSamlRequestsRequired
            SamlMessageDeliveryWindow                  = $mockResource.SamlMessageDeliveryWindow
            SignSamlAuthnRequests                      = $mockResource.SignSamlAuthnRequests
            SsoLifetime                                = $mockResource.SsoLifetime
            PersistentSsoLifetimeMins                  = $mockResource.PersistentSsoLifetimeMins
            KmsiLifetimeMins                           = $mockResource.KmsiLifetimeMins
            EnablePersistentSso                        = $mockResource.EnablePersistentSso
            PersistentSsoCutoffTime                    = $mockResource.PersistentSsoCutoffTime
            EnableKmsi                                 = $mockResource.EnableKmsi
            WIASupportedUserAgents                     = $mockResource.WIASupportedUserAgents
            BrowserSsoSupportedUserAgents              = $mockResource.BrowserSsoSupportedUserAgents
            BrowserSsoEnabled                          = $mockResource.BrowserSsoEnabled
            LoopDetectionTimeIntervalInSeconds         = $mockResource.LoopDetectionTimeIntervalInSeconds
            LoopDetectionMaximumTokensIssuedInInterval = $mockResource.LoopDetectionMaximumTokensIssuedInInterval
            EnableLoopDetection                        = $mockResource.EnableLoopDetection
            ExtranetLockoutThreshold                   = $mockResource.ExtranetLockoutThreshold
            ExtranetLockoutThresholdFamiliarLocation   = $mockResource.ExtranetLockoutThresholdFamiliarLocation
            ExtranetLockoutMode                        = $mockResource.ExtranetLockoutMode
            EnableExtranetLockout                      = $mockResource.EnableExtranetLockout
            ExtranetObservationWindow                  = $mockResource.ExtranetObservationWindow
            ExtranetLockoutRequirePDC                  = $mockResource.ExtranetLockoutRequirePDC
            SendClientRequestIdAsQueryStringParameter  = $mockResource.SendClientRequestIdAsQueryStringParameter
            GlobalRelyingPartyClaimsIssuancePolicy     = $mockResource.GlobalRelyingPartyClaimsIssuancePolicy
            EnableLocalAuthenticationTypes             = $mockResource.EnableLocalAuthenticationTypes
            EnableRelayStateForIdpInitiatedSignOn      = $mockResource.EnableRelayStateForIdpInitiatedSignOn
            DelegateServiceAdministration              = $mockResource.DelegateServiceAdministration
            AllowSystemServiceAdministration           = $mockResource.AllowSystemServiceAdministration
            AllowLocalAdminsServiceAdministration      = $mockResource.AllowLocalAdminsServiceAdministration
            DeviceUsageWindowInDays                    = $mockResource.DeviceUsageWindowInDays
            EnableIdPInitiatedSignonPage               = $mockResource.EnableIdPInitiatedSignonPage
            IgnoreTokenBinding                         = $mockResource.IgnoreTokenBinding
            IdTokenIssuer                              = $mockResource.IdTokenIssuer
            PromptLoginFederation                      = $mockResource.PromptLoginFederation
            PromptLoginFallbackAuthenticationType      = $mockResource.PromptLoginFallbackAuthenticationType
        }

        Describe 'MSFT_AdfsProperties\Get-TargetResource' -Tag 'Get' {
            BeforeAll {
                $getTargetResourceParameters = @{
                    FederationServiceName = $mockResource.FederationServiceName
                }

                $mockGetResourceCommandResult = @{
                    FederationServiceName                      = $mockResource.FederationServiceName
                    AcceptableIdentifiers                      = $mockResource.AcceptableIdentifiers
                    AdditionalErrorPageInfo                    = $mockResource.AdditionalErrorPageInfo
                    ArtifactDbConnection                       = $mockResource.ArtifactDbConnection
                    AuthenticationContextOrder                 = $mockResource.AuthenticationContextOrder
                    AuditLevel                                 = $mockResource.AuditLevel
                    AutoCertificateRollover                    = $mockResource.AutoCertificateRollover
                    CertificateCriticalThreshold               = $mockResource.CertificateCriticalThreshold
                    CertificateDuration                        = $mockResource.CertificateDuration
                    CertificateGenerationThreshold             = $mockResource.CertificateGenerationThreshold
                    CertificatePromotionThreshold              = $mockResource.CertificatePromotionThreshold
                    CertificateRolloverInterval                = $mockResource.CertificateRolloverInterval
                    CertificateThresholdMultiplier             = $mockResource.CertificateThresholdMultiplier
                    IntranetUseLocalClaimsProvider             = $mockResource.IntranetUseLocalClaimsProvider
                    ExtendedProtectionTokenCheck               = $mockResource.ExtendedProtectionTokenCheck
                    HostName                                   = $mockResource.HostName
                    HttpPort                                   = $mockResource.HttpPort
                    HttpsPort                                  = $mockResource.HttpsPort
                    TlsClientPort                              = $mockResource.TlsClientPort
                    Identifier                                 = $mockResource.Identifier
                    IdTokenIssuer                              = $mockResource.IdTokenIssuer
                    LogLevel                                   = $mockResource.LogLevel
                    MonitoringInterval                         = $mockResource.MonitoringInterval
                    NetTcpPort                                 = $mockResource.NetTcpPort
                    NtlmOnlySupportedClientAtProxy             = $mockResource.NtlmOnlySupportedClientAtProxy
                    PreventTokenReplays                        = $mockResource.PreventTokenReplays
                    ProxyTrustTokenLifetime                    = $mockResource.ProxyTrustTokenLifetime
                    ReplayCacheExpirationInterval              = $mockResource.ReplayCacheExpirationInterval
                    SignedSamlRequestsRequired                 = $mockResource.SignedSamlRequestsRequired
                    SamlMessageDeliveryWindow                  = $mockResource.SamlMessageDeliveryWindow
                    SignSamlAuthnRequests                      = $mockResource.SignSamlAuthnRequests
                    SsoLifetime                                = $mockResource.SsoLifetime
                    PersistentSsoLifetimeMins                  = $mockResource.PersistentSsoLifetimeMins
                    KmsiLifetimeMins                           = $mockResource.KmsiLifetimeMins
                    PersistentSsoEnabled                       = $mockResource.EnablePersistentSso
                    PersistentSsoCutoffTime                    = $mockResource.PersistentSsoCutoffTime
                    KmsiEnabled                                = $mockResource.EnableKmsi
                    LoopDetectionEnabled                       = $mockResource.EnableLoopDetection
                    LoopDetectionTimeIntervalInSeconds         = $mockResource.LoopDetectionTimeIntervalInSeconds
                    LoopDetectionMaximumTokensIssuedInInterval = $mockResource.LoopDetectionMaximumTokensIssuedInInterval
                    SendClientRequestIdAsQueryStringParameter  = $mockResource.SendClientRequestIdAsQueryStringParameter
                    WIASupportedUserAgents                     = $mockResource.WIASupportedUserAgents
                    BrowserSsoSupportedUserAgents              = $mockResource.BrowserSsoSupportedUserAgents
                    ExtranetLockoutThreshold                   = $mockResource.ExtranetLockoutThreshold
                    ExtranetLockoutThresholdFamiliarLocation   = $mockResource.ExtranetLockoutThresholdFamiliarLocation
                    ExtranetLockoutEnabled                     = $mockResource.EnableExtranetLockout
                    ExtranetLockoutMode                        = $mockResource.ExtranetLockoutMode
                    ExtranetObservationWindow                  = $mockResource.ExtranetObservationWindow
                    GlobalRelyingPartyClaimsIssuancePolicy     = $mockResource.GlobalRelyingPartyClaimsIssuancePolicy
                    ExtranetLockoutRequirePDC                  = $mockResource.ExtranetLockoutRequirePDC
                    LocalAuthenticationTypesEnabled            = $mockResource.EnableLocalAuthenticationTypes
                    RelayStateForIdpInitiatedSignOnEnabled     = $mockResource.EnableRelayStateForIdpInitiatedSignOn
                    BrowserSsoEnabled                          = $mockResource.BrowserSsoEnabled
                    DelegateServiceAdministration              = $mockResource.DelegateServiceAdministration
                    AllowSystemServiceAdministration           = $mockResource.AllowSystemServiceAdministration
                    AllowLocalAdminsServiceAdministration      = $mockResource.AllowLocalAdminsServiceAdministration
                    DeviceUsageWindowInDays                    = $mockResource.DeviceUsageWindowInDays
                    EnableIdpInitiatedSignonPage               = $mockResource.EnableIdpInitiatedSignonPage
                    IgnoreTokenBinding                         = $mockResource.IgnoreTokenBinding
                    EnableOauthDeviceFlow                      = $mockResource.EnableOauthDeviceFlow
                    PromptLoginFederation                      = $mockResource.PromptLoginFederation
                    PromptLoginFallbackAuthenticationType      = $mockResource.PromptLoginFallbackAuthenticationType
                }

                Mock -CommandName Assert-Module
                Mock -CommandName "Assert-$($Global:PSModuleName)Service"
                Mock -CommandName $ResourceCommand.Get -MockWith { $mockGetResourceCommandResult }

                $result = Get-TargetResource @getTargetResourceParameters
            }

            foreach ($property in $mockResource.Keys)
            {
                It "Should return the correct $property property" {
                    $result.$property | Should -Be $mockResource.$property
                }
            }

            It 'Should call the expected mocks' {
                Assert-MockCalled -CommandName Assert-Module `
                    -ParameterFilter { $ModuleName -eq $Global:PSModuleName } `
                    -Exactly -Times 1
                Assert-MockCalled -CommandName "Assert-$($Global:PSModuleName)Service" -Exactly -Times 1
                Assert-MockCalled -CommandName $ResourceCommand.Get -Exactly -Times 1
            }

            Context "When $($ResourceCommand.Get) throws an exception" {
                BeforeAll {
                    Mock -CommandName $ResourceCommand.Get -MockWith { Throw 'Error' }
                }

                It 'Should throw the correct exception' {
                    { Get-TargetResource @getTargetResourceParameters } | Should -Throw (
                        $script:localizedData.GettingResourceErrorMessage -f $getTargetResourceParameters.FederationServiceName )
                }
            }
        }

        Describe 'MSFT_AdfsProperties\Set-TargetResource' -Tag 'Set' {
            BeforeAll {
                $setTargetResourceParameters = @{
                    FederationServiceName                      = $mockResource.FederationServiceName
                    AuthenticationContextOrder                 = $mockResource.AuthenticationContextOrder
                    AcceptableIdentifiers                      = $mockResource.AcceptableIdentifiers
                    ArtifactDbConnection                       = $mockResource.ArtifactDbConnection
                    AuditLevel                                 = $mockResource.AuditLevel
                    AutoCertificateRollover                    = $mockResource.AutoCertificateRollover
                    CertificateCriticalThreshold               = $mockResource.CertificateCriticalThreshold
                    CertificateDuration                        = $mockResource.CertificateDuration
                    CertificateGenerationThreshold             = $mockResource.CertificateGenerationThreshold
                    CertificatePromotionThreshold              = $mockResource.CertificatePromotionThreshold
                    CertificateRolloverInterval                = $mockResource.CertificateRolloverInterval
                    CertificateThresholdMultiplier             = $mockResource.CertificateThresholdMultiplier
                    EnableOAuthDeviceFlow                      = $mockResource.EnableOAuthDeviceFlow
                    HostName                                   = $mockResource.HostName
                    HttpPort                                   = $mockResource.HttpPort
                    HttpsPort                                  = $mockResource.HttpsPort
                    IntranetUseLocalClaimsProvider             = $mockResource.IntranetUseLocalClaimsProvider
                    TlsClientPort                              = $mockResource.TlsClientPort
                    Identifier                                 = $mockResource.Identifier
                    LogLevel                                   = $mockResource.LogLevel
                    MonitoringInterval                         = $mockResource.MonitoringInterval
                    NetTcpPort                                 = $mockResource.NetTcpPort
                    NtlmOnlySupportedClientAtProxy             = $mockResource.NtlmOnlySupportedClientAtProxy
                    PreventTokenReplays                        = $mockResource.PreventTokenReplays
                    ExtendedProtectionTokenCheck               = $mockResource.ExtendedProtectionTokenCheck
                    ProxyTrustTokenLifetime                    = $mockResource.ProxyTrustTokenLifetime
                    ReplayCacheExpirationInterval              = $mockResource.ReplayCacheExpirationInterval
                    SignedSamlRequestsRequired                 = $mockResource.SignedSamlRequestsRequired
                    SamlMessageDeliveryWindow                  = $mockResource.SamlMessageDeliveryWindow
                    SignSamlAuthnRequests                      = $mockResource.SignSamlAuthnRequests
                    SsoLifetime                                = $mockResource.SsoLifetime
                    PersistentSsoLifetimeMins                  = $mockResource.PersistentSsoLifetimeMins
                    KmsiLifetimeMins                           = $mockResource.KmsiLifetimeMins
                    EnablePersistentSso                        = $mockResource.EnablePersistentSso
                    PersistentSsoCutoffTime                    = $mockResource.PersistentSsoCutoffTime
                    EnableKmsi                                 = $mockResource.EnableKmsi
                    WIASupportedUserAgents                     = $mockResource.WIASupportedUserAgents
                    BrowserSsoSupportedUserAgents              = $mockResource.BrowserSsoSupportedUserAgents
                    BrowserSsoEnabled                          = $mockResource.BrowserSsoEnabled
                    LoopDetectionTimeIntervalInSeconds         = $mockResource.LoopDetectionTimeIntervalInSeconds
                    LoopDetectionMaximumTokensIssuedInInterval = $mockResource.LoopDetectionMaximumTokensIssuedInInterval
                    EnableLoopDetection                        = $mockResource.EnableLoopDetection
                    ExtranetLockoutThreshold                   = $mockResource.ExtranetLockoutThreshold
                    EnableExtranetLockout                      = $mockResource.EnableExtranetLockout
                    ExtranetObservationWindow                  = $mockResource.ExtranetObservationWindow
                    ExtranetLockoutRequirePDC                  = $mockResource.ExtranetLockoutRequirePDC
                    SendClientRequestIdAsQueryStringParameter  = $mockResource.SendClientRequestIdAsQueryStringParameter
                    GlobalRelyingPartyClaimsIssuancePolicy     = $mockResource.GlobalRelyingPartyClaimsIssuancePolicy
                    EnableLocalAuthenticationTypes             = $mockResource.EnableLocalAuthenticationTypes
                    EnableRelayStateForIdpInitiatedSignOn      = $mockResource.EnableRelayStateForIdpInitiatedSignOn
                    DelegateServiceAdministration              = $mockResource.DelegateServiceAdministration
                    AllowSystemServiceAdministration           = $mockResource.AllowSystemServiceAdministration
                    AllowLocalAdminsServiceAdministration      = $mockResource.AllowLocalAdminsServiceAdministration
                    DeviceUsageWindowInDays                    = $mockResource.DeviceUsageWindowInDays
                    EnableIdPInitiatedSignonPage               = $mockResource.EnableIdPInitiatedSignonPage
                    IgnoreTokenBinding                         = $mockResource.IgnoreTokenBinding
                    IdTokenIssuer                              = $mockResource.IdTokenIssuer
                    PromptLoginFederation                      = $mockResource.PromptLoginFederation
                    PromptLoginFallbackAuthenticationType      = $mockResource.PromptLoginFallbackAuthenticationType
                }

                Mock -CommandName $ResourceCommand.Set
                Mock -CommandName Get-TargetResource -MockWith { $mockGetTargetResourceResult }
            }

            foreach ($property in $mockChangedResource.Keys)
            {
                Context "When $property has changed" {
                    BeforeAll {
                        $setTargetResourceParametersChangedProperty = $setTargetResourceParameters.Clone()
                        $setTargetResourceParametersChangedProperty.$property = $mockChangedResource.$property
                    }

                    It 'Should not throw' {
                        { Set-TargetResource @setTargetResourceParametersChangedProperty } | Should -Not -Throw
                    }

                    It 'Should call the correct mocks' {
                        Assert-MockCalled -CommandName Get-TargetResource `
                            -ParameterFilter { `
                                $FederationServiceName -eq $setTargetResourceParametersChangedProperty.FederationServiceName } `
                            -Exactly -Times 1
                        Assert-MockCalled -CommandName $ResourceCommand.Set -Exactly -Times 1
                    }
                }
            }

            Context "When $($ResourceCommand.Set) throws an exception" {
                BeforeAll {
                    Mock -CommandName $ResourceCommand.Set -MockWith { Throw 'Error' }
                }

                It 'Should throw the correct exception' {
                    { Set-TargetResource @setTargetResourceParameters } | Should -Throw (
                        $script:localizedData.SettingResourceErrorMessage -f $setTargetResourceParameters.FederationServiceName )
                }
            }
        }

        Describe 'MSFT_AdfsProperties\Test-TargetResource' -Tag 'Test' {
            BeforeAll {
                $testTargetResourceParameters = @{
                    FederationServiceName = $mockResource.FederationServiceName
                }

                Mock -CommandName Get-TargetResource -MockWith { $mockGetTargetResourceResult }
            }

            It 'Should not throw' {
                { Test-TargetResource @testTargetResourceParameters } | Should -Not -Throw
            }

            It 'Should call the expected mocks' {
                Assert-MockCalled -CommandName Get-TargetResource `
                    -ParameterFilter { $FederationServiceName -eq $testTargetResourceParameters.FederationServiceName } `
                    -Exactly -Times 1
            }

            Context 'When all the resource properties are in the desired state' {
                It 'Should return $true' {
                    Test-TargetResource @testTargetResourceParameters | Should -Be $true
                }
            }

            foreach ($property in $mockChangedResource.Keys)
            {
                Context "When the $property resource property is not in the desired state" {
                    BeforeAll {
                        $testTargetResourceNotInDesiredStateParameters = $testTargetResourceParameters.Clone()
                        $testTargetResourceNotInDesiredStateParameters.$property = $mockChangedResource.$property
                    }

                    It 'Should return $false' {
                        Test-TargetResource @testTargetResourceNotInDesiredStateParameters | Should -Be $false
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
