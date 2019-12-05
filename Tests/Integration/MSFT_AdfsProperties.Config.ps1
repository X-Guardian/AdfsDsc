<#
    .SYNOPSIS
        AdfsProperties DSC Resource Integration Test Configuration
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
        AllNodes              = @(
            @{
                NodeName        = 'localhost'
                CertificateFile = $env:DscPublicCertificatePath
            }
        )
        FederationServiceName = 'sts.contoso.com'
        AdfsPropertiesInit     = @{
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
            LogLevel                                   = 'Errors', 'FailureAudits', 'Information', 'Verbose', 'SuccessAudits', 'Warnings'
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
            DelegateServiceAdministration              = $null
            AllowSystemServiceAdministration           = $false
            AllowLocalAdminsServiceAdministration      = $true
            DeviceUsageWindowInDays                    = 7
            EnableIdPInitiatedSignonPage               = $false
            IgnoreTokenBinding                         = $false
            IdTokenIssuer                              = 'https://sts.contoso.com/adfs'
        }
        AdfsProperties     = @{
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
            LogLevel                                   = 'Errors', 'FailureAudits', 'Information', 'SuccessAudits', 'Warnings'
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
            EnablePersistentSso                        = $true
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
            GlobalRelyingPartyClaimsIssuancePolicy     = ''
            EnableLocalAuthenticationTypes             = $false
            EnableRelayStateForIdpInitiatedSignOn      = $true
            DelegateServiceAdministration              = $null
            AllowSystemServiceAdministration           = $true
            AllowLocalAdminsServiceAdministration      = $false
            DeviceUsageWindowInDays                    = 14
            EnableIdPInitiatedSignonPage               = $true
            IgnoreTokenBinding                         = $true
            IdTokenIssuer                              = 'https://sts.fabrikam.com/adfs'
        }
    }
}

Configuration MSFT_AdfsProperties_Init_Config
{
    <#
        .SYNOPSIS
            Initialises the Integration test resources
    #>

    Import-DscResource -ModuleName 'AdfsDsc'

    node $AllNodes.NodeName
    {
        AdfsProperties 'Integration_Test'
        {
            FederationServiceName                      = $ConfigurationData.FederationServiceName
            AcceptableIdentifiers                      = $ConfigurationData.AdfsPropertiesInit.AcceptableIdentifiers
            AdditionalErrorPageInfo                    = $ConfigurationData.AdfsPropertiesInit.AdditionalErrorPageInfo
            ArtifactDbConnection                       = $ConfigurationData.AdfsPropertiesInit.ArtifactDbConnection
            AuditLevel                                 = $ConfigurationData.AdfsPropertiesInit.AuditLevel
            AuthenticationContextOrder                 = $ConfigurationData.AdfsPropertiesInit.AuthenticationContextOrder
            AutoCertificateRollover                    = $ConfigurationData.AdfsPropertiesInit.AutoCertificateRollover
            CertificateCriticalThreshold               = $ConfigurationData.AdfsPropertiesInit.CertificateCriticalThreshold
            CertificateDuration                        = $ConfigurationData.AdfsPropertiesInit.CertificateDuration
            CertificateGenerationThreshold             = $ConfigurationData.AdfsPropertiesInit.CertificateGenerationThreshold
            CertificatePromotionThreshold              = $ConfigurationData.AdfsPropertiesInit.CertificatePromotionThreshold
            CertificateRolloverInterval                = $ConfigurationData.AdfsPropertiesInit.CertificateRolloverInterval
            CertificateThresholdMultiplier             = $ConfigurationData.AdfsPropertiesInit.CertificateThresholdMultiplier
            EnableOAuthDeviceFlow                      = $ConfigurationData.AdfsPropertiesInit.EnableOAuthDeviceFlow
            HostName                                   = $ConfigurationData.AdfsPropertiesInit.HostName
            HttpPort                                   = $ConfigurationData.AdfsPropertiesInit.HttpPort
            HttpsPort                                  = $ConfigurationData.AdfsPropertiesInit.HttpsPort
            IntranetUseLocalClaimsProvider             = $ConfigurationData.AdfsPropertiesInit.IntranetUseLocalClaimsProvider
            TlsClientPort                              = $ConfigurationData.AdfsPropertiesInit.TlsClientPort
            Identifier                                 = $ConfigurationData.AdfsPropertiesInit.Identifier
            LogLevel                                   = $ConfigurationData.AdfsPropertiesInit.LogLevel
            MonitoringInterval                         = $ConfigurationData.AdfsPropertiesInit.MonitoringInterval
            NetTcpPort                                 = $ConfigurationData.AdfsPropertiesInit.NetTcpPort
            NtlmOnlySupportedClientAtProxy             = $ConfigurationData.AdfsPropertiesInit.NtlmOnlySupportedClientAtProxy
            PreventTokenReplays                        = $ConfigurationData.AdfsPropertiesInit.PreventTokenReplays
            ExtendedProtectionTokenCheck               = $ConfigurationData.AdfsPropertiesInit.ExtendedProtectionTokenCheck
            ProxyTrustTokenLifetime                    = $ConfigurationData.AdfsPropertiesInit.ProxyTrustTokenLifetime
            ReplayCacheExpirationInterval              = $ConfigurationData.AdfsPropertiesInit.ReplayCacheExpirationInterval
            SignedSamlRequestsRequired                 = $ConfigurationData.AdfsPropertiesInit.SignedSamlRequestsRequired
            SamlMessageDeliveryWindow                  = $ConfigurationData.AdfsPropertiesInit.SamlMessageDeliveryWindow
            SignSamlAuthnRequests                      = $ConfigurationData.AdfsPropertiesInit.SignSamlAuthnRequests
            SsoLifetime                                = $ConfigurationData.AdfsPropertiesInit.SsoLifetime
            PersistentSsoLifetimeMins                  = $ConfigurationData.AdfsPropertiesInit.PersistentSsoLifetimeMins
            KmsiLifetimeMins                           = $ConfigurationData.AdfsPropertiesInit.KmsiLifetimeMins
            EnablePersistentSso                        = $ConfigurationData.AdfsPropertiesInit.EnablePersistentSso
            PersistentSsoCutoffTime                    = $ConfigurationData.AdfsPropertiesInit.PersistentSsoCutoffTime
            EnableKmsi                                 = $ConfigurationData.AdfsPropertiesInit.EnableKmsi
            WIASupportedUserAgents                     = $ConfigurationData.AdfsPropertiesInit.WIASupportedUserAgents
            BrowserSsoSupportedUserAgents              = $ConfigurationData.AdfsPropertiesInit.BrowserSsoSupportedUserAgents
            BrowserSsoEnabled                          = $ConfigurationData.AdfsPropertiesInit.BrowserSsoEnabled
            LoopDetectionTimeIntervalInSeconds         = $ConfigurationData.AdfsPropertiesInit.LoopDetectionTimeIntervalInSeconds
            LoopDetectionMaximumTokensIssuedInInterval = $ConfigurationData.AdfsPropertiesInit.LoopDetectionMaximumTokensIssuedInInterval
            EnableLoopDetection                        = $ConfigurationData.AdfsPropertiesInit.EnableLoopDetection
            ExtranetLockoutMode                        = $ConfigurationData.AdfsPropertiesInit.ExtranetLockoutMode
            ExtranetLockoutThreshold                   = $ConfigurationData.AdfsPropertiesInit.ExtranetLockoutThreshold
            ExtranetLockoutThresholdFamiliarLocation   = $ConfigurationData.AdfsPropertiesInit.ExtranetLockoutThresholdFamiliarLocation
            EnableExtranetLockout                      = $ConfigurationData.AdfsPropertiesInit.EnableExtranetLockout
            ExtranetObservationWindow                  = $ConfigurationData.AdfsPropertiesInit.ExtranetObservationWindow
            ExtranetLockoutRequirePDC                  = $ConfigurationData.AdfsPropertiesInit.ExtranetLockoutRequirePDC
            SendClientRequestIdAsQueryStringParameter  = $ConfigurationData.AdfsPropertiesInit.SendClientRequestIdAsQueryStringParameter
            GlobalRelyingPartyClaimsIssuancePolicy     = $ConfigurationData.AdfsPropertiesInit.GlobalRelyingPartyClaimsIssuancePolicy
            EnableLocalAuthenticationTypes             = $ConfigurationData.AdfsPropertiesInit.EnableLocalAuthenticationTypes
            EnableRelayStateForIdpInitiatedSignOn      = $ConfigurationData.AdfsPropertiesInit.EnableRelayStateForIdpInitiatedSignOn
            DelegateServiceAdministration              = $ConfigurationData.AdfsPropertiesInit.DelegateServiceAdministration
            AllowSystemServiceAdministration           = $ConfigurationData.AdfsPropertiesInit.AllowSystemServiceAdministration
            AllowLocalAdminsServiceAdministration      = $ConfigurationData.AdfsPropertiesInit.AllowLocalAdminsServiceAdministration
            DeviceUsageWindowInDays                    = $ConfigurationData.AdfsPropertiesInit.DeviceUsageWindowInDays
            EnableIdPInitiatedSignonPage               = $ConfigurationData.AdfsPropertiesInit.EnableIdPInitiatedSignonPage
            IgnoreTokenBinding                         = $ConfigurationData.AdfsPropertiesInit.IgnoreTokenBinding
            IdTokenIssuer                              = $ConfigurationData.AdfsPropertiesInit.IdTokenIssuer
        }
    }
}

Configuration MSFT_AdfsProperties_Config
{
    <#
        .SYNOPSIS
            Manages an ADFS Global Authentication Policy
    #>

    Import-DscResource -ModuleName 'AdfsDsc'

    node $AllNodes.NodeName
    {
        AdfsProperties 'Integration_Test'
        {
            FederationServiceName                      = $ConfigurationData.FederationServiceName
            AcceptableIdentifiers                      = $ConfigurationData.AdfsProperties.AcceptableIdentifiers
            AdditionalErrorPageInfo                    = $ConfigurationData.AdfsProperties.AdditionalErrorPageInfo
            ArtifactDbConnection                       = $ConfigurationData.AdfsProperties.ArtifactDbConnection
            AuditLevel                                 = $ConfigurationData.AdfsProperties.AuditLevel
            AuthenticationContextOrder                 = $ConfigurationData.AdfsProperties.AuthenticationContextOrder
            AutoCertificateRollover                    = $ConfigurationData.AdfsProperties.AutoCertificateRollover
            CertificateCriticalThreshold               = $ConfigurationData.AdfsProperties.CertificateCriticalThreshold
            CertificateDuration                        = $ConfigurationData.AdfsProperties.CertificateDuration
            CertificateGenerationThreshold             = $ConfigurationData.AdfsProperties.CertificateGenerationThreshold
            CertificatePromotionThreshold              = $ConfigurationData.AdfsProperties.CertificatePromotionThreshold
            CertificateRolloverInterval                = $ConfigurationData.AdfsProperties.CertificateRolloverInterval
            CertificateThresholdMultiplier             = $ConfigurationData.AdfsProperties.CertificateThresholdMultiplier
            EnableOAuthDeviceFlow                      = $ConfigurationData.AdfsProperties.EnableOAuthDeviceFlow
            HostName                                   = $ConfigurationData.AdfsProperties.HostName
            HttpPort                                   = $ConfigurationData.AdfsProperties.HttpPort
            HttpsPort                                  = $ConfigurationData.AdfsProperties.HttpsPort
            IntranetUseLocalClaimsProvider             = $ConfigurationData.AdfsProperties.IntranetUseLocalClaimsProvider
            TlsClientPort                              = $ConfigurationData.AdfsProperties.TlsClientPort
            Identifier                                 = $ConfigurationData.AdfsProperties.Identifier
            LogLevel                                   = $ConfigurationData.AdfsProperties.LogLevel
            MonitoringInterval                         = $ConfigurationData.AdfsProperties.MonitoringInterval
            NetTcpPort                                 = $ConfigurationData.AdfsProperties.NetTcpPort
            NtlmOnlySupportedClientAtProxy             = $ConfigurationData.AdfsProperties.NtlmOnlySupportedClientAtProxy
            PreventTokenReplays                        = $ConfigurationData.AdfsProperties.PreventTokenReplays
            ExtendedProtectionTokenCheck               = $ConfigurationData.AdfsProperties.ExtendedProtectionTokenCheck
            ProxyTrustTokenLifetime                    = $ConfigurationData.AdfsProperties.ProxyTrustTokenLifetime
            ReplayCacheExpirationInterval              = $ConfigurationData.AdfsProperties.ReplayCacheExpirationInterval
            SignedSamlRequestsRequired                 = $ConfigurationData.AdfsProperties.SignedSamlRequestsRequired
            SamlMessageDeliveryWindow                  = $ConfigurationData.AdfsProperties.SamlMessageDeliveryWindow
            SignSamlAuthnRequests                      = $ConfigurationData.AdfsProperties.SignSamlAuthnRequests
            SsoLifetime                                = $ConfigurationData.AdfsProperties.SsoLifetime
            PersistentSsoLifetimeMins                  = $ConfigurationData.AdfsProperties.PersistentSsoLifetimeMins
            KmsiLifetimeMins                           = $ConfigurationData.AdfsProperties.KmsiLifetimeMins
            EnablePersistentSso                        = $ConfigurationData.AdfsProperties.EnablePersistentSso
            PersistentSsoCutoffTime                    = $ConfigurationData.AdfsProperties.PersistentSsoCutoffTime
            EnableKmsi                                 = $ConfigurationData.AdfsProperties.EnableKmsi
            WIASupportedUserAgents                     = $ConfigurationData.AdfsProperties.WIASupportedUserAgents
            BrowserSsoSupportedUserAgents              = $ConfigurationData.AdfsProperties.BrowserSsoSupportedUserAgents
            BrowserSsoEnabled                          = $ConfigurationData.AdfsProperties.BrowserSsoEnabled
            LoopDetectionTimeIntervalInSeconds         = $ConfigurationData.AdfsProperties.LoopDetectionTimeIntervalInSeconds
            LoopDetectionMaximumTokensIssuedInInterval = $ConfigurationData.AdfsProperties.LoopDetectionMaximumTokensIssuedInInterval
            EnableLoopDetection                        = $ConfigurationData.AdfsProperties.EnableLoopDetection
            ExtranetLockoutMode                        = $ConfigurationData.AdfsProperties.ExtranetLockoutMode
            ExtranetLockoutThreshold                   = $ConfigurationData.AdfsProperties.ExtranetLockoutThreshold
            ExtranetLockoutThresholdFamiliarLocation   = $ConfigurationData.AdfsProperties.ExtranetLockoutThresholdFamiliarLocation
            EnableExtranetLockout                      = $ConfigurationData.AdfsProperties.EnableExtranetLockout
            ExtranetObservationWindow                  = $ConfigurationData.AdfsProperties.ExtranetObservationWindow
            ExtranetLockoutRequirePDC                  = $ConfigurationData.AdfsProperties.ExtranetLockoutRequirePDC
            SendClientRequestIdAsQueryStringParameter  = $ConfigurationData.AdfsProperties.SendClientRequestIdAsQueryStringParameter
            GlobalRelyingPartyClaimsIssuancePolicy     = $ConfigurationData.AdfsProperties.GlobalRelyingPartyClaimsIssuancePolicy
            EnableLocalAuthenticationTypes             = $ConfigurationData.AdfsProperties.EnableLocalAuthenticationTypes
            EnableRelayStateForIdpInitiatedSignOn      = $ConfigurationData.AdfsProperties.EnableRelayStateForIdpInitiatedSignOn
            DelegateServiceAdministration              = $ConfigurationData.AdfsProperties.DelegateServiceAdministration
            AllowSystemServiceAdministration           = $ConfigurationData.AdfsProperties.AllowSystemServiceAdministration
            AllowLocalAdminsServiceAdministration      = $ConfigurationData.AdfsProperties.AllowLocalAdminsServiceAdministration
            DeviceUsageWindowInDays                    = $ConfigurationData.AdfsProperties.DeviceUsageWindowInDays
            EnableIdPInitiatedSignonPage               = $ConfigurationData.AdfsProperties.EnableIdPInitiatedSignonPage
            IgnoreTokenBinding                         = $ConfigurationData.AdfsProperties.IgnoreTokenBinding
            IdTokenIssuer                              = $ConfigurationData.AdfsProperties.IdTokenIssuer
        }
    }
}
