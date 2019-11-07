# These suppresses rules PsScriptAnalyzer may catch in stub functions.
[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingUserNameAndPassWordParams', '')]
[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '')]
[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUsePSCredentialType', '')]
[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]

[CmdletBinding()]
param ()

    <#
    .SYNOPSIS
        This is the stub cmdlets for module: ADFS, version: 1.0.0.0 which can be used in
        Pester unit tests to be able to test code without having the actual module installed.

    .NOTES
        CreatedOn: 2019-09-19 07:27:51Z
    #>

Add-Type -IgnoreWarnings -TypeDefinition @'
namespace Microsoft.IdentityServer.Management.Commands
{
    public enum DebugLogConsumer : int
    {
        FileShare = 0,
        Email = 1,
    }

    public enum LockoutLocation : int
    {
        Unknown = 0,
        Familiar = 1,
    }

}

namespace Microsoft.IdentityServer.Management.Resources
{
    public class AdfsAccessControlPolicy
    {
        // Property
        public System.String Name { get; set; }
        public System.String Identifier { get; set; }
        public System.Boolean IsBuiltIn { get; set; }
        public System.Int32 RpUsageCount { get; set; }
        public System.Nullable<System.DateTime> LastUpdateTime { get; set; }
        public System.String Description { get; set; }
        public Microsoft.IdentityServer.PolicyModel.Configuration.PolicyTemplate.PolicyMetadata PolicyMetadata { get; set; }
        public System.Collections.ObjectModel.ReadOnlyCollection<System.String> AssignedTo { get; set; }

        // Fabricated constructor
        private AdfsAccessControlPolicy() { }
        public static AdfsAccessControlPolicy CreateTypeInstance()
        {
            return new AdfsAccessControlPolicy();
        }
    }

    public class AdfsAuthProviderWebContent
    {
        // Property
        public System.Globalization.CultureInfo Locale { get; set; }
        public System.String Name { get; set; }
        public System.String DisplayName { get; set; }
        public System.String Description { get; set; }
        public System.String UserNotProvisionedErrorMessage { get; set; }

        // Fabricated constructor
        private AdfsAuthProviderWebContent() { }
        public static AdfsAuthProviderWebContent CreateTypeInstance()
        {
            return new AdfsAuthProviderWebContent();
        }
    }

    public class AdfsClient
    {
        // Property
        public System.String[] RedirectUri { get; set; }
        public System.String Name { get; set; }
        public System.String Description { get; set; }
        public System.String ClientId { get; set; }
        public System.Boolean BuiltIn { get; set; }
        public System.Boolean Enabled { get; set; }
        public Microsoft.IdentityServer.Protocols.PolicyStore.ClientType ClientType { get; set; }
        public System.String ADUserPrincipalName { get; set; }
        public System.String ClientSecret { get; set; }
        public System.String LogoutUri { get; set; }
        public Microsoft.IdentityServer.PolicyModel.Configuration.RevocationSetting JWTSigningCertificateRevocationCheck { get; set; }
        public System.Collections.Generic.IDictionary<System.String,System.Object> JWTSigningKeys { get; set; }
        public System.Uri JWKSUri { get; set; }

        // Fabricated constructor
        private AdfsClient() { }
        public static AdfsClient CreateTypeInstance()
        {
            return new AdfsClient();
        }
    }

    public class AdfsGlobalWebContent
    {
        // Property
        public System.String SignOutPageDescriptionText { get; set; }
        public System.String UpdatePasswordPageDescriptionText { get; set; }
        public System.Globalization.CultureInfo Locale { get; set; }
        public System.String CompanyName { get; set; }
        public System.String CertificatePageDescriptionText { get; set; }
        public System.String ErrorPageDescriptionText { get; set; }
        public System.String ErrorPageGenericErrorMessage { get; set; }
        public System.String ErrorPageAuthorizationErrorMessage { get; set; }
        public System.String ErrorPageDeviceAuthenticationErrorMessage { get; set; }
        public System.String ErrorPageSupportEmail { get; set; }
        public System.Uri HelpDeskLink { get; set; }
        public System.String HelpDeskLinkText { get; set; }
        public System.Uri HomeLink { get; set; }
        public System.String HomeLinkText { get; set; }
        public System.String HomeRealmDiscoveryOtherOrganizationDescriptionText { get; set; }
        public System.String HomeRealmDiscoveryPageDescriptionText { get; set; }
        public System.String OrganizationalNameDescriptionText { get; set; }
        public System.Uri PrivacyLink { get; set; }
        public System.String PrivacyLinkText { get; set; }
        public System.String SignInPageDescriptionText { get; set; }
        public System.String SignInPageAdditionalAuthenticationDescriptionText { get; set; }

        // Fabricated constructor
        private AdfsGlobalWebContent() { }
        public static AdfsGlobalWebContent CreateTypeInstance()
        {
            return new AdfsGlobalWebContent();
        }
    }

    public class AdfsRelyingPartyWebContent
    {
        // Property
        public System.String Name { get; set; }
        public System.Globalization.CultureInfo Locale { get; set; }
        public System.String CompanyName { get; set; }
        public System.String CertificatePageDescriptionText { get; set; }
        public System.String ErrorPageDescriptionText { get; set; }
        public System.String ErrorPageGenericErrorMessage { get; set; }
        public System.String ErrorPageAuthorizationErrorMessage { get; set; }
        public System.String ErrorPageDeviceAuthenticationErrorMessage { get; set; }
        public System.String ErrorPageSupportEmail { get; set; }
        public System.Uri HelpDeskLink { get; set; }
        public System.String HelpDeskLinkText { get; set; }
        public System.Uri HomeLink { get; set; }
        public System.String HomeLinkText { get; set; }
        public System.String HomeRealmDiscoveryOtherOrganizationDescriptionText { get; set; }
        public System.String HomeRealmDiscoveryPageDescriptionText { get; set; }
        public System.String OrganizationalNameDescriptionText { get; set; }
        public System.Uri PrivacyLink { get; set; }
        public System.String PrivacyLinkText { get; set; }
        public System.String SignInPageDescriptionText { get; set; }
        public System.String SignInPageAdditionalAuthenticationDescriptionText { get; set; }

        // Fabricated constructor
        private AdfsRelyingPartyWebContent() { }
        public static AdfsRelyingPartyWebContent CreateTypeInstance()
        {
            return new AdfsRelyingPartyWebContent();
        }
    }

    public class AdfsRelyingPartyWebTheme
    {
        // Property
        public System.String Name { get; set; }
        public System.Collections.Generic.IDictionary<System.Globalization.CultureInfo,System.Byte[]> StyleSheet { get; set; }
        public System.Byte[] RTLStyleSheet { get; set; }
        public System.Byte[] OnLoadScript { get; set; }
        public System.Collections.Generic.IDictionary<System.Globalization.CultureInfo,System.Byte[]> Logo { get; set; }
        public System.Collections.Generic.IDictionary<System.Globalization.CultureInfo,System.Byte[]> Illustration { get; set; }

        // Fabricated constructor
        private AdfsRelyingPartyWebTheme() { }
        public static AdfsRelyingPartyWebTheme CreateTypeInstance()
        {
            return new AdfsRelyingPartyWebTheme();
        }
    }

    public class AdfsTrustedFederationPartner
    {
        // Property
        public System.String Name { get; set; }
        public System.Uri FederationPartnerHostName { get; set; }

        // Fabricated constructor
        private AdfsTrustedFederationPartner() { }
        public static AdfsTrustedFederationPartner CreateTypeInstance()
        {
            return new AdfsTrustedFederationPartner();
        }
    }

    public class AdfsWebTheme
    {
        // Property
        public System.String Name { get; set; }
        public System.Boolean IsBuiltinTheme { get; set; }
        public System.Collections.Generic.IDictionary<System.Globalization.CultureInfo,System.Byte[]> StyleSheet { get; set; }
        public System.Byte[] RTLStyleSheet { get; set; }
        public System.Byte[] OnLoadScript { get; set; }
        public System.Collections.Generic.IDictionary<System.Globalization.CultureInfo,System.Byte[]> Logo { get; set; }
        public System.Collections.Generic.IDictionary<System.Globalization.CultureInfo,System.Byte[]> Illustration { get; set; }
        public System.Collections.Generic.IDictionary<System.String,System.Byte[]> AdditionalFileResources { get; set; }

        // Fabricated constructor
        private AdfsWebTheme() { }
        public static AdfsWebTheme CreateTypeInstance()
        {
            return new AdfsWebTheme();
        }
    }

    public class ApplicationGroup
    {
        // Property
        public System.String ApplicationGroupIdentifier { get; set; }
        public System.String Description { get; set; }
        public System.String Name { get; set; }
        public System.Boolean Enabled { get; set; }
        public Microsoft.IdentityServer.Management.Resources.IApplication[] Applications { get; set; }

        // Fabricated constructor
        private ApplicationGroup() { }
        public static ApplicationGroup CreateTypeInstance()
        {
            return new ApplicationGroup();
        }
    }

    public class AttributeStore
    {
        // Property
        public System.Collections.Hashtable Configuration { get; set; }
        public System.String Name { get; set; }
        public System.String StoreClassification { get; set; }
        public System.String StoreTypeQualifiedName { get; set; }

        // Fabricated constructor
        private AttributeStore() { }
        public static AttributeStore CreateTypeInstance()
        {
            return new AttributeStore();
        }
    }

    public class ClaimDescription
    {
        // Property
        public System.String ClaimType { get; set; }
        public System.Boolean IsAccepted { get; set; }
        public System.Boolean IsOffered { get; set; }
        public System.Boolean IsRequired { get; set; }
        public System.String Name { get; set; }
        public System.String ShortName { get; set; }
        public System.String Notes { get; set; }

        // Fabricated constructor
        private ClaimDescription() { }
        public static ClaimDescription CreateTypeInstance()
        {
            return new ClaimDescription();
        }
    }

    public class ClaimsProviderTrust
    {
        // Property
        public System.Boolean AllowCreate { get; set; }
        public System.Boolean AutoUpdateEnabled { get; set; }
        public System.Boolean SupportsMFA { get; set; }
        public System.Uri WSFedEndpoint { get; set; }
        public Microsoft.IdentityServer.Management.Resources.ClaimDescription[] ClaimsOffered { get; set; }
        public System.Boolean ConflictWithPublishedPolicy { get; set; }
        public System.Uri CustomMFAUri { get; set; }
        public System.Security.Cryptography.X509Certificates.X509Certificate2 EncryptionCertificate { get; set; }
        public Microsoft.IdentityServer.PolicyModel.Configuration.RevocationSetting EncryptionCertificateRevocationCheck { get; set; }
        public Microsoft.IdentityServer.PolicyModel.Configuration.RevocationSetting SigningCertificateRevocationCheck { get; set; }
        public System.DateTime LastMonitoredTime { get; set; }
        public System.Nullable<System.Boolean> LastPublishedPolicyCheckSuccessful { get; set; }
        public System.DateTime LastUpdateTime { get; set; }
        public System.Uri MetadataUrl { get; set; }
        public System.Boolean MonitoringEnabled { get; set; }
        public System.String OrganizationInfo { get; set; }
        public System.Uri RequiredNameIdFormat { get; set; }
        public System.Boolean EncryptedNameIdRequired { get; set; }
        public System.Boolean SignedSamlRequestsRequired { get; set; }
        public System.UInt16 SamlAuthenticationRequestIndex { get; set; }
        public System.String SamlAuthenticationRequestParameters { get; set; }
        public System.String SamlAuthenticationRequestProtocolBinding { get; set; }
        public Microsoft.IdentityServer.Management.Resources.SamlEndpoint[] SamlEndpoints { get; set; }
        public System.String SignatureAlgorithm { get; set; }
        public System.Collections.ObjectModel.ReadOnlyCollection<System.Security.Cryptography.X509Certificates.X509Certificate2> TokenSigningCertificates { get; set; }
        public System.String AlternateLoginID { get; set; }
        public System.Collections.Generic.IList<System.String> LookupForests { get; set; }
        public Microsoft.IdentityServer.PolicyModel.Configuration.PromptLoginFederation PromptLoginFederation { get; set; }
        public System.String PromptLoginFallbackAuthenticationType { get; set; }
        public System.String AuthorityGroupId { get; set; }
        public System.String AuthorityGroupIdentifier { get; set; }
        public System.String AnchorClaimType { get; set; }
        public System.String IdentifierType { get; set; }
        public System.Collections.ObjectModel.Collection<System.String> Identities { get; set; }
        public System.String AcceptanceTransformRules { get; set; }
        public System.String[] OrganizationalAccountSuffix { get; set; }
        public System.Boolean Enabled { get; set; }
        public System.Boolean IsLocal { get; set; }
        public System.String Identifier { get; set; }
        public System.String Name { get; set; }
        public System.String Notes { get; set; }
        public System.String ProtocolProfile { get; set; }

        // Fabricated constructor
        private ClaimsProviderTrust() { }
        public static ClaimsProviderTrust CreateTypeInstance()
        {
            return new ClaimsProviderTrust();
        }
    }

    public class ContactPerson
    {
        // Property
        public System.String Company { get; set; }
        public System.String ContactType { get; set; }
        public System.String[] EmailAddresses { get; set; }
        public System.String GivenName { get; set; }
        public System.String[] PhoneNumbers { get; set; }
        public System.String Surname { get; set; }

        // Fabricated constructor
        private ContactPerson() { }
        public static ContactPerson CreateTypeInstance()
        {
            return new ContactPerson();
        }
    }

    public class Endpoint
    {
        // Property
        public System.String ClientCredentialType { get; set; }
        public System.Boolean Enabled { get; set; }
        public System.Uri FullUrl { get; set; }
        public System.Boolean Proxy { get; set; }
        public System.String Protocol { get; set; }
        public System.String SecurityMode { get; set; }
        public System.String AddressPath { get; set; }
        public System.String Version { get; set; }

        // Fabricated constructor
        private Endpoint() { }
        public static Endpoint CreateTypeInstance()
        {
            return new Endpoint();
        }
    }

    public class IApplication
    {
        public bool IsSecondaryStubType = true;

        public IApplication() { }
    }

    public class LdapAttributeToClaimMapping
    {
        // Property
        public System.String LdapAttribute { get; set; }
        public System.String ClaimType { get; set; }

        // Fabricated constructor
        private LdapAttributeToClaimMapping() { }
        public static LdapAttributeToClaimMapping CreateTypeInstance()
        {
            return new LdapAttributeToClaimMapping();
        }
    }

    public enum LdapAuthenticationMethod : int
    {
        Basic = 0,
        Kerberos = 1,
        Negotiate = 2,
    }

    public class LdapServerConnection
    {
        // Property
        public System.String HostName { get; set; }
        public System.Int32 Port { get; set; }
        public Microsoft.IdentityServer.Management.Resources.LdapSslMode SslMode { get; set; }
        // public System.DirectoryServices.Protocols.AuthType AuthenticationMethod { get; set; }
        public System.Management.Automation.PSCredential Credential { get; set; }

        // Fabricated constructor
        private LdapServerConnection() { }
        public static LdapServerConnection CreateTypeInstance()
        {
            return new LdapServerConnection();
        }
    }

    public enum LdapSslMode : int
    {
        None = 0,
        Ssl = 1,
        Tls = 2,
    }

    public class LocalClaimsProviderTrust
    {
        // Property
        public System.String LocalClaimsProviderType { get; set; }
        public System.String AnchorClaimType { get; set; }
        public System.String IdentifierType { get; set; }
        public System.Collections.ObjectModel.Collection<System.String> Identities { get; set; }
        public System.String AcceptanceTransformRules { get; set; }
        public System.String[] OrganizationalAccountSuffix { get; set; }
        public System.Boolean Enabled { get; set; }
        public System.Boolean IsLocal { get; set; }
        public System.String Identifier { get; set; }
        public System.String Name { get; set; }
        public System.String Notes { get; set; }
        public System.String ProtocolProfile { get; set; }

        // Fabricated constructor
        private LocalClaimsProviderTrust() { }
        public static LocalClaimsProviderTrust CreateTypeInstance()
        {
            return new LocalClaimsProviderTrust();
        }
    }

    public class NativeClientApplication
    {
        // Property
        public System.String Name { get; set; }
        public System.String Identifier { get; set; }
        public System.String ApplicationGroupIdentifier { get; set; }
        public System.String Description { get; set; }
        public System.Boolean Enabled { get; set; }
        public System.String[] RedirectUri { get; set; }
        public System.String LogoutUri { get; set; }

        // Fabricated constructor
        private NativeClientApplication() { }
        public static NativeClientApplication CreateTypeInstance()
        {
            return new NativeClientApplication();
        }
    }

    public class NonClaimsAwareRelyingPartyTrust
    {
        // Property
        public System.Boolean AlwaysRequireAuthentication { get; set; }
        public System.Boolean Enabled { get; set; }
        public System.Collections.ObjectModel.ReadOnlyCollection<System.String> Identifier { get; set; }
        public System.Boolean PublishedThroughProxy { get; set; }
        public System.String IssuanceAuthorizationRules { get; set; }
        public System.String Name { get; set; }
        public System.String Notes { get; set; }
        public System.String ObjectIdentifier { get; set; }
        public System.Collections.ObjectModel.ReadOnlyCollection<System.String> ProxiedTrustedEndpoints { get; set; }
        public System.String AdditionalAuthenticationRules { get; set; }
        public System.String AccessControlPolicyName { get; set; }
        public System.String[] ClaimsProviderName { get; set; }
        public System.Object AccessControlPolicyParameters { get; set; }
        public System.Nullable<Microsoft.IdentityServer.PolicyModel.Configuration.DeviceAuthenticationMethod> DeviceAuthenticationMethod { get; set; }
        public Microsoft.IdentityServer.PolicyModel.Configuration.PolicyTemplate.PolicyMetadata ResultantPolicy { get; set; }

        // Fabricated constructor
        private NonClaimsAwareRelyingPartyTrust() { }
        public static NonClaimsAwareRelyingPartyTrust CreateTypeInstance()
        {
            return new NonClaimsAwareRelyingPartyTrust();
        }
    }

    public class OAuthPermission
    {
        // Property
        public System.String GrantedBy { get; set; }
        public System.DateTime GrantedAt { get; set; }
        public Microsoft.IdentityServer.Protocols.PolicyStore.OAuthConsentType ConsentType { get; set; }
        public System.String ClientRoleIdentifier { get; set; }
        public System.String ServerRoleIdentifier { get; set; }
        public System.String Description { get; set; }
        public System.String ObjectIdentifier { get; set; }
        public System.String[] ScopeNames { get; set; }

        // Fabricated constructor
        private OAuthPermission() { }
        public static OAuthPermission CreateTypeInstance()
        {
            return new OAuthPermission();
        }
    }

    public class OAuthScopeDescription
    {
        // Property
        public System.String Name { get; set; }
        public System.String Description { get; set; }
        public System.Boolean IsBuiltIn { get; set; }

        // Fabricated constructor
        private OAuthScopeDescription() { }
        public static OAuthScopeDescription CreateTypeInstance()
        {
            return new OAuthScopeDescription();
        }
    }

    public class Organization
    {
        // Property
        public System.String DisplayName { get; set; }
        public System.String Name { get; set; }
        public System.Uri OrganizationUrl { get; set; }

        // Fabricated constructor
        private Organization() { }
        public static Organization CreateTypeInstance()
        {
            return new Organization();
        }
    }

    public class RelyingPartyTrust
    {
        // Property
        public System.String[] AllowedAuthenticationClassReferences { get; set; }
        public Microsoft.IdentityServer.PolicyModel.Configuration.RevocationSetting EncryptionCertificateRevocationCheck { get; set; }
        public System.Boolean PublishedThroughProxy { get; set; }
        public Microsoft.IdentityServer.PolicyModel.Configuration.RevocationSetting SigningCertificateRevocationCheck { get; set; }
        public System.Uri WSFedEndpoint { get; set; }
        public System.Collections.ObjectModel.ReadOnlyCollection<System.String> AdditionalWSFedEndpoint { get; set; }
        public System.String[] ClaimsProviderName { get; set; }
        public Microsoft.IdentityServer.Management.Resources.ClaimDescription[] ClaimsAccepted { get; set; }
        public System.Boolean EncryptClaims { get; set; }
        public System.Boolean Enabled { get; set; }
        public System.Security.Cryptography.X509Certificates.X509Certificate2 EncryptionCertificate { get; set; }
        public System.Collections.ObjectModel.ReadOnlyCollection<System.String> Identifier { get; set; }
        public System.Int32 NotBeforeSkew { get; set; }
        public System.Boolean EnableJWT { get; set; }
        public System.Boolean AlwaysRequireAuthentication { get; set; }
        public System.String Notes { get; set; }
        public System.String OrganizationInfo { get; set; }
        public System.String ObjectIdentifier { get; set; }
        public System.Collections.Generic.Dictionary<System.String,System.String> ProxyEndpointMappings { get; set; }
        public System.Collections.ObjectModel.ReadOnlyCollection<System.String> ProxyTrustedEndpoints { get; set; }
        public System.String ProtocolProfile { get; set; }
        public System.Collections.ObjectModel.ReadOnlyCollection<System.Security.Cryptography.X509Certificates.X509Certificate2> RequestSigningCertificate { get; set; }
        public System.Boolean EncryptedNameIdRequired { get; set; }
        public System.Boolean SignedSamlRequestsRequired { get; set; }
        public Microsoft.IdentityServer.Management.Resources.SamlEndpoint[] SamlEndpoints { get; set; }
        public System.String SamlResponseSignature { get; set; }
        public System.String SignatureAlgorithm { get; set; }
        public System.Int32 TokenLifetime { get; set; }
        public Microsoft.IdentityServer.Protocols.PolicyStore.AllowedClientTypes AllowedClientTypes { get; set; }
        public Microsoft.IdentityServer.Protocols.PolicyStore.RefreshTokenIssuanceDeviceTypes IssueOAuthRefreshTokensTo { get; set; }
        public System.Boolean RefreshTokenProtectionEnabled { get; set; }
        public System.Boolean RequestMFAFromClaimsProviders { get; set; }
        public System.String ScopeGroupId { get; set; }
        public System.String ScopeGroupIdentifier { get; set; }
        public System.Nullable<Microsoft.IdentityServer.PolicyModel.Configuration.DeviceAuthenticationMethod> DeviceAuthenticationMethod { get; set; }
        public System.String Name { get; set; }
        public System.Boolean AutoUpdateEnabled { get; set; }
        public System.Boolean MonitoringEnabled { get; set; }
        public System.Uri MetadataUrl { get; set; }
        public System.Boolean ConflictWithPublishedPolicy { get; set; }
        public System.String IssuanceAuthorizationRules { get; set; }
        public System.String IssuanceTransformRules { get; set; }
        public System.String DelegationAuthorizationRules { get; set; }
        public System.Nullable<System.Boolean> LastPublishedPolicyCheckSuccessful { get; set; }
        public System.DateTime LastUpdateTime { get; set; }
        public System.DateTime LastMonitoredTime { get; set; }
        public System.String ImpersonationAuthorizationRules { get; set; }
        public System.String AdditionalAuthenticationRules { get; set; }
        public System.String AccessControlPolicyName { get; set; }
        public System.Object AccessControlPolicyParameters { get; set; }
        public Microsoft.IdentityServer.PolicyModel.Configuration.PolicyTemplate.PolicyMetadata ResultantPolicy { get; set; }

        // Fabricated constructor
        private RelyingPartyTrust() { }
        public static RelyingPartyTrust CreateTypeInstance()
        {
            return new RelyingPartyTrust();
        }
    }

    public class SamlEndpoint
    {
        // Property
        public System.String Binding { get; set; }
        public System.Uri BindingUri { get; set; }
        public System.Int32 Index { get; set; }
        public System.Boolean IsDefault { get; set; }
        public System.Uri Location { get; set; }
        public System.String Protocol { get; set; }
        public System.Uri ResponseLocation { get; set; }

        // Fabricated constructor
        private SamlEndpoint() { }
        public static SamlEndpoint CreateTypeInstance()
        {
            return new SamlEndpoint();
        }
    }

    public class ServerApplication
    {
        // Property
        public System.String ADUserPrincipalName { get; set; }
        public System.String ClientSecret { get; set; }
        public Microsoft.IdentityServer.PolicyModel.Configuration.RevocationSetting JWTSigningCertificateRevocationCheck { get; set; }
        public System.Collections.Generic.IDictionary<System.String,System.Object> JWTSigningKeys { get; set; }
        public System.Uri JWKSUri { get; set; }
        public System.String Name { get; set; }
        public System.String Identifier { get; set; }
        public System.String ApplicationGroupIdentifier { get; set; }
        public System.String Description { get; set; }
        public System.Boolean Enabled { get; set; }
        public System.String[] RedirectUri { get; set; }
        public System.String LogoutUri { get; set; }

        // Fabricated constructor
        private ServerApplication() { }
        public static ServerApplication CreateTypeInstance()
        {
            return new ServerApplication();
        }
    }

    public class ServiceCertificate
    {
        // Property
        public System.Security.Cryptography.X509Certificates.X509Certificate2 Certificate { get; set; }
        public System.String CertificateType { get; set; }
        public System.Boolean IsPrimary { get; set; }
        public System.Security.Cryptography.X509Certificates.StoreLocation StoreLocation { get; set; }
        public System.Security.Cryptography.X509Certificates.StoreName StoreName { get; set; }
        public System.String Thumbprint { get; set; }

        // Fabricated constructor
        private ServiceCertificate() { }
        public static ServiceCertificate CreateTypeInstance()
        {
            return new ServiceCertificate();
        }
    }

    public class WebApiApplication
    {
        // Property
        public System.String Name { get; set; }
        public System.Collections.ObjectModel.ReadOnlyCollection<System.String> Identifier { get; set; }
        public System.String AccessControlPolicyName { get; set; }
        public System.Object AccessControlPolicyParameters { get; set; }
        public System.String AdditionalAuthenticationRules { get; set; }
        public System.String[] AllowedAuthenticationClassReferences { get; set; }
        public Microsoft.IdentityServer.Protocols.PolicyStore.AllowedClientTypes AllowedClientTypes { get; set; }
        public System.String ApplicationGroupIdentifier { get; set; }
        public System.String ApplicationGroupId { get; set; }
        public System.Boolean AlwaysRequireAuthentication { get; set; }
        public System.String[] ClaimsProviderName { get; set; }
        public System.String DelegationAuthorizationRules { get; set; }
        public System.Boolean Enabled { get; set; }
        public System.String ImpersonationAuthorizationRules { get; set; }
        public System.String IssuanceAuthorizationRules { get; set; }
        public Microsoft.IdentityServer.Protocols.PolicyStore.RefreshTokenIssuanceDeviceTypes IssueOAuthRefreshTokensTo { get; set; }
        public System.String IssuanceTransformRules { get; set; }
        public System.Int32 NotBeforeSkew { get; set; }
        public System.String Description { get; set; }
        public System.Boolean PublishedThroughProxy { get; set; }
        public System.Boolean RefreshTokenProtectionEnabled { get; set; }
        public System.Boolean RequestMFAFromClaimsProviders { get; set; }
        public System.Nullable<Microsoft.IdentityServer.PolicyModel.Configuration.DeviceAuthenticationMethod> DeviceAuthenticationMethod { get; set; }
        public Microsoft.IdentityServer.PolicyModel.Configuration.PolicyTemplate.PolicyMetadata ResultantPolicy { get; set; }
        public System.Int32 TokenLifetime { get; set; }

        // Fabricated constructor
        private WebApiApplication() { }
        public static WebApiApplication CreateTypeInstance()
        {
            return new WebApiApplication();
        }
    }

    public class WebThemeBase
    {
        // Property
        public System.String Name { get; set; }
        public System.Collections.Generic.IDictionary<System.Globalization.CultureInfo,System.Byte[]> StyleSheet { get; set; }
        public System.Byte[] RTLStyleSheet { get; set; }
        public System.Byte[] OnLoadScript { get; set; }
        public System.Collections.Generic.IDictionary<System.Globalization.CultureInfo,System.Byte[]> Logo { get; set; }
        public System.Collections.Generic.IDictionary<System.Globalization.CultureInfo,System.Byte[]> Illustration { get; set; }
        public System.Collections.Generic.IDictionary<System.String,System.Byte[]> AdditionalFileResources { get; set; }

        // Fabricated constructor
        private WebThemeBase() { }
        public static WebThemeBase CreateTypeInstance()
        {
            return new WebThemeBase();
        }
    }

    public class SyncProperties
    {
        // Constructor
        public SyncProperties() { }

        // Property
        public System.String LastSyncFromPrimaryComputerName { get; set; }
        public System.Int32 LastSyncStatus { get; set; }
        public System.DateTime LastSyncTime { get; set; }
        public System.Int32 PollDuration { get; set; }
        public System.String PrimaryComputerName { get; set; }
        public System.Int32 PrimaryComputerPort { get; set; }
        public System.String Role { get; set; }
    }

    public class SyncPropertiesBase
    {
        // Constructor
        public SyncPropertiesBase() { }

        // Property
        public System.String Role { get; set; }
    }
}

namespace Microsoft.IdentityServer.PolicyModel.Configuration
{
    [System.Flags]
    public enum ClientAuthenticationMethod : int
    {
        None = 0,
        ClientSecretPostAuthentication = 1,
        ClientSecretBasicAuthentication = 2,
        PrivateKeyJWTBearerAuthentication = 4,
        WindowsIntegratedAuthentication = 8,
    }

    public enum DeviceAuthenticationMethod : int
    {
        All = 0,
        ClientTLS = 1,
        SignedToken = 2,
        PKeyAuth = 3,
    }

    public enum ErrorShowLevel : int
    {
        None = 0,
        Private = 1,
        Detailed = 2,
    }

    [System.Flags]
    public enum ExtranetLockoutModes : int
    {
        ADPasswordCounter = 1,
        ADFSSmartLockoutLogOnly = 2,
        ADFSSmartLockoutEnforce = 4,
    }

    public enum PromptLoginFederation : int
    {
        None = 0,
        FallbackToProtocolSpecificParameters = 1,
        ForwardPromptAndHintsOverWsFederation = 2,
        Disabled = 3,
    }

    public enum RevocationSetting : int
    {
        None = 0,
        CheckEndCert = 1,
        CheckEndCertCacheOnly = 2,
        CheckChain = 3,
        CheckChainCacheOnly = 4,
        CheckChainExcludeRoot = 5,
        CheckChainExcludeRootCacheOnly = 6,
    }

    public enum WindowsHelloKeyVerificationOptions : int
    {
        AllowAll = 0,
        AllowAllAndLog = 1,
        AllowStrongKeysOnly = 2,
    }

}

namespace Microsoft.IdentityServer.PolicyModel.Configuration.PolicyTemplate
{
    public class PolicyMetadata
    {
        // Constructor
        public PolicyMetadata() { }
        public PolicyMetadata(System.String serializedMetadata) { }

        // Property
        public System.Boolean IsParameterized { get; set; }
        public System.String Serialized { get; set; }
        public System.String Summary { get; set; }
        // public System.Runtime.Serialization.ExtensionDataObject ExtensionData { get; set; }

    }

}

namespace Microsoft.IdentityServer.Protocols.PolicyStore
{
    [System.Flags]
    public enum AllowedClientTypes : int
    {
        None = 0,
        Public = 2,
        Confidential = 4,
    }

    public enum ClientType : int
    {
        Unknown = 0,
        Public = 2,
        Confidential = 4,
    }

    public enum OAuthConsentType : int
    {
        Unknown = 0,
        Administrator = 1,
        User = 2,
    }

    public enum RefreshTokenIssuanceDeviceTypes : int
    {
        NoDevice = 0,
        WorkplaceJoinedDevices = 1,
        AllDevices = 2,
    }

}
'@

function Add-AdfsAttributeStore {
    <#
    .SYNOPSIS
        Add-AdfsAttributeStore -Name <string> -StoreType <string> -Configuration <hashtable> [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]

Add-AdfsAttributeStore -Name <string> -TypeQualifiedName <string> -Configuration <hashtable> [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Low')]
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${Name},

        [Parameter(ParameterSetName='Predefined', Mandatory=$true)]
        [ValidateSet('ActiveDirectory','LDAP','SQL')]
        [string]
        ${StoreType},

        [Parameter(ParameterSetName='Custom', Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${TypeQualifiedName},

        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        [hashtable]
        ${Configuration},

        [switch]
        ${PassThru}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Add-AdfsCertificate {
    <#
    .SYNOPSIS
        Add-AdfsCertificate -CertificateType <string> -Thumbprint <string> [-IsPrimary] [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Low')]
    param (
        [Parameter(Mandatory=$true)]
        [ValidateSet('Token-Decrypting','Token-Signing')]
        [string]
        ${CertificateType},

        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [string]
        ${Thumbprint},

        [switch]
        ${IsPrimary},

        [switch]
        ${PassThru}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Add-AdfsClaimDescription {
    <#
    .SYNOPSIS
        Add-AdfsClaimDescription -Name <string> -ClaimType <string> [-ShortName <string>] [-IsAccepted <bool>] [-IsOffered <bool>] [-IsRequired <bool>] [-Notes <string>] [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Low')]
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${Name},

        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        [string]
        ${ClaimType},

        [ValidateNotNull()]
        [string]
        ${ShortName},

        [bool]
        ${IsAccepted},

        [bool]
        ${IsOffered},

        [bool]
        ${IsRequired},

        [string]
        ${Notes},

        [switch]
        ${PassThru}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Add-AdfsClaimsProviderTrust {
    <#
    .SYNOPSIS
        Add-AdfsClaimsProviderTrust -Name <string> -Identifier <string> -TokenSigningCertificate <X509Certificate2[]> [-AutoUpdateEnabled <bool>] [-AllowCreate <bool>] [-AnchorClaimType <string>] [-CustomMFAUri <uri>] [-EncryptionCertificateRevocationCheck <string>] [-Enabled <bool>] [-Notes <string>] [-ProtocolProfile <string>] [-EncryptedNameIdRequired <bool>] [-SamlAuthenticationRequestIndex <uint16>] [-SamlAuthenticationRequestParameters <string>] [-SamlAuthenticationRequestProtocolBinding <string>] [-SignatureAlgorithm <string>] [-SigningCertificateRevocationCheck <string>] [-SupportsMfa] [-PromptLoginFederation <PromptLoginFederation>] [-PromptLoginFallbackAuthenticationType <string>] [-RequiredNameIdFormat <uri>] [-EncryptionCertificate <X509Certificate2>] [-OrganizationalAccountSuffix <string[]>] [-WSFedEndpoint <uri>] [-ClaimOffered <ClaimDescription[]>] [-SamlEndpoint <SamlEndpoint[]>] [-SignedSamlRequestsRequired <bool>] [-PassThru] [-AcceptanceTransformRules <string>] [-AcceptanceTransformRulesFile <string>] [-MonitoringEnabled <bool>] [-WhatIf] [-Confirm] [<CommonParameters>]

Add-AdfsClaimsProviderTrust -Name <string> [-AutoUpdateEnabled <bool>] [-AllowCreate <bool>] [-AnchorClaimType <string>] [-EncryptionCertificateRevocationCheck <string>] [-Enabled <bool>] [-Notes <string>] [-ProtocolProfile <string>] [-EncryptedNameIdRequired <bool>] [-SamlAuthenticationRequestIndex <uint16>] [-SamlAuthenticationRequestParameters <string>] [-SamlAuthenticationRequestProtocolBinding <string>] [-SignatureAlgorithm <string>] [-SigningCertificateRevocationCheck <string>] [-PromptLoginFederation <PromptLoginFederation>] [-PromptLoginFallbackAuthenticationType <string>] [-RequiredNameIdFormat <uri>] [-OrganizationalAccountSuffix <string[]>] [-MetadataFile <string>] [-SignedSamlRequestsRequired <bool>] [-PassThru] [-AcceptanceTransformRules <string>] [-AcceptanceTransformRulesFile <string>] [-MonitoringEnabled <bool>] [-WhatIf] [-Confirm] [<CommonParameters>]

Add-AdfsClaimsProviderTrust -Name <string> [-AutoUpdateEnabled <bool>] [-AllowCreate <bool>] [-AnchorClaimType <string>] [-EncryptionCertificateRevocationCheck <string>] [-Enabled <bool>] [-Notes <string>] [-ProtocolProfile <string>] [-EncryptedNameIdRequired <bool>] [-SamlAuthenticationRequestIndex <uint16>] [-SamlAuthenticationRequestParameters <string>] [-SamlAuthenticationRequestProtocolBinding <string>] [-SignatureAlgorithm <string>] [-SigningCertificateRevocationCheck <string>] [-PromptLoginFederation <PromptLoginFederation>] [-PromptLoginFallbackAuthenticationType <string>] [-RequiredNameIdFormat <uri>] [-OrganizationalAccountSuffix <string[]>] [-MetadataUrl <uri>] [-SignedSamlRequestsRequired <bool>] [-PassThru] [-AcceptanceTransformRules <string>] [-AcceptanceTransformRulesFile <string>] [-MonitoringEnabled <bool>] [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Low')]
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        [string]
        ${Name},

        [Parameter(ParameterSetName='AllProperties', Mandatory=$true)]
        [ValidateNotNull()]
        [string]
        ${Identifier},

        [Parameter(ParameterSetName='AllProperties', Mandatory=$true, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [System.Security.Cryptography.X509Certificates.X509Certificate2[]]
        ${TokenSigningCertificate},

        [System.Nullable[bool]]
        ${AutoUpdateEnabled},

        [System.Nullable[bool]]
        ${AllowCreate},

        [ValidateNotNullOrEmpty()]
        [string]
        ${AnchorClaimType},

        [Parameter(ParameterSetName='AllProperties')]
        [ValidateNotNull()]
        [uri]
        ${CustomMFAUri},

        [ValidateSet('CheckChain','CheckChainCacheOnly','CheckChainExcludeRoot','CheckChainExcludeRootCacheOnly','CheckEndCert','CheckEndCertCacheOnly','None')]
        [string]
        ${EncryptionCertificateRevocationCheck},

        [System.Nullable[bool]]
        ${Enabled},

        [ValidateNotNullOrEmpty()]
        [string]
        ${Notes},

        [ValidateSet('WSFederation','WsFed-SAML','SAML')]
        [string]
        ${ProtocolProfile},

        [ValidateNotNull()]
        [System.Nullable[bool]]
        ${EncryptedNameIdRequired},

        [System.Nullable[uint16]]
        ${SamlAuthenticationRequestIndex},

        [ValidateSet('Index','None','ProtocolBinding','Url','UrlWithProtocolBinding')]
        [string]
        ${SamlAuthenticationRequestParameters},

        [ValidateSet('Artifact','POST','Redirect')]
        [string]
        ${SamlAuthenticationRequestProtocolBinding},

        [ValidateSet('http://www.w3.org/2000/09/xmldsig#rsa-sha1','http://www.w3.org/2001/04/xmldsig-more#rsa-sha256')]
        [string]
        ${SignatureAlgorithm},

        [ValidateSet('CheckChain','CheckChainCacheOnly','CheckChainExcludeRoot','CheckChainExcludeRootCacheOnly','CheckEndCert','CheckEndCertCacheOnly','None')]
        [string]
        ${SigningCertificateRevocationCheck},

        [Parameter(ParameterSetName='AllProperties')]
        [ValidateNotNull()]
        [switch]
        ${SupportsMfa},

        [Microsoft.IdentityServer.PolicyModel.Configuration.PromptLoginFederation]
        ${PromptLoginFederation},

        [string]
        ${PromptLoginFallbackAuthenticationType},

        [uri]
        ${RequiredNameIdFormat},

        [Parameter(ParameterSetName='AllProperties')]
        [ValidateNotNull()]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]
        ${EncryptionCertificate},

        [ValidateNotNull()]
        [string[]]
        ${OrganizationalAccountSuffix},

        [Parameter(ParameterSetName='MetadataFile')]
        [ValidateNotNullOrEmpty()]
        [string]
        ${MetadataFile},

        [Parameter(ParameterSetName='MetadataUrl')]
        [ValidateNotNull()]
        [uri]
        ${MetadataUrl},

        [Parameter(ParameterSetName='AllProperties')]
        [ValidateNotNull()]
        [uri]
        ${WSFedEndpoint},

        [Parameter(ParameterSetName='AllProperties', ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [Microsoft.IdentityServer.Management.Resources.ClaimDescription[]]
        ${ClaimOffered},

        [Parameter(ParameterSetName='AllProperties', ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [Microsoft.IdentityServer.Management.Resources.SamlEndpoint[]]
        ${SamlEndpoint},

        [ValidateNotNull()]
        [System.Nullable[bool]]
        ${SignedSamlRequestsRequired},

        [switch]
        ${PassThru},

        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [string]
        ${AcceptanceTransformRules},

        [ValidateNotNullOrEmpty()]
        [string]
        ${AcceptanceTransformRulesFile},

        [System.Nullable[bool]]
        ${MonitoringEnabled}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Add-AdfsClaimsProviderTrustsGroup {
    <#
    .SYNOPSIS
        Add-AdfsClaimsProviderTrustsGroup -MetadataFile <string> [-Force] [-PassThru] [-AcceptanceTransformRules <string>] [-AcceptanceTransformRulesFile <string>] [-MonitoringEnabled <bool>] [-WhatIf] [-Confirm] [<CommonParameters>]

Add-AdfsClaimsProviderTrustsGroup -MetadataUrl <uri> [-AutoUpdateEnabled <bool>] [-Force] [-PassThru] [-AcceptanceTransformRules <string>] [-AcceptanceTransformRulesFile <string>] [-MonitoringEnabled <bool>] [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Low')]
    param (
        [Parameter(ParameterSetName='MetadataFile', Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${MetadataFile},

        [Parameter(ParameterSetName='MetadataUrl', Mandatory=$true)]
        [ValidateNotNull()]
        [uri]
        ${MetadataUrl},

        [Parameter(ParameterSetName='MetadataUrl')]
        [System.Nullable[bool]]
        ${AutoUpdateEnabled},

        [ValidateNotNullOrEmpty()]
        [switch]
        ${Force},

        [ValidateNotNullOrEmpty()]
        [switch]
        ${PassThru},

        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [string]
        ${AcceptanceTransformRules},

        [ValidateNotNullOrEmpty()]
        [string]
        ${AcceptanceTransformRulesFile},

        [System.Nullable[bool]]
        ${MonitoringEnabled}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Add-AdfsClient {
    <#
    .SYNOPSIS
        Add-AdfsClient [-ClientId] <string> [-Name] <string> [[-RedirectUri] <string[]>] [-Description <string>] [-ClientType <ClientType>] [-ADUserPrincipalName <string>] [-JWTSigningCertificate <X509Certificate2[]>] [-JWTSigningCertificateRevocationCheck <RevocationSetting>] [-JWKSUri <uri>] [-JWKSFile <string>] [-LogoutUri <string>] [-GenerateClientSecret] [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    param (
        [Parameter(Mandatory=$true, Position=0, ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${ClientId},

        [Parameter(Mandatory=$true, Position=1, ValueFromPipelineByPropertyName=$true)]
        [string]
        ${Name},

        [Parameter(Position=2, ValueFromPipelineByPropertyName=$true)]
        [string[]]
        ${RedirectUri},

        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [string]
        ${Description},

        [Microsoft.IdentityServer.Protocols.PolicyStore.ClientType]
        ${ClientType},

        [ValidateNotNullOrEmpty()]
        [string]
        ${ADUserPrincipalName},

        [ValidateNotNull()]
        [ValidateCount(1, 2147483647)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2[]]
        ${JWTSigningCertificate},

        [Microsoft.IdentityServer.PolicyModel.Configuration.RevocationSetting]
        ${JWTSigningCertificateRevocationCheck},

        [uri]
        ${JWKSUri},

        [string]
        ${JWKSFile},

        [ValidateNotNullOrEmpty()]
        [string]
        ${LogoutUri},

        [switch]
        ${GenerateClientSecret},

        [switch]
        ${PassThru}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Add-AdfsDeviceRegistrationUpnSuffix {
    <#
    .SYNOPSIS
        Add-AdfsDeviceRegistrationUpnSuffix [-UpnSuffix] <string> [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    param (
        [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [string]
        ${UpnSuffix}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Add-AdfsFarmNode {
    <#
    .SYNOPSIS
        Add-AdfsFarmNode -GroupServiceAccountIdentifier <string> -PrimaryComputerName <string> [-OverwriteConfiguration] [-CertificateThumbprint <string>] [-Credential <pscredential>] [-PrimaryComputerPort <int>] [-WhatIf] [-Confirm] [<CommonParameters>]

Add-AdfsFarmNode -ServiceAccountCredential <pscredential> -PrimaryComputerName <string> [-OverwriteConfiguration] [-CertificateThumbprint <string>] [-Credential <pscredential>] [-PrimaryComputerPort <int>] [-WhatIf] [-Confirm] [<CommonParameters>]

Add-AdfsFarmNode -ServiceAccountCredential <pscredential> -SQLConnectionString <string> [-CertificateThumbprint <string>] [-Credential <pscredential>] [-FarmBehavior <int>] [-WhatIf] [-Confirm] [<CommonParameters>]

Add-AdfsFarmNode -GroupServiceAccountIdentifier <string> -SQLConnectionString <string> [-CertificateThumbprint <string>] [-Credential <pscredential>] [-FarmBehavior <int>] [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(DefaultParameterSetName='AdfsFarmJoinWidGmsa', SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    param (
        [Parameter(ParameterSetName='AdfsFarmJoinWidGmsa')]
        [Parameter(ParameterSetName='ADFSFarmJoinWidSvcAcct')]
        [switch]
        ${OverwriteConfiguration},

        [ValidateLength(1, 8192)]
        [string]
        ${CertificateThumbprint},

        [Parameter(ParameterSetName='ADFSFarmJoinWidSvcAcct', Mandatory=$true)]
        [Parameter(ParameterSetName='ADFSFarmJoinSqlSvcAcct', Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [pscredential]
        ${ServiceAccountCredential},

        [Parameter(ParameterSetName='AdfsFarmJoinWidGmsa', Mandatory=$true)]
        [Parameter(ParameterSetName='AdfsFarmJoinSqlGmsa', Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${GroupServiceAccountIdentifier},

        [ValidateNotNullOrEmpty()]
        [pscredential]
        ${Credential},

        [Parameter(ParameterSetName='AdfsFarmJoinSqlGmsa', Mandatory=$true)]
        [Parameter(ParameterSetName='ADFSFarmJoinSqlSvcAcct', Mandatory=$true)]
        [ValidateLength(1, 1024)]
        [string]
        ${SQLConnectionString},

        [Parameter(ParameterSetName='AdfsFarmJoinWidGmsa', Mandatory=$true)]
        [Parameter(ParameterSetName='ADFSFarmJoinWidSvcAcct', Mandatory=$true)]
        [ValidateLength(1, 255)]
        [string]
        ${PrimaryComputerName},

        [Parameter(ParameterSetName='AdfsFarmJoinWidGmsa')]
        [Parameter(ParameterSetName='ADFSFarmJoinWidSvcAcct')]
        [ValidateRange(1, 65535)]
        [int]
        ${PrimaryComputerPort},

        [Parameter(ParameterSetName='AdfsFarmJoinSqlGmsa')]
        [Parameter(ParameterSetName='ADFSFarmJoinSqlSvcAcct')]
        #[ValidateRange(Win2012R2, Max)]
        [int]
        ${FarmBehavior}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Add-AdfsLocalClaimsProviderTrust {
    <#
    .SYNOPSIS
        Add-AdfsLocalClaimsProviderTrust -Name <string> -Identifier <string> -LdapServerConnection <LdapServerConnection[]> -UserObjectClass <string> -UserContainer <string> -AnchorClaimLdapAttribute <string> -AnchorClaimType <string> [-AcceptanceTransformRules <string>] [-AcceptanceTransformRulesFile <string>] [-Enabled <bool>] [-Notes <string>] [-OrganizationalAccountSuffix <string[]>] [-Force] [-Type <string>] [-PassThru] [-WhatIf] [-Confirm] [-LdapAuthenticationMethod <LdapAuthenticationMethod>] [-LdapAttributeToClaimMapping <LdapAttributeToClaimMapping[]>] [<CommonParameters>]
    #>

    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Low')]
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        [string]
        ${Name},

        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        [string]
        ${Identifier},

        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [string]
        ${AcceptanceTransformRules},

        [ValidateNotNullOrEmpty()]
        [string]
        ${AcceptanceTransformRulesFile},

        [System.Nullable[bool]]
        ${Enabled},

        [ValidateNotNullOrEmpty()]
        [string]
        ${Notes},

        [ValidateNotNull()]
        [string[]]
        ${OrganizationalAccountSuffix},

        [ValidateNotNullOrEmpty()]
        [switch]
        ${Force},

        [ValidateNotNullOrEmpty()]
        [string]
        ${Type},

        [switch]
        ${PassThru}
    )

    dynamicparam {
        $parameters = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary

        # LdapServerConnection
        $attributes = New-Object System.Collections.Generic.List[Attribute]

        $attribute = New-Object System.Management.Automation.ParameterAttribute
        $attribute.ParameterSetName = "AccountStoreDataParams"
        $attribute.Mandatory = $True
        $attributes.Add($attribute)

        $attribute = New-Object System.Management.Automation.ValidateNotNullOrEmptyAttribute
        $attributes.Add($attribute)

        $parameter = New-Object System.Management.Automation.RuntimeDefinedParameter("LdapServerConnection", [Microsoft.IdentityServer.Management.Resources.LdapServerConnection[]], $attributes)
        $parameters.Add("LdapServerConnection", $parameter)

        # UserObjectClass
        $attributes = New-Object System.Collections.Generic.List[Attribute]

        $attribute = New-Object System.Management.Automation.ParameterAttribute
        $attribute.ParameterSetName = "AccountStoreDataParams"
        $attribute.Mandatory = $True
        $attributes.Add($attribute)

        $attribute = New-Object System.Management.Automation.ValidateNotNullOrEmptyAttribute
        $attributes.Add($attribute)

        $parameter = New-Object System.Management.Automation.RuntimeDefinedParameter("UserObjectClass", [System.String], $attributes)
        $parameters.Add("UserObjectClass", $parameter)

        # UserContainer
        $attributes = New-Object System.Collections.Generic.List[Attribute]

        $attribute = New-Object System.Management.Automation.ParameterAttribute
        $attribute.ParameterSetName = "AccountStoreDataParams"
        $attribute.Mandatory = $True
        $attributes.Add($attribute)

        $attribute = New-Object System.Management.Automation.ValidateNotNullAttribute
        $attributes.Add($attribute)

        $parameter = New-Object System.Management.Automation.RuntimeDefinedParameter("UserContainer", [System.String], $attributes)
        $parameters.Add("UserContainer", $parameter)

        # AnchorClaimLdapAttribute
        $attributes = New-Object System.Collections.Generic.List[Attribute]

        $attribute = New-Object System.Management.Automation.ParameterAttribute
        $attribute.ParameterSetName = "AccountStoreDataParams"
        $attribute.Mandatory = $True
        $attributes.Add($attribute)

        $attribute = New-Object System.Management.Automation.ValidateNotNullOrEmptyAttribute
        $attributes.Add($attribute)

        $parameter = New-Object System.Management.Automation.RuntimeDefinedParameter("AnchorClaimLdapAttribute", [System.String], $attributes)
        $parameters.Add("AnchorClaimLdapAttribute", $parameter)

        # AnchorClaimType
        $attributes = New-Object System.Collections.Generic.List[Attribute]

        $attribute = New-Object System.Management.Automation.ParameterAttribute
        $attribute.ParameterSetName = "AccountStoreDataParams"
        $attribute.Mandatory = $True
        $attributes.Add($attribute)

        $attribute = New-Object System.Management.Automation.ValidateNotNullOrEmptyAttribute
        $attributes.Add($attribute)

        $parameter = New-Object System.Management.Automation.RuntimeDefinedParameter("AnchorClaimType", [System.String], $attributes)
        $parameters.Add("AnchorClaimType", $parameter)

        # LdapAuthenticationMethod
        $attributes = New-Object System.Collections.Generic.List[Attribute]

        $attribute = New-Object System.Management.Automation.ParameterAttribute
        $attribute.ParameterSetName = "AccountStoreDataParams"
        $attributes.Add($attribute)

        $attribute = New-Object System.Management.Automation.ValidateNotNullAttribute
        $attributes.Add($attribute)

        $parameter = New-Object System.Management.Automation.RuntimeDefinedParameter("LdapAuthenticationMethod", [System.Nullable`1[Microsoft.IdentityServer.Management.Resources.LdapAuthenticationMethod]], $attributes)
        $parameters.Add("LdapAuthenticationMethod", $parameter)

        # LdapAttributeToClaimMapping
        $attributes = New-Object System.Collections.Generic.List[Attribute]

        $attribute = New-Object System.Management.Automation.ParameterAttribute
        $attribute.ParameterSetName = "AccountStoreDataParams"
        $attributes.Add($attribute)

        $attribute = New-Object System.Management.Automation.ValidateNotNullAttribute
        $attributes.Add($attribute)

        $parameter = New-Object System.Management.Automation.RuntimeDefinedParameter("LdapAttributeToClaimMapping", [Microsoft.IdentityServer.Management.Resources.LdapAttributeToClaimMapping[]], $attributes)
        $parameters.Add("LdapAttributeToClaimMapping", $parameter)

        return $parameters
    }

    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Add-AdfsNativeClientApplication {
    <#
    .SYNOPSIS
        Add-AdfsNativeClientApplication [-ApplicationGroupIdentifier] <string> [-Name] <string> [-Identifier] <string> [[-RedirectUri] <string[]>] [-Description <string>] [-LogoutUri <string>] [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]

Add-AdfsNativeClientApplication [-ApplicationGroup] <ApplicationGroup> [-Name] <string> [-Identifier] <string> [[-RedirectUri] <string[]>] [-Description <string>] [-LogoutUri <string>] [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(DefaultParameterSetName='ApplicationGroupIdentifier', SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    param (
        [Parameter(ParameterSetName='ApplicationGroupIdentifier', Mandatory=$true, Position=0, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${ApplicationGroupIdentifier},

        [Parameter(ParameterSetName='ApplicationGroupObject', Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [Microsoft.IdentityServer.Management.Resources.ApplicationGroup]
        ${ApplicationGroup},

        [Parameter(Mandatory=$true, Position=1, ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${Name},

        [Parameter(Mandatory=$true, Position=2, ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${Identifier},

        [Parameter(Position=3, ValueFromPipelineByPropertyName=$true)]
        [string[]]
        ${RedirectUri},

        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [string]
        ${Description},

        [ValidateNotNullOrEmpty()]
        [string]
        ${LogoutUri},

        [switch]
        ${PassThru}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Add-AdfsNonClaimsAwareRelyingPartyTrust {
    <#
    .SYNOPSIS
        Add-AdfsNonClaimsAwareRelyingPartyTrust [-Name] <string> [-Identifier] <string[]> [-AlwaysRequireAuthentication] [-Enabled <bool>] [-IssuanceAuthorizationRules <string>] [-IssuanceAuthorizationRulesFile <string>] [-Notes <string>] [-PassThru] [-AdditionalAuthenticationRules <string>] [-AdditionalAuthenticationRulesFile <string>] [-AccessControlPolicyName <string>] [-AccessControlPolicyParameters <Object>] [-ClaimsProviderName <string[]>] [-DeviceAuthenticationMethod <DeviceAuthenticationMethod>] [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Low')]
    param (
        [Parameter(Mandatory=$true, Position=0)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${Name},

        [Parameter(Mandatory=$true, Position=1)]
        [ValidateNotNull()]
        [string[]]
        ${Identifier},

        [switch]
        ${AlwaysRequireAuthentication},

        [bool]
        ${Enabled},

        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [string]
        ${IssuanceAuthorizationRules},

        [ValidateNotNullOrEmpty()]
        [string]
        ${IssuanceAuthorizationRulesFile},

        [ValidateNotNullOrEmpty()]
        [string]
        ${Notes},

        [switch]
        ${PassThru},

        [ValidateNotNullOrEmpty()]
        [string]
        ${AdditionalAuthenticationRules},

        [ValidateNotNullOrEmpty()]
        [string]
        ${AdditionalAuthenticationRulesFile},

        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [string]
        ${AccessControlPolicyName},

        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [System.Object]
        ${AccessControlPolicyParameters},

        [ValidateNotNull()]
        [string[]]
        ${ClaimsProviderName},

        [System.Nullable[Microsoft.IdentityServer.PolicyModel.Configuration.DeviceAuthenticationMethod]]
        ${DeviceAuthenticationMethod}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Add-AdfsRelyingPartyTrust {
    <#
    .SYNOPSIS
        Add-AdfsRelyingPartyTrust -Name <string> -Identifier <string[]> [-EncryptClaims <bool>] [-Enabled <bool>] [-EncryptionCertificate <X509Certificate2>] [-AutoUpdateEnabled <bool>] [-WSFedEndpoint <uri>] [-AdditionalWSFedEndpoint <string[]>] [-ClaimAccepted <ClaimDescription[]>] [-SamlEndpoint <SamlEndpoint[]>] [-RequestSigningCertificate <X509Certificate2[]>] [-EncryptedNameIdRequired <bool>] [-SignedSamlRequestsRequired <bool>] [-Notes <string>] [-SignatureAlgorithm <string>] [-SigningCertificateRevocationCheck <string>] [-TokenLifetime <int>] [-AlwaysRequireAuthentication] [-RequestMFAFromClaimsProviders] [-AllowedAuthenticationClassReferences <string[]>] [-EncryptionCertificateRevocationCheck <string>] [-NotBeforeSkew <int>] [-ProtocolProfile <string>] [-ClaimsProviderName <string[]>] [-EnableJWT <bool>] [-SamlResponseSignature <string>] [-AllowedClientTypes <AllowedClientTypes>] [-IssueOAuthRefreshTokensTo <RefreshTokenIssuanceDeviceTypes>] [-RefreshTokenProtectionEnabled <bool>] [-DeviceAuthenticationMethod <DeviceAuthenticationMethod>] [-PassThru] [-MonitoringEnabled <bool>] [-ImpersonationAuthorizationRules <string>] [-ImpersonationAuthorizationRulesFile <string>] [-IssuanceTransformRules <string>] [-IssuanceTransformRulesFile <string>] [-IssuanceAuthorizationRules <string>] [-IssuanceAuthorizationRulesFile <string>] [-DelegationAuthorizationRules <string>] [-DelegationAuthorizationRulesFile <string>] [-AdditionalAuthenticationRules <string>] [-AdditionalAuthenticationRulesFile <string>] [-AccessControlPolicyName <string>] [-AccessControlPolicyParameters <Object>] [-WhatIf] [-Confirm] [<CommonParameters>]

Add-AdfsRelyingPartyTrust -Name <string> [-EncryptClaims <bool>] [-Enabled <bool>] [-MetadataFile <string>] [-AutoUpdateEnabled <bool>] [-EncryptedNameIdRequired <bool>] [-SignedSamlRequestsRequired <bool>] [-Notes <string>] [-SignatureAlgorithm <string>] [-SigningCertificateRevocationCheck <string>] [-TokenLifetime <int>] [-AlwaysRequireAuthentication] [-RequestMFAFromClaimsProviders] [-AllowedAuthenticationClassReferences <string[]>] [-EncryptionCertificateRevocationCheck <string>] [-NotBeforeSkew <int>] [-ProtocolProfile <string>] [-ClaimsProviderName <string[]>] [-EnableJWT <bool>] [-SamlResponseSignature <string>] [-AllowedClientTypes <AllowedClientTypes>] [-IssueOAuthRefreshTokensTo <RefreshTokenIssuanceDeviceTypes>] [-RefreshTokenProtectionEnabled <bool>] [-DeviceAuthenticationMethod <DeviceAuthenticationMethod>] [-PassThru] [-MonitoringEnabled <bool>] [-ImpersonationAuthorizationRules <string>] [-ImpersonationAuthorizationRulesFile <string>] [-IssuanceTransformRules <string>] [-IssuanceTransformRulesFile <string>] [-IssuanceAuthorizationRules <string>] [-IssuanceAuthorizationRulesFile <string>] [-DelegationAuthorizationRules <string>] [-DelegationAuthorizationRulesFile <string>] [-AdditionalAuthenticationRules <string>] [-AdditionalAuthenticationRulesFile <string>] [-AccessControlPolicyName <string>] [-AccessControlPolicyParameters <Object>] [-WhatIf] [-Confirm] [<CommonParameters>]

Add-AdfsRelyingPartyTrust -Name <string> [-EncryptClaims <bool>] [-Enabled <bool>] [-MetadataUrl <uri>] [-AutoUpdateEnabled <bool>] [-EncryptedNameIdRequired <bool>] [-SignedSamlRequestsRequired <bool>] [-Notes <string>] [-SignatureAlgorithm <string>] [-SigningCertificateRevocationCheck <string>] [-TokenLifetime <int>] [-AlwaysRequireAuthentication] [-RequestMFAFromClaimsProviders] [-AllowedAuthenticationClassReferences <string[]>] [-EncryptionCertificateRevocationCheck <string>] [-NotBeforeSkew <int>] [-ProtocolProfile <string>] [-ClaimsProviderName <string[]>] [-EnableJWT <bool>] [-SamlResponseSignature <string>] [-AllowedClientTypes <AllowedClientTypes>] [-IssueOAuthRefreshTokensTo <RefreshTokenIssuanceDeviceTypes>] [-RefreshTokenProtectionEnabled <bool>] [-DeviceAuthenticationMethod <DeviceAuthenticationMethod>] [-PassThru] [-MonitoringEnabled <bool>] [-ImpersonationAuthorizationRules <string>] [-ImpersonationAuthorizationRulesFile <string>] [-IssuanceTransformRules <string>] [-IssuanceTransformRulesFile <string>] [-IssuanceAuthorizationRules <string>] [-IssuanceAuthorizationRulesFile <string>] [-DelegationAuthorizationRules <string>] [-DelegationAuthorizationRulesFile <string>] [-AdditionalAuthenticationRules <string>] [-AdditionalAuthenticationRulesFile <string>] [-AccessControlPolicyName <string>] [-AccessControlPolicyParameters <Object>] [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Low')]
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        [string]
        ${Name},

        [Parameter(ParameterSetName='AllProperties', Mandatory=$true)]
        [ValidateNotNull()]
        [string[]]
        ${Identifier},

        [System.Nullable[bool]]
        ${EncryptClaims},

        [System.Nullable[bool]]
        ${Enabled},

        [Parameter(ParameterSetName='AllProperties')]
        [ValidateNotNull()]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]
        ${EncryptionCertificate},

        [Parameter(ParameterSetName='MetadataFile')]
        [ValidateNotNullOrEmpty()]
        [string]
        ${MetadataFile},

        [Parameter(ParameterSetName='MetadataUrl')]
        [ValidateNotNull()]
        [uri]
        ${MetadataUrl},

        [System.Nullable[bool]]
        ${AutoUpdateEnabled},

        [Parameter(ParameterSetName='AllProperties')]
        [ValidateNotNull()]
        [uri]
        ${WSFedEndpoint},

        [Parameter(ParameterSetName='AllProperties')]
        [ValidateNotNull()]
        [string[]]
        ${AdditionalWSFedEndpoint},

        [Parameter(ParameterSetName='AllProperties', ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [Microsoft.IdentityServer.Management.Resources.ClaimDescription[]]
        ${ClaimAccepted},

        [Parameter(ParameterSetName='AllProperties', ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [Microsoft.IdentityServer.Management.Resources.SamlEndpoint[]]
        ${SamlEndpoint},

        [Parameter(ParameterSetName='AllProperties', ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [System.Security.Cryptography.X509Certificates.X509Certificate2[]]
        ${RequestSigningCertificate},

        [ValidateNotNull()]
        [System.Nullable[bool]]
        ${EncryptedNameIdRequired},

        [ValidateNotNull()]
        [System.Nullable[bool]]
        ${SignedSamlRequestsRequired},

        [ValidateNotNullOrEmpty()]
        [string]
        ${Notes},

        [ValidateSet('http://www.w3.org/2000/09/xmldsig#rsa-sha1','http://www.w3.org/2001/04/xmldsig-more#rsa-sha256')]
        [string]
        ${SignatureAlgorithm},

        [ValidateSet('CheckChain','CheckChainCacheOnly','CheckChainExcludeRoot','CheckChainExcludeRootCacheOnly','CheckEndCert','CheckEndCertCacheOnly','None')]
        [string]
        ${SigningCertificateRevocationCheck},

        [System.Nullable[int]]
        ${TokenLifetime},

        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [switch]
        ${AlwaysRequireAuthentication},

        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [switch]
        ${RequestMFAFromClaimsProviders},

        [ValidateNotNull()]
        [string[]]
        ${AllowedAuthenticationClassReferences},

        [ValidateSet('CheckChain','CheckChainCacheOnly','CheckChainExcludeRoot','CheckChainExcludeRootCacheOnly','CheckEndCert','CheckEndCertCacheOnly','None')]
        [string]
        ${EncryptionCertificateRevocationCheck},

        [ValidateRange(0, 15)]
        [System.Nullable[int]]
        ${NotBeforeSkew},

        [ValidateSet('WsFed-SAML','WSFederation','SAML')]
        [string]
        ${ProtocolProfile},

        [ValidateNotNull()]
        [string[]]
        ${ClaimsProviderName},

        [System.Nullable[bool]]
        ${EnableJWT},

        [ValidateSet('AssertionOnly','MessageAndAssertion','MessageOnly')]
        [string]
        ${SamlResponseSignature},

        [Microsoft.IdentityServer.Protocols.PolicyStore.AllowedClientTypes]
        ${AllowedClientTypes},

        [Microsoft.IdentityServer.Protocols.PolicyStore.RefreshTokenIssuanceDeviceTypes]
        ${IssueOAuthRefreshTokensTo},

        [System.Nullable[bool]]
        ${RefreshTokenProtectionEnabled},

        [System.Nullable[Microsoft.IdentityServer.PolicyModel.Configuration.DeviceAuthenticationMethod]]
        ${DeviceAuthenticationMethod},

        [switch]
        ${PassThru},

        [System.Nullable[bool]]
        ${MonitoringEnabled},

        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [string]
        ${ImpersonationAuthorizationRules},

        [ValidateNotNullOrEmpty()]
        [string]
        ${ImpersonationAuthorizationRulesFile},

        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [string]
        ${IssuanceTransformRules},

        [ValidateNotNullOrEmpty()]
        [string]
        ${IssuanceTransformRulesFile},

        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [string]
        ${IssuanceAuthorizationRules},

        [ValidateNotNullOrEmpty()]
        [string]
        ${IssuanceAuthorizationRulesFile},

        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [string]
        ${DelegationAuthorizationRules},

        [ValidateNotNullOrEmpty()]
        [string]
        ${DelegationAuthorizationRulesFile},

        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [string]
        ${AdditionalAuthenticationRules},

        [ValidateNotNullOrEmpty()]
        [string]
        ${AdditionalAuthenticationRulesFile},

        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [string]
        ${AccessControlPolicyName},

        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [System.Object]
        ${AccessControlPolicyParameters}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Add-AdfsRelyingPartyTrustsGroup {
    <#
    .SYNOPSIS
        Add-AdfsRelyingPartyTrustsGroup -MetadataFile <string> [-Force] [-PassThru] [-MonitoringEnabled <bool>] [-ImpersonationAuthorizationRules <string>] [-ImpersonationAuthorizationRulesFile <string>] [-IssuanceTransformRules <string>] [-IssuanceTransformRulesFile <string>] [-IssuanceAuthorizationRules <string>] [-IssuanceAuthorizationRulesFile <string>] [-DelegationAuthorizationRules <string>] [-DelegationAuthorizationRulesFile <string>] [-AdditionalAuthenticationRules <string>] [-AdditionalAuthenticationRulesFile <string>] [-AccessControlPolicyName <string>] [-AccessControlPolicyParameters <Object>] [-WhatIf] [-Confirm] [<CommonParameters>]

Add-AdfsRelyingPartyTrustsGroup -MetadataUrl <uri> [-AutoUpdateEnabled <bool>] [-Force] [-PassThru] [-MonitoringEnabled <bool>] [-ImpersonationAuthorizationRules <string>] [-ImpersonationAuthorizationRulesFile <string>] [-IssuanceTransformRules <string>] [-IssuanceTransformRulesFile <string>] [-IssuanceAuthorizationRules <string>] [-IssuanceAuthorizationRulesFile <string>] [-DelegationAuthorizationRules <string>] [-DelegationAuthorizationRulesFile <string>] [-AdditionalAuthenticationRules <string>] [-AdditionalAuthenticationRulesFile <string>] [-AccessControlPolicyName <string>] [-AccessControlPolicyParameters <Object>] [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Low')]
    param (
        [Parameter(ParameterSetName='MetadataFile', Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${MetadataFile},

        [Parameter(ParameterSetName='MetadataUrl', Mandatory=$true)]
        [ValidateNotNull()]
        [uri]
        ${MetadataUrl},

        [Parameter(ParameterSetName='MetadataUrl')]
        [System.Nullable[bool]]
        ${AutoUpdateEnabled},

        [ValidateNotNullOrEmpty()]
        [switch]
        ${Force},

        [ValidateNotNullOrEmpty()]
        [switch]
        ${PassThru},

        [System.Nullable[bool]]
        ${MonitoringEnabled},

        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [string]
        ${ImpersonationAuthorizationRules},

        [ValidateNotNullOrEmpty()]
        [string]
        ${ImpersonationAuthorizationRulesFile},

        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [string]
        ${IssuanceTransformRules},

        [ValidateNotNullOrEmpty()]
        [string]
        ${IssuanceTransformRulesFile},

        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [string]
        ${IssuanceAuthorizationRules},

        [ValidateNotNullOrEmpty()]
        [string]
        ${IssuanceAuthorizationRulesFile},

        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [string]
        ${DelegationAuthorizationRules},

        [ValidateNotNullOrEmpty()]
        [string]
        ${DelegationAuthorizationRulesFile},

        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [string]
        ${AdditionalAuthenticationRules},

        [ValidateNotNullOrEmpty()]
        [string]
        ${AdditionalAuthenticationRulesFile},

        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [string]
        ${AccessControlPolicyName},

        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [System.Object]
        ${AccessControlPolicyParameters}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Add-AdfsScopeDescription {
    <#
    .SYNOPSIS
        Add-AdfsScopeDescription [-Name] <string> [-Description <string>] [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    param (
        [Parameter(Mandatory=$true, Position=0, ValueFromPipelineByPropertyName=$true)]
        [string]
        ${Name},

        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [string]
        ${Description},

        [switch]
        ${PassThru}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Add-AdfsServerApplication {
    <#
    .SYNOPSIS
        Add-AdfsServerApplication [-ApplicationGroupIdentifier] <string> [-Name] <string> [-Identifier] <string> [[-RedirectUri] <string[]>] [-Description <string>] [-ADUserPrincipalName <string>] [-JWTSigningCertificate <X509Certificate2[]>] [-JWTSigningCertificateRevocationCheck <RevocationSetting>] [-JWKSUri <uri>] [-LogoutUri <string>] [-JWKSFile <string>] [-GenerateClientSecret] [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]

Add-AdfsServerApplication [-ApplicationGroup] <ApplicationGroup> [-Name] <string> [-Identifier] <string> [[-RedirectUri] <string[]>] [-Description <string>] [-ADUserPrincipalName <string>] [-JWTSigningCertificate <X509Certificate2[]>] [-JWTSigningCertificateRevocationCheck <RevocationSetting>] [-JWKSUri <uri>] [-LogoutUri <string>] [-JWKSFile <string>] [-GenerateClientSecret] [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(DefaultParameterSetName='ApplicationGroupIdentifier', SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    param (
        [Parameter(ParameterSetName='ApplicationGroupIdentifier', Mandatory=$true, Position=0, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${ApplicationGroupIdentifier},

        [Parameter(ParameterSetName='ApplicationGroupObject', Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [Microsoft.IdentityServer.Management.Resources.ApplicationGroup]
        ${ApplicationGroup},

        [Parameter(Mandatory=$true, Position=1, ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${Name},

        [Parameter(Mandatory=$true, Position=2, ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${Identifier},

        [Parameter(Position=3, ValueFromPipelineByPropertyName=$true)]
        [string[]]
        ${RedirectUri},

        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [string]
        ${Description},

        [ValidateNotNullOrEmpty()]
        [string]
        ${ADUserPrincipalName},

        [ValidateNotNull()]
        [ValidateCount(1, 2147483647)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2[]]
        ${JWTSigningCertificate},

        [Microsoft.IdentityServer.PolicyModel.Configuration.RevocationSetting]
        ${JWTSigningCertificateRevocationCheck},

        [uri]
        ${JWKSUri},

        [ValidateNotNullOrEmpty()]
        [string]
        ${LogoutUri},

        [string]
        ${JWKSFile},

        [switch]
        ${GenerateClientSecret},

        [switch]
        ${PassThru}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Add-AdfsTrustedFederationPartner {
    <#
    .SYNOPSIS
        Add-AdfsTrustedFederationPartner [-Name] <string> [-FederationPartnerHostName] <uri> [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    param (
        [Parameter(Mandatory=$true, Position=0, ValueFromPipelineByPropertyName=$true)]
        [string]
        ${Name},

        [Parameter(Mandatory=$true, Position=1, ValueFromPipelineByPropertyName=$true)]
        [uri]
        ${FederationPartnerHostName},

        [switch]
        ${PassThru}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Add-AdfsWebApiApplication {
    <#
    .SYNOPSIS
        Add-AdfsWebApiApplication [-ApplicationGroupIdentifier] <string> -Name <string> -Identifier <string[]> [-AllowedAuthenticationClassReferences <string[]>] [-ClaimsProviderName <string[]>] [-IssuanceAuthorizationRules <string>] [-IssuanceAuthorizationRulesFile <string>] [-DelegationAuthorizationRules <string>] [-DelegationAuthorizationRulesFile <string>] [-ImpersonationAuthorizationRules <string>] [-ImpersonationAuthorizationRulesFile <string>] [-IssuanceTransformRules <string>] [-IssuanceTransformRulesFile <string>] [-AdditionalAuthenticationRules <string>] [-AdditionalAuthenticationRulesFile <string>] [-AccessControlPolicyName <string>] [-AccessControlPolicyParameters <Object>] [-NotBeforeSkew <int>] [-Description <string>] [-TokenLifetime <int>] [-AlwaysRequireAuthentication] [-AllowedClientTypes <AllowedClientTypes>] [-IssueOAuthRefreshTokensTo <RefreshTokenIssuanceDeviceTypes>] [-RefreshTokenProtectionEnabled <bool>] [-RequestMFAFromClaimsProviders] [-DeviceAuthenticationMethod <DeviceAuthenticationMethod>] [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]

Add-AdfsWebApiApplication [-ApplicationGroup] <ApplicationGroup> -Name <string> -Identifier <string[]> [-AllowedAuthenticationClassReferences <string[]>] [-ClaimsProviderName <string[]>] [-IssuanceAuthorizationRules <string>] [-IssuanceAuthorizationRulesFile <string>] [-DelegationAuthorizationRules <string>] [-DelegationAuthorizationRulesFile <string>] [-ImpersonationAuthorizationRules <string>] [-ImpersonationAuthorizationRulesFile <string>] [-IssuanceTransformRules <string>] [-IssuanceTransformRulesFile <string>] [-AdditionalAuthenticationRules <string>] [-AdditionalAuthenticationRulesFile <string>] [-AccessControlPolicyName <string>] [-AccessControlPolicyParameters <Object>] [-NotBeforeSkew <int>] [-Description <string>] [-TokenLifetime <int>] [-AlwaysRequireAuthentication] [-AllowedClientTypes <AllowedClientTypes>] [-IssueOAuthRefreshTokensTo <RefreshTokenIssuanceDeviceTypes>] [-RefreshTokenProtectionEnabled <bool>] [-RequestMFAFromClaimsProviders] [-DeviceAuthenticationMethod <DeviceAuthenticationMethod>] [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(DefaultParameterSetName='ApplicationGroupIdentifier', SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    param (
        [Parameter(ParameterSetName='ApplicationGroupIdentifier', Mandatory=$true, Position=0, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${ApplicationGroupIdentifier},

        [Parameter(ParameterSetName='ApplicationGroupObject', Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [Microsoft.IdentityServer.Management.Resources.ApplicationGroup]
        ${ApplicationGroup},

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${Name},

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string[]]
        ${Identifier},

        [ValidateNotNull()]
        [string[]]
        ${AllowedAuthenticationClassReferences},

        [ValidateNotNull()]
        [string[]]
        ${ClaimsProviderName},

        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [string]
        ${IssuanceAuthorizationRules},

        [ValidateNotNullOrEmpty()]
        [string]
        ${IssuanceAuthorizationRulesFile},

        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [string]
        ${DelegationAuthorizationRules},

        [ValidateNotNullOrEmpty()]
        [string]
        ${DelegationAuthorizationRulesFile},

        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [string]
        ${ImpersonationAuthorizationRules},

        [ValidateNotNullOrEmpty()]
        [string]
        ${ImpersonationAuthorizationRulesFile},

        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [string]
        ${IssuanceTransformRules},

        [ValidateNotNullOrEmpty()]
        [string]
        ${IssuanceTransformRulesFile},

        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [string]
        ${AdditionalAuthenticationRules},

        [ValidateNotNullOrEmpty()]
        [string]
        ${AdditionalAuthenticationRulesFile},

        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [string]
        ${AccessControlPolicyName},

        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [System.Object]
        ${AccessControlPolicyParameters},

        [ValidateRange(0, 15)]
        [System.Nullable[int]]
        ${NotBeforeSkew},

        [ValidateNotNullOrEmpty()]
        [string]
        ${Description},

        [System.Nullable[int]]
        ${TokenLifetime},

        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [switch]
        ${AlwaysRequireAuthentication},

        [Microsoft.IdentityServer.Protocols.PolicyStore.AllowedClientTypes]
        ${AllowedClientTypes},

        [Microsoft.IdentityServer.Protocols.PolicyStore.RefreshTokenIssuanceDeviceTypes]
        ${IssueOAuthRefreshTokensTo},

        [System.Nullable[bool]]
        ${RefreshTokenProtectionEnabled},

        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [switch]
        ${RequestMFAFromClaimsProviders},

        [System.Nullable[Microsoft.IdentityServer.PolicyModel.Configuration.DeviceAuthenticationMethod]]
        ${DeviceAuthenticationMethod},

        [switch]
        ${PassThru}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Add-AdfsWebApplicationProxyRelyingPartyTrust {
    <#
    .SYNOPSIS
        Add-AdfsWebApplicationProxyRelyingPartyTrust [-Name] <string> [-Identifier] <string[]> [-AlwaysRequireAuthentication] [-Enabled <bool>] [-AccessControlPolicyName <string>] [-AccessControlPolicyParameters <Object>] [-AdditionalAuthenticationRules <string>] [-AdditionalAuthenticationRulesFile <string>] [-NotBeforeSkew <int>] [-Notes <string>] [-PassThru] [-TokenLifetime <int>] [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Low')]
    param (
        [Parameter(Mandatory=$true, Position=0)]
        [ValidateNotNull()]
        [string]
        ${Name},

        [Parameter(Mandatory=$true, Position=1)]
        [ValidateNotNull()]
        [string[]]
        ${Identifier},

        [switch]
        ${AlwaysRequireAuthentication},

        [bool]
        ${Enabled},

        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [string]
        ${AccessControlPolicyName},

        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [System.Object]
        ${AccessControlPolicyParameters},

        [ValidateNotNullOrEmpty()]
        [string]
        ${AdditionalAuthenticationRules},

        [ValidateNotNullOrEmpty()]
        [string]
        ${AdditionalAuthenticationRulesFile},

        [ValidateRange(0, 15)]
        [int]
        ${NotBeforeSkew},

        [ValidateNotNullOrEmpty()]
        [string]
        ${Notes},

        [switch]
        ${PassThru},

        [int]
        ${TokenLifetime}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Disable-AdfsApplicationGroup {
    <#
    .SYNOPSIS
        Disable-AdfsApplicationGroup [-TargetApplicationGroupIdentifier] <string> [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]

Disable-AdfsApplicationGroup [-TargetName] <string> [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]

Disable-AdfsApplicationGroup [-TargetApplicationGroup] <ApplicationGroup> [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(DefaultParameterSetName='ApplicationGroupIdentifier', SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    param (
        [Parameter(ParameterSetName='Name', Mandatory=$true, Position=0, ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${TargetName},

        [Parameter(ParameterSetName='ApplicationGroupIdentifier', Mandatory=$true, Position=0, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${TargetApplicationGroupIdentifier},

        [Parameter(ParameterSetName='ApplicationGroupObject', Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [Microsoft.IdentityServer.Management.Resources.ApplicationGroup]
        ${TargetApplicationGroup},

        [switch]
        ${PassThru}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Disable-AdfsCertificateAuthority {
    <#
    .SYNOPSIS
        Disable-AdfsCertificateAuthority [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Low')]
    param (
        [switch]
        ${PassThru}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Disable-AdfsClaimsProviderTrust {
    <#
    .SYNOPSIS
        Disable-AdfsClaimsProviderTrust -TargetClaimsProviderTrust <ClaimsProviderTrust> [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]

Disable-AdfsClaimsProviderTrust -TargetCertificate <X509Certificate2> [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]

Disable-AdfsClaimsProviderTrust -TargetIdentifier <string> [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]

Disable-AdfsClaimsProviderTrust -TargetName <string> [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Low')]
    param (
        [Parameter(ParameterSetName='IdentifierObject', Mandatory=$true, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [Microsoft.IdentityServer.Management.Resources.ClaimsProviderTrust]
        ${TargetClaimsProviderTrust},

        [Parameter(ParameterSetName='TokenSigningCertificates', Mandatory=$true, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]
        ${TargetCertificate},

        [Parameter(ParameterSetName='Identifier', Mandatory=$true, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [string]
        ${TargetIdentifier},

        [Parameter(ParameterSetName='IdentifierName', Mandatory=$true, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [string]
        ${TargetName},

        [switch]
        ${PassThru}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Disable-AdfsClient {
    <#
    .SYNOPSIS
        Disable-AdfsClient [[-TargetName] <string>] [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]

Disable-AdfsClient [-TargetClientId] <string> [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]

Disable-AdfsClient [-TargetClient] <AdfsClient> [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(DefaultParameterSetName='Name', SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    param (
        [Parameter(ParameterSetName='ClientId', Mandatory=$true, Position=0, ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${TargetClientId},

        [Parameter(ParameterSetName='Name', Position=0, ValueFromPipelineByPropertyName=$true)]
        [string]
        ${TargetName},

        [Parameter(ParameterSetName='InputObject', Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [Microsoft.IdentityServer.Management.Resources.AdfsClient]
        ${TargetClient},

        [switch]
        ${PassThru}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Disable-AdfsDeviceRegistration {
    <#
    .SYNOPSIS
        Disable-AdfsDeviceRegistration [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    param ( )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Disable-AdfsEndpoint {
    <#
    .SYNOPSIS
        Disable-AdfsEndpoint [[-TargetAddressPath] <string>] [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]

Disable-AdfsEndpoint [-TargetEndpoint] <Endpoint> [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]

Disable-AdfsEndpoint [-TargetFullUrl] <uri> [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Low')]
    param (
        [Parameter(ParameterSetName='Address', Position=0, ValueFromPipeline=$true)]
        [AllowNull()]
        [string]
        ${TargetAddressPath},

        [Parameter(ParameterSetName='TargetObject', Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [Microsoft.IdentityServer.Management.Resources.Endpoint]
        ${TargetEndpoint},

        [Parameter(ParameterSetName='FullUrl', Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [uri]
        ${TargetFullUrl},

        [switch]
        ${PassThru}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Disable-AdfsLocalClaimsProviderTrust {
    <#
    .SYNOPSIS
        Disable-AdfsLocalClaimsProviderTrust -TargetClaimsProviderTrust <LocalClaimsProviderTrust> [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]

Disable-AdfsLocalClaimsProviderTrust -TargetIdentifier <string> [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]

Disable-AdfsLocalClaimsProviderTrust -TargetName <string> [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Low')]
    param (
        [Parameter(ParameterSetName='IdentifierObject', Mandatory=$true, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [Microsoft.IdentityServer.Management.Resources.LocalClaimsProviderTrust]
        ${TargetClaimsProviderTrust},

        [Parameter(ParameterSetName='Identifier', Mandatory=$true, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [string]
        ${TargetIdentifier},

        [Parameter(ParameterSetName='IdentifierName', Mandatory=$true, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [string]
        ${TargetName},

        [switch]
        ${PassThru}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Disable-AdfsNonClaimsAwareRelyingPartyTrust {
    <#
    .SYNOPSIS
        Disable-AdfsNonClaimsAwareRelyingPartyTrust [-TargetName] <string> [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]

Disable-AdfsNonClaimsAwareRelyingPartyTrust -TargetIdentifier <string> [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]

Disable-AdfsNonClaimsAwareRelyingPartyTrust -TargetNonClaimsAwareRelyingPartyTrust <NonClaimsAwareRelyingPartyTrust> [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(DefaultParameterSetName='IdentifierName', SupportsShouldProcess=$true, ConfirmImpact='Low')]
    param (
        [switch]
        ${PassThru},

        [Parameter(ParameterSetName='Identifier', Mandatory=$true)]
        [ValidateNotNull()]
        [string]
        ${TargetIdentifier},

        [Parameter(ParameterSetName='IdentifierName', Mandatory=$true, Position=0)]
        [ValidateNotNull()]
        [string]
        ${TargetName},

        [Parameter(ParameterSetName='IdentifierObject', Mandatory=$true, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [Microsoft.IdentityServer.Management.Resources.NonClaimsAwareRelyingPartyTrust]
        ${TargetNonClaimsAwareRelyingPartyTrust}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Disable-AdfsRelyingPartyTrust {
    <#
    .SYNOPSIS
        Disable-AdfsRelyingPartyTrust -TargetIdentifier <string> [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]

Disable-AdfsRelyingPartyTrust -TargetRelyingParty <RelyingPartyTrust> [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]

Disable-AdfsRelyingPartyTrust -TargetName <string> [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Low')]
    param (
        [Parameter(ParameterSetName='Identifier', Mandatory=$true, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [string]
        ${TargetIdentifier},

        [Parameter(ParameterSetName='IdentifierObject', Mandatory=$true, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [Microsoft.IdentityServer.Management.Resources.RelyingPartyTrust]
        ${TargetRelyingParty},

        [Parameter(ParameterSetName='IdentifierName', Mandatory=$true, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [string]
        ${TargetName},

        [switch]
        ${PassThru}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Disable-AdfsWebApplicationProxyRelyingPartyTrust {
    <#
    .SYNOPSIS
        Disable-AdfsWebApplicationProxyRelyingPartyTrust [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Low')]
    param (
        [switch]
        ${PassThru}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Enable-AdfsApplicationGroup {
    <#
    .SYNOPSIS
        Enable-AdfsApplicationGroup [-TargetApplicationGroupIdentifier] <string> [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]

Enable-AdfsApplicationGroup [-TargetName] <string> [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]

Enable-AdfsApplicationGroup [-TargetApplicationGroup] <ApplicationGroup> [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(DefaultParameterSetName='ApplicationGroupIdentifier', SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    param (
        [Parameter(ParameterSetName='Name', Mandatory=$true, Position=0, ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${TargetName},

        [Parameter(ParameterSetName='ApplicationGroupIdentifier', Mandatory=$true, Position=0, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${TargetApplicationGroupIdentifier},

        [Parameter(ParameterSetName='ApplicationGroupObject', Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [Microsoft.IdentityServer.Management.Resources.ApplicationGroup]
        ${TargetApplicationGroup},

        [switch]
        ${PassThru}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
F    }
}

function Enable-AdfsClaimsProviderTrust {
    <#
    .SYNOPSIS
        Enable-AdfsClaimsProviderTrust -TargetClaimsProviderTrust <ClaimsProviderTrust> [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]

Enable-AdfsClaimsProviderTrust -TargetCertificate <X509Certificate2> [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]

Enable-AdfsClaimsProviderTrust -TargetIdentifier <string> [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]

Enable-AdfsClaimsProviderTrust -TargetName <string> [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Low')]
    param (
        [Parameter(ParameterSetName='IdentifierObject', Mandatory=$true, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [Microsoft.IdentityServer.Management.Resources.ClaimsProviderTrust]
        ${TargetClaimsProviderTrust},

        [Parameter(ParameterSetName='TokenSigningCertificates', Mandatory=$true, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]
        ${TargetCertificate},

        [Parameter(ParameterSetName='Identifier', Mandatory=$true, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [string]
        ${TargetIdentifier},

        [Parameter(ParameterSetName='IdentifierName', Mandatory=$true, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [string]
        ${TargetName},

        [switch]
        ${PassThru}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Enable-AdfsClient {
    <#
    .SYNOPSIS
        Enable-AdfsClient [[-TargetName] <string>] [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]

Enable-AdfsClient [-TargetClientId] <string> [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]

Enable-AdfsClient [-TargetClient] <AdfsClient> [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(DefaultParameterSetName='Name', SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    param (
        [Parameter(ParameterSetName='ClientId', Mandatory=$true, Position=0, ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${TargetClientId},

        [Parameter(ParameterSetName='Name', Position=0, ValueFromPipelineByPropertyName=$true)]
        [string]
        ${TargetName},

        [Parameter(ParameterSetName='InputObject', Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [Microsoft.IdentityServer.Management.Resources.AdfsClient]
        ${TargetClient},

        [switch]
        ${PassThru}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Enable-AdfsDeviceRegistration {
    <#
    .SYNOPSIS
        Enable-AdfsDeviceRegistration [-Credential <pscredential>] [-Force] [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(DefaultParameterSetName='__AllParameterSets', SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    param (
        [pscredential]
        ${Credential},

        [switch]
        ${Force}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Enable-AdfsEndpoint {
    <#
    .SYNOPSIS
        Enable-AdfsEndpoint [[-TargetAddressPath] <string>] [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]

Enable-AdfsEndpoint [-TargetEndpoint] <Endpoint> [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]

Enable-AdfsEndpoint [-TargetFullUrl] <uri> [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Low')]
    param (
        [Parameter(ParameterSetName='Address', Position=0, ValueFromPipeline=$true)]
        [AllowNull()]
        [string]
        ${TargetAddressPath},

        [Parameter(ParameterSetName='TargetObject', Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [Microsoft.IdentityServer.Management.Resources.Endpoint]
        ${TargetEndpoint},

        [Parameter(ParameterSetName='FullUrl', Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [uri]
        ${TargetFullUrl},

        [switch]
        ${PassThru}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Enable-AdfsLocalClaimsProviderTrust {
    <#
    .SYNOPSIS
        Enable-AdfsLocalClaimsProviderTrust -TargetClaimsProviderTrust <LocalClaimsProviderTrust> [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]

Enable-AdfsLocalClaimsProviderTrust -TargetIdentifier <string> [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]

Enable-AdfsLocalClaimsProviderTrust -TargetName <string> [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Low')]
    param (
        [Parameter(ParameterSetName='IdentifierObject', Mandatory=$true, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [Microsoft.IdentityServer.Management.Resources.LocalClaimsProviderTrust]
        ${TargetClaimsProviderTrust},

        [Parameter(ParameterSetName='Identifier', Mandatory=$true, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [string]
        ${TargetIdentifier},

        [Parameter(ParameterSetName='IdentifierName', Mandatory=$true, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [string]
        ${TargetName},

        [switch]
        ${PassThru}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Enable-AdfsNonClaimsAwareRelyingPartyTrust {
    <#
    .SYNOPSIS
        Enable-AdfsNonClaimsAwareRelyingPartyTrust [-TargetName] <string> [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]

Enable-AdfsNonClaimsAwareRelyingPartyTrust -TargetIdentifier <string> [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]

Enable-AdfsNonClaimsAwareRelyingPartyTrust -TargetNonClaimsAwareRelyingPartyTrust <NonClaimsAwareRelyingPartyTrust> [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(DefaultParameterSetName='IdentifierName', SupportsShouldProcess=$true, ConfirmImpact='Low')]
    param (
        [switch]
        ${PassThru},

        [Parameter(ParameterSetName='Identifier', Mandatory=$true)]
        [ValidateNotNull()]
        [string]
        ${TargetIdentifier},

        [Parameter(ParameterSetName='IdentifierName', Mandatory=$true, Position=0)]
        [ValidateNotNull()]
        [string]
        ${TargetName},

        [Parameter(ParameterSetName='IdentifierObject', Mandatory=$true, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [Microsoft.IdentityServer.Management.Resources.NonClaimsAwareRelyingPartyTrust]
        ${TargetNonClaimsAwareRelyingPartyTrust}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Enable-AdfsRelyingPartyTrust {
    <#
    .SYNOPSIS
        Enable-AdfsRelyingPartyTrust -TargetIdentifier <string> [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]

Enable-AdfsRelyingPartyTrust -TargetRelyingParty <RelyingPartyTrust> [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]

Enable-AdfsRelyingPartyTrust -TargetName <string> [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Low')]
    param (
        [Parameter(ParameterSetName='Identifier', Mandatory=$true, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [string]
        ${TargetIdentifier},

        [Parameter(ParameterSetName='IdentifierObject', Mandatory=$true, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [Microsoft.IdentityServer.Management.Resources.RelyingPartyTrust]
        ${TargetRelyingParty},

        [Parameter(ParameterSetName='IdentifierName', Mandatory=$true, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [string]
        ${TargetName},

        [switch]
        ${PassThru}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Enable-AdfsWebApplicationProxyRelyingPartyTrust {
    <#
    .SYNOPSIS
        Enable-AdfsWebApplicationProxyRelyingPartyTrust [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Low')]
    param (
        [switch]
        ${PassThru}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Export-AdfsAuthenticationProviderConfigurationData {
    <#
    .SYNOPSIS
        Export-AdfsAuthenticationProviderConfigurationData -Name <string> -FilePath <string> [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Low')]
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${Name},

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${FilePath}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Export-AdfsDeploymentSQLScript {
    <#
    .SYNOPSIS
        Export-AdfsDeploymentSQLScript -DestinationFolder <string> -ServiceAccountName <string> [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${DestinationFolder},

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${ServiceAccountName}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Export-AdfsThreatDetectionModuleConfiguration {
    <#
    .SYNOPSIS
        Export-AdfsThreatDetectionModuleConfiguration -Name <string> -ConfigurationFilePath <string> [<CommonParameters>]
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${Name},

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${ConfigurationFilePath}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Export-AdfsWebContent {
    <#
    .SYNOPSIS
        Export-AdfsWebContent [[-Locale] <cultureinfo>] -FilePath <string> [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    param (
        [Parameter(Position=0, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [cultureinfo]
        ${Locale},

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${FilePath}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Export-AdfsWebTheme {
    <#
    .SYNOPSIS
        Export-AdfsWebTheme -Name <string> -DirectoryPath <string> [-WhatIf] [-Confirm] [<CommonParameters>]

Export-AdfsWebTheme -RelyingPartyName <string> -DirectoryPath <string> [-WhatIf] [-Confirm] [<CommonParameters>]

Export-AdfsWebTheme -WebTheme <WebThemeBase> -DirectoryPath <string> [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    param (
        [Parameter(ParameterSetName='IdentifierName', Mandatory=$true, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${Name},

        [Parameter(ParameterSetName='RelyingPartyName', Mandatory=$true, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${RelyingPartyName},

        [Parameter(ParameterSetName='IdentifierObject', Mandatory=$true, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [Microsoft.IdentityServer.Management.Resources.WebThemeBase]
        ${WebTheme},

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${DirectoryPath}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Get-AdfsAccessControlPolicy {
    <#
    .SYNOPSIS
        Get-AdfsAccessControlPolicy [-Name <string[]>] [-Identifier <string[]>] [<CommonParameters>]
    #>

    [CmdletBinding()]
    param (
        [ValidateNotNullOrEmpty()]
        [string[]]
        ${Name},

        [ValidateNotNullOrEmpty()]
        [string[]]
        ${Identifier}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Get-AdfsAccountActivity {
    <#
    .SYNOPSIS
        Get-AdfsAccountActivity [-Identity] <string> [-Server <string>] [-WhatIf] [-Confirm] [<CommonParameters>]

Get-AdfsAccountActivity -UserPrincipalName <string> [-Server <string>] [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(DefaultParameterSetName='Identity', SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    param (
        [Parameter(ParameterSetName='Upn', Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${UserPrincipalName},

        [Parameter(ParameterSetName='Identity', Mandatory=$true, Position=0, ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${Identity},

        [ValidateNotNullOrEmpty()]
        [string]
        ${Server}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Get-AdfsAdditionalAuthenticationRule {
    <#
    .SYNOPSIS
        Get-AdfsAdditionalAuthenticationRule [<CommonParameters>]
    #>

    [CmdletBinding()]
    param ( )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Get-AdfsApplicationGroup {
    <#
    .SYNOPSIS
        Get-AdfsApplicationGroup [[-ApplicationGroupIdentifier] <string[]>] [<CommonParameters>]

Get-AdfsApplicationGroup [-Name] <string[]> [<CommonParameters>]

Get-AdfsApplicationGroup [-ApplicationGroup] <ApplicationGroup> [<CommonParameters>]
    #>

    [CmdletBinding(DefaultParameterSetName='ApplicationGroupIdentifier')]
    param (
        [Parameter(ParameterSetName='ApplicationGroupIdentifier', Position=0, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [string[]]
        ${ApplicationGroupIdentifier},

        [Parameter(ParameterSetName='Name', Mandatory=$true, Position=0, ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [string[]]
        ${Name},

        [Parameter(ParameterSetName='ApplicationGroupObject', Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [Microsoft.IdentityServer.Management.Resources.ApplicationGroup]
        ${ApplicationGroup}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Get-AdfsApplicationPermission {
    <#
    .SYNOPSIS
        Get-AdfsApplicationPermission [[-Identifiers] <string[]>] [<CommonParameters>]

Get-AdfsApplicationPermission [[-ClientRoleIdentifiers] <string[]>] [<CommonParameters>]

Get-AdfsApplicationPermission [[-ServerRoleIdentifiers] <string[]>] [<CommonParameters>]
    #>

    [CmdletBinding(DefaultParameterSetName='Identifier')]
    param (
        [Parameter(ParameterSetName='Identifier', Position=0, ValueFromPipelineByPropertyName=$true)]
        [string[]]
        ${Identifiers},

        [Parameter(ParameterSetName='ClientRoleIdentifier', Position=0, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [string[]]
        ${ClientRoleIdentifiers},

        [Parameter(ParameterSetName='ServerRoleIdentifier', Position=0, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [string[]]
        ${ServerRoleIdentifiers}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Get-AdfsAttributeStore {
    <#
    .SYNOPSIS
        Get-AdfsAttributeStore [[-Name] <string[]>] [<CommonParameters>]
    #>

    [CmdletBinding()]
    param (
        [Parameter(Position=0, ValueFromPipeline=$true)]
        [AllowNull()]
        [string[]]
        ${Name}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Get-AdfsAuthenticationProvider {
    <#
    .SYNOPSIS
        Get-AdfsAuthenticationProvider [[-Name] <string>] [<CommonParameters>]
    #>

    [CmdletBinding()]
    param (
        [Parameter(Position=0)]
        [string]
        ${Name}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Get-AdfsAuthenticationProviderWebContent {
    <#
    .SYNOPSIS
        Get-AdfsAuthenticationProviderWebContent [-Locale <cultureinfo>] [-Name <string[]>] [<CommonParameters>]
    #>

    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNull()]
        [cultureinfo]
        ${Locale},

        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNull()]
        [string[]]
        ${Name}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Get-AdfsAzureMfaConfigured {
    <#
    .SYNOPSIS
        Get-AdfsAzureMfaConfigured [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    param ( )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Get-AdfsCertificate {
    <#
    .SYNOPSIS
        Get-AdfsCertificate [[-CertificateType] <string[]>] [<CommonParameters>]

Get-AdfsCertificate [-Thumbprint] <string[]> [<CommonParameters>]
    #>

    [CmdletBinding(DefaultParameterSetName='ByType')]
    param (
        [Parameter(ParameterSetName='ByType', Position=0)]
        [ValidateSet('Service-Communications','Token-Decrypting','Token-Signing')]
        [AllowNull()]
        [string[]]
        ${CertificateType},

        [Parameter(ParameterSetName='ByReference', Mandatory=$true, Position=0)]
        [ValidateNotNullOrEmpty()]
        [string[]]
        ${Thumbprint}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Get-AdfsCertificateAuthority {
    <#
    .SYNOPSIS
        Get-AdfsCertificateAuthority [<CommonParameters>]
    #>

    [CmdletBinding()]
    param ( )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Get-AdfsClaimDescription {
    <#
    .SYNOPSIS
        Get-AdfsClaimDescription [[-Name] <string[]>] [<CommonParameters>]

Get-AdfsClaimDescription -ClaimType <string[]> [<CommonParameters>]

Get-AdfsClaimDescription -ShortName <string[]> [<CommonParameters>]
    #>

    [CmdletBinding(DefaultParameterSetName='Name')]
    param (
        [Parameter(ParameterSetName='Name', Position=0, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [AllowNull()]
        [string[]]
        ${Name},

        [Parameter(ParameterSetName='Identifier', Mandatory=$true, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [string[]]
        ${ClaimType},

        [Parameter(ParameterSetName='ShortName', Mandatory=$true, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [string[]]
        ${ShortName}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Get-AdfsClaimsProviderTrust {
    <#
    .SYNOPSIS
        Get-AdfsClaimsProviderTrust [[-Name] <string[]>] [<CommonParameters>]

Get-AdfsClaimsProviderTrust [-Certificate] <X509Certificate2[]> [<CommonParameters>]

Get-AdfsClaimsProviderTrust [-Identifier] <string[]> [<CommonParameters>]
    #>

    [CmdletBinding(DefaultParameterSetName='ClaimsProviderName')]
    param (
        [Parameter(ParameterSetName='TokenSigningCertificates', Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [System.Security.Cryptography.X509Certificates.X509Certificate2[]]
        ${Certificate},

        [Parameter(ParameterSetName='Identifier', Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [string[]]
        ${Identifier},

        [Parameter(ParameterSetName='ClaimsProviderName', Position=0, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [AllowNull()]
        [string[]]
        ${Name}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Get-AdfsClaimsProviderTrustsGroup {
    <#
    .SYNOPSIS
        Get-AdfsClaimsProviderTrustsGroup [[-Identifier] <string[]>] [<CommonParameters>]
    #>

    [CmdletBinding()]
    param (
        [Parameter(Position=0, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [string[]]
        ${Identifier}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Get-AdfsClient {
    <#
    .SYNOPSIS
        Get-AdfsClient [[-Name] <string[]>] [<CommonParameters>]

Get-AdfsClient [-ClientId] <string[]> [<CommonParameters>]

Get-AdfsClient [-InputObject] <AdfsClient> [<CommonParameters>]
    #>

    [CmdletBinding(DefaultParameterSetName='Name')]
    param (
        [Parameter(ParameterSetName='ClientId', Mandatory=$true, Position=0, ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [string[]]
        ${ClientId},

        [Parameter(ParameterSetName='Name', Position=0, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [AllowNull()]
        [string[]]
        ${Name},

        [Parameter(ParameterSetName='InputObject', Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [Microsoft.IdentityServer.Management.Resources.AdfsClient]
        ${InputObject}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Get-AdfsDebugLogConsumersConfiguration {
    <#
    .SYNOPSIS
        Get-AdfsDebugLogConsumersConfiguration -Consumer <DebugLogConsumer> [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        [Microsoft.IdentityServer.Management.Commands.DebugLogConsumer]
        ${Consumer}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Get-AdfsDeviceRegistration {
    <#
    .SYNOPSIS
        Get-AdfsDeviceRegistration [<CommonParameters>]
    #>

    [CmdletBinding()]
    param ( )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Get-AdfsDeviceRegistrationUpnSuffix {
    <#
    .SYNOPSIS
        Get-AdfsDeviceRegistrationUpnSuffix [<CommonParameters>]
    #>

    [CmdletBinding()]
    param ( )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Get-AdfsDirectoryProperties {
    <#
    .SYNOPSIS
        Get-AdfsDirectoryProperties [<CommonParameters>]
    #>

    [CmdletBinding()]
    param ( )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Get-AdfsEndpoint {
    <#
    .SYNOPSIS
        Get-AdfsEndpoint [[-AddressPath] <string[]>] [<CommonParameters>]

Get-AdfsEndpoint [-FullUrl] <uri[]> [<CommonParameters>]
    #>

    [CmdletBinding(DefaultParameterSetName='Address')]
    param (
        [Parameter(ParameterSetName='Address', Position=0, ValueFromPipeline=$true)]
        [AllowNull()]
        [string[]]
        ${AddressPath},

        [Parameter(ParameterSetName='FullUrl', Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [uri[]]
        ${FullUrl}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Get-AdfsFarmInformation {
    <#
    .SYNOPSIS
        Get-AdfsFarmInformation [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Low')]
    param ( )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Get-AdfsGlobalAuthenticationPolicy {
    <#
    .SYNOPSIS
        Get-AdfsGlobalAuthenticationPolicy [<CommonParameters>]
    #>

    [CmdletBinding()]
    param ( )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Get-AdfsGlobalWebContent {
    <#
    .SYNOPSIS
        Get-AdfsGlobalWebContent [-Locale <cultureinfo[]>] [<CommonParameters>]
    #>

    [CmdletBinding(DefaultParameterSetName='IdentifierName')]
    param (
        [ValidateNotNull()]
        [cultureinfo[]]
        ${Locale}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Get-AdfsLocalClaimsProviderTrust {
    <#
    .SYNOPSIS
        Get-AdfsLocalClaimsProviderTrust [[-Name] <string[]>] [<CommonParameters>]

Get-AdfsLocalClaimsProviderTrust [-Identifier] <string[]> [<CommonParameters>]
    #>

    [CmdletBinding(DefaultParameterSetName='ClaimsProviderName')]
    param (
        [Parameter(ParameterSetName='Identifier', Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [string[]]
        ${Identifier},

        [Parameter(ParameterSetName='ClaimsProviderName', Position=0, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [AllowNull()]
        [string[]]
        ${Name}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Get-AdfsNativeClientApplication {
    <#
    .SYNOPSIS
        Get-AdfsNativeClientApplication [[-Identifier] <string[]>] [<CommonParameters>]

Get-AdfsNativeClientApplication [-Name] <string[]> [<CommonParameters>]

Get-AdfsNativeClientApplication [-Application] <NativeClientApplication> [<CommonParameters>]

Get-AdfsNativeClientApplication [-ApplicationGroupIdentifier] <string> [<CommonParameters>]

Get-AdfsNativeClientApplication [-ApplicationGroup] <ApplicationGroup> [<CommonParameters>]
    #>

    [CmdletBinding(DefaultParameterSetName='Identifier')]
    param (
        [Parameter(ParameterSetName='Identifier', Position=0, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [string[]]
        ${Identifier},

        [Parameter(ParameterSetName='Name', Mandatory=$true, Position=0, ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [string[]]
        ${Name},

        [Parameter(ParameterSetName='ApplicationObject', Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [Microsoft.IdentityServer.Management.Resources.NativeClientApplication]
        ${Application},

        [Parameter(ParameterSetName='ApplicationGroupIdentifier', Mandatory=$true, Position=0)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${ApplicationGroupIdentifier},

        [Parameter(ParameterSetName='ApplicationGroupObject', Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [Microsoft.IdentityServer.Management.Resources.ApplicationGroup]
        ${ApplicationGroup}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Get-AdfsNonClaimsAwareRelyingPartyTrust {
    <#
    .SYNOPSIS
        Get-AdfsNonClaimsAwareRelyingPartyTrust [<CommonParameters>]

Get-AdfsNonClaimsAwareRelyingPartyTrust -TargetIdentifier <string> [<CommonParameters>]

Get-AdfsNonClaimsAwareRelyingPartyTrust [-TargetName] <string> [<CommonParameters>]

Get-AdfsNonClaimsAwareRelyingPartyTrust -TargetNonClaimsAwareRelyingPartyTrust <NonClaimsAwareRelyingPartyTrust> [<CommonParameters>]
    #>

    [CmdletBinding(DefaultParameterSetName='__AllParameterSets')]
    param (
        [Parameter(ParameterSetName='Identifier', Mandatory=$true)]
        [ValidateNotNull()]
        [string]
        ${TargetIdentifier},

        [Parameter(ParameterSetName='IdentifierName', Mandatory=$true, Position=0)]
        [ValidateNotNull()]
        [string]
        ${TargetName},

        [Parameter(ParameterSetName='IdentifierObject', Mandatory=$true, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [Microsoft.IdentityServer.Management.Resources.NonClaimsAwareRelyingPartyTrust]
        ${TargetNonClaimsAwareRelyingPartyTrust}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Get-AdfsProperties {
    <#
    .SYNOPSIS
        Get-AdfsProperties [<CommonParameters>]
    #>

    [CmdletBinding()]
    param ( )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Get-AdfsRegistrationHosts {
    <#
    .SYNOPSIS
        Get-AdfsRegistrationHosts [-PassThru] [<CommonParameters>]
    #>

    [CmdletBinding()]
    param (
        [switch]
        ${PassThru}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Get-AdfsRelyingPartyTrust {
    <#
    .SYNOPSIS
        Get-AdfsRelyingPartyTrust [[-Name] <string[]>] [<CommonParameters>]

Get-AdfsRelyingPartyTrust [-Identifier] <string[]> [<CommonParameters>]

Get-AdfsRelyingPartyTrust [-PrefixIdentifier] <string> [<CommonParameters>]
    #>

    [CmdletBinding(DefaultParameterSetName='RelyingPartyName')]
    param (
        [Parameter(ParameterSetName='Identifier', Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [string[]]
        ${Identifier},

        [Parameter(ParameterSetName='RelyingPartyName', Position=0, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [AllowNull()]
        [string[]]
        ${Name},

        [Parameter(ParameterSetName='PrefixIdentifier', Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${PrefixIdentifier}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Get-AdfsRelyingPartyTrustsGroup {
    <#
    .SYNOPSIS
        Get-AdfsRelyingPartyTrustsGroup [[-Identifier] <string[]>] [<CommonParameters>]
    #>

    [CmdletBinding()]
    param (
        [Parameter(Position=0, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [AllowNull()]
        [string[]]
        ${Identifier}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Get-AdfsRelyingPartyWebContent {
    <#
    .SYNOPSIS
        Get-AdfsRelyingPartyWebContent [-Locale <cultureinfo>] [-RelyingPartyName <string[]>] [<CommonParameters>]
    #>

    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNull()]
        [cultureinfo]
        ${Locale},

        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [Alias('Name')]
        [ValidateNotNull()]
        [string[]]
        ${RelyingPartyName}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Get-AdfsRelyingPartyWebTheme {
    <#
    .SYNOPSIS
        Get-AdfsRelyingPartyWebTheme [-RelyingPartyName <string[]>] [<CommonParameters>]
    #>

    [CmdletBinding()]
    param (
        [Alias('Name')]
        [ValidateNotNullOrEmpty()]
        [string[]]
        ${RelyingPartyName}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Get-AdfsResponseHeaders {
    <#
    .SYNOPSIS
        Get-AdfsResponseHeaders [<CommonParameters>]
    #>

    [CmdletBinding()]
    param ( )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Get-AdfsScopeDescription {
    <#
    .SYNOPSIS
        Get-AdfsScopeDescription [[-Name] <string[]>] [<CommonParameters>]
    #>

    [CmdletBinding()]
    param (
        [Parameter(Position=0, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [AllowNull()]
        [string[]]
        ${Name}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Get-AdfsServerApplication {
    <#
    .SYNOPSIS
        Get-AdfsServerApplication [[-Identifier] <string[]>] [<CommonParameters>]

Get-AdfsServerApplication [-Name] <string[]> [<CommonParameters>]

Get-AdfsServerApplication [-Application] <ServerApplication> [<CommonParameters>]

Get-AdfsServerApplication [-ApplicationGroupIdentifier] <string> [<CommonParameters>]

Get-AdfsServerApplication [-ApplicationGroup] <ApplicationGroup> [<CommonParameters>]
    #>

    [CmdletBinding(DefaultParameterSetName='Identifier')]
    param (
        [Parameter(ParameterSetName='Identifier', Position=0, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [string[]]
        ${Identifier},

        [Parameter(ParameterSetName='Name', Mandatory=$true, Position=0, ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [string[]]
        ${Name},

        [Parameter(ParameterSetName='ApplicationObject', Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [Microsoft.IdentityServer.Management.Resources.ServerApplication]
        ${Application},

        [Parameter(ParameterSetName='ApplicationGroupIdentifier', Mandatory=$true, Position=0)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${ApplicationGroupIdentifier},

        [Parameter(ParameterSetName='ApplicationGroupObject', Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [Microsoft.IdentityServer.Management.Resources.ApplicationGroup]
        ${ApplicationGroup}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Get-AdfsSslCertificate {
    <#
    .SYNOPSIS
        Get-AdfsSslCertificate [<CommonParameters>]
    #>

    [CmdletBinding()]
    param ( )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Get-AdfsSyncProperties {
    <#
    .SYNOPSIS
        Get-AdfsSyncProperties [<CommonParameters>]
    #>

    [CmdletBinding()]
    param ( )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Get-AdfsThreatDetectionModule {
    <#
    .SYNOPSIS
        Get-AdfsThreatDetectionModule [-Name <string>] [<CommonParameters>]
    #>

    [CmdletBinding()]
    param (
        [ValidateNotNullOrEmpty()]
        [string]
        ${Name}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Get-AdfsTrustedFederationPartner {
    <#
    .SYNOPSIS
        Get-AdfsTrustedFederationPartner [[-Name] <string[]>] [<CommonParameters>]

Get-AdfsTrustedFederationPartner [-FederationPartnerHostName] <uri[]> [<CommonParameters>]
    #>

    [CmdletBinding(DefaultParameterSetName='Name')]
    param (
        [Parameter(ParameterSetName='Name', Position=0, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [AllowNull()]
        [string[]]
        ${Name},

        [Parameter(ParameterSetName='FederationPartnerHostName', Mandatory=$true, Position=0, ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [uri[]]
        ${FederationPartnerHostName}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Get-AdfsWebApiApplication {
    <#
    .SYNOPSIS
        Get-AdfsWebApiApplication [[-Identifier] <string[]>] [<CommonParameters>]

Get-AdfsWebApiApplication [-Name] <string[]> [<CommonParameters>]

Get-AdfsWebApiApplication [-PrefixIdentifier] <string> [<CommonParameters>]

Get-AdfsWebApiApplication [-Application] <WebApiApplication> [<CommonParameters>]

Get-AdfsWebApiApplication [-ApplicationGroupIdentifier] <string> [<CommonParameters>]

Get-AdfsWebApiApplication [-ApplicationGroup] <ApplicationGroup> [<CommonParameters>]
    #>

    [CmdletBinding(DefaultParameterSetName='Identifier')]
    param (
        [Parameter(ParameterSetName='Identifier', Position=0, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [string[]]
        ${Identifier},

        [Parameter(ParameterSetName='Name', Mandatory=$true, Position=0, ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [string[]]
        ${Name},

        [Parameter(ParameterSetName='PrefixIdentifier', Mandatory=$true, Position=0)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${PrefixIdentifier},

        [Parameter(ParameterSetName='ApplicationObject', Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [Microsoft.IdentityServer.Management.Resources.WebApiApplication]
        ${Application},

        [Parameter(ParameterSetName='ApplicationGroupIdentifier', Mandatory=$true, Position=0, ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${ApplicationGroupIdentifier},

        [Parameter(ParameterSetName='ApplicationGroupObject', Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [Microsoft.IdentityServer.Management.Resources.ApplicationGroup]
        ${ApplicationGroup}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Get-AdfsWebApplicationProxyRelyingPartyTrust {
    <#
    .SYNOPSIS
        Get-AdfsWebApplicationProxyRelyingPartyTrust [<CommonParameters>]
    #>

    [CmdletBinding()]
    param ( )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Get-AdfsWebConfig {
    <#
    .SYNOPSIS
        Get-AdfsWebConfig [<CommonParameters>]
    #>

    [CmdletBinding()]
    param ( )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Get-AdfsWebTheme {
    <#
    .SYNOPSIS
        Get-AdfsWebTheme [-Name <string>] [<CommonParameters>]
    #>

    [CmdletBinding()]
    param (
        [ValidateNotNullOrEmpty()]
        [string]
        ${Name}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Grant-AdfsApplicationPermission {
    <#
    .SYNOPSIS
        Grant-AdfsApplicationPermission [-ClientRoleIdentifier] <string> [-ServerRoleIdentifier] <string> [[-ScopeNames] <string[]>] [-Description <string>] [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]

Grant-AdfsApplicationPermission -AllowAllRegisteredClients [-ServerRoleIdentifier] <string> [[-ScopeNames] <string[]>] [-Description <string>] [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(DefaultParameterSetName='ClientRoleIdentifier', SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    param (
        [Parameter(ParameterSetName='ClientRoleIdentifier', Mandatory=$true, Position=0, ValueFromPipelineByPropertyName=$true)]
        [string]
        ${ClientRoleIdentifier},

        [Parameter(ParameterSetName='PermitAllRegisteredClients', Mandatory=$true, Position=0, ValueFromPipelineByPropertyName=$true)]
        [ValidateSet('true')]
        [switch]
        ${AllowAllRegisteredClients},

        [Parameter(Mandatory=$true, Position=1, ValueFromPipelineByPropertyName=$true)]
        [string]
        ${ServerRoleIdentifier},

        [Parameter(Position=2, ValueFromPipelineByPropertyName=$true)]
        [string[]]
        ${ScopeNames},

        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [string]
        ${Description},

        [switch]
        ${PassThru}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Import-AdfsAuthenticationProviderConfigurationData {
    <#
    .SYNOPSIS
        Import-AdfsAuthenticationProviderConfigurationData -Name <string> -FilePath <string> [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${Name},

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${FilePath}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Import-AdfsThreatDetectionModuleConfiguration {
    <#
    .SYNOPSIS
        Import-AdfsThreatDetectionModuleConfiguration -Name <string> -ConfigurationFilePath <string> [<CommonParameters>]
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${Name},

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${ConfigurationFilePath}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Import-AdfsWebContent {
    <#
    .SYNOPSIS
        Import-AdfsWebContent [[-Locale] <cultureinfo>] -FilePath <string> [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    param (
        [Parameter(Position=0, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [cultureinfo]
        ${Locale},

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${FilePath}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Initialize-ADDeviceRegistration {
    <#
    .SYNOPSIS
        Initialize-ADDeviceRegistration -ServiceAccountName <string> [-DeviceLocation <string>] [-RegistrationQuota <uint32>] [-MaximumRegistrationInactivityPeriod <uint32>] [-Credential <pscredential>] [-Force] [-DiscoveryName <string>] [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
    param (
        [Parameter(Mandatory=$true)]
        [string]
        ${ServiceAccountName},

        [string]
        ${DeviceLocation},

        [uint32]
        ${RegistrationQuota},

        [uint32]
        ${MaximumRegistrationInactivityPeriod},

        [pscredential]
        ${Credential},

        [switch]
        ${Force},

        [string]
        ${DiscoveryName}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Install-AdfsFarm {
    <#
    .SYNOPSIS
        Install-AdfsFarm -FederationServiceName <string> -ServiceAccountCredential <pscredential> [-CertificateThumbprint <string>] [-Credential <pscredential>] [-FederationServiceDisplayName <string>] [-OverwriteConfiguration] [-SSLPort <int>] [-TlsClientPort <int>] [-AdminConfiguration <hashtable>] [-WhatIf] [-Confirm] [<CommonParameters>]

Install-AdfsFarm -DecryptionCertificateThumbprint <string> -FederationServiceName <string> -ServiceAccountCredential <pscredential> -SigningCertificateThumbprint <string> [-CertificateThumbprint <string>] [-Credential <pscredential>] [-FederationServiceDisplayName <string>] [-OverwriteConfiguration] [-SSLPort <int>] [-TlsClientPort <int>] [-AdminConfiguration <hashtable>] [-WhatIf] [-Confirm] [<CommonParameters>]

Install-AdfsFarm -DecryptionCertificateThumbprint <string> -FederationServiceName <string> -ServiceAccountCredential <pscredential> -SigningCertificateThumbprint <string> -SQLConnectionString <string> [-CertificateThumbprint <string>] [-Credential <pscredential>] [-FederationServiceDisplayName <string>] [-OverwriteConfiguration] [-SSLPort <int>] [-TlsClientPort <int>] [-AdminConfiguration <hashtable>] [-WhatIf] [-Confirm] [<CommonParameters>]

Install-AdfsFarm -DecryptionCertificateThumbprint <string> -FederationServiceName <string> -GroupServiceAccountIdentifier <string> -SigningCertificateThumbprint <string> [-CertificateThumbprint <string>] [-Credential <pscredential>] [-FederationServiceDisplayName <string>] [-OverwriteConfiguration] [-SSLPort <int>] [-TlsClientPort <int>] [-AdminConfiguration <hashtable>] [-WhatIf] [-Confirm] [<CommonParameters>]

Install-AdfsFarm -DecryptionCertificateThumbprint <string> -FederationServiceName <string> -GroupServiceAccountIdentifier <string> -SigningCertificateThumbprint <string> -SQLConnectionString <string> [-CertificateThumbprint <string>] [-Credential <pscredential>] [-FederationServiceDisplayName <string>] [-OverwriteConfiguration] [-SSLPort <int>] [-TlsClientPort <int>] [-AdminConfiguration <hashtable>] [-WhatIf] [-Confirm] [<CommonParameters>]

Install-AdfsFarm -FederationServiceName <string> -ServiceAccountCredential <pscredential> -SQLConnectionString <string> [-CertificateThumbprint <string>] [-Credential <pscredential>] [-FederationServiceDisplayName <string>] [-OverwriteConfiguration] [-SSLPort <int>] [-TlsClientPort <int>] [-AdminConfiguration <hashtable>] [-WhatIf] [-Confirm] [<CommonParameters>]

Install-AdfsFarm -FederationServiceName <string> -GroupServiceAccountIdentifier <string> [-CertificateThumbprint <string>] [-Credential <pscredential>] [-FederationServiceDisplayName <string>] [-OverwriteConfiguration] [-SSLPort <int>] [-TlsClientPort <int>] [-AdminConfiguration <hashtable>] [-WhatIf] [-Confirm] [<CommonParameters>]

Install-AdfsFarm -FederationServiceName <string> -GroupServiceAccountIdentifier <string> -SQLConnectionString <string> [-CertificateThumbprint <string>] [-Credential <pscredential>] [-FederationServiceDisplayName <string>] [-OverwriteConfiguration] [-SSLPort <int>] [-TlsClientPort <int>] [-AdminConfiguration <hashtable>] [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(DefaultParameterSetName='ADFSFarmCreateLocalDatabase', SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    param (
        [ValidateLength(1, 8192)]
        [string]
        ${CertificateThumbprint},

        [pscredential]
        ${Credential},

        [Parameter(ParameterSetName='ADFSFarmCreateLocalDatabaseDisableAutoCertRollover', Mandatory=$true)]
        [Parameter(ParameterSetName='ADFSFarmCreateSharedDatabaseDisableAutoCertRollover', Mandatory=$true)]
        [Parameter(ParameterSetName='AdfsFarmCreateLocalDatabaseDisableAutoCertRolloverGmsa', Mandatory=$true)]
        [Parameter(ParameterSetName='AdfsFarmCreateSharedDatabaseDisableAutoCertRolloverGmsa', Mandatory=$true)]
        [ValidateLength(1, 8192)]
        [string]
        ${DecryptionCertificateThumbprint},

        [Parameter(Mandatory=$true)]
        [ValidateLength(1, 255)]
        [string]
        ${FederationServiceName},

        [ValidateLength(0, 8192)]
        [string]
        ${FederationServiceDisplayName},

        [Parameter(ParameterSetName='ADFSFarmCreateLocalDatabase', Mandatory=$true)]
        [Parameter(ParameterSetName='ADFSFarmCreateSharedDatabase', Mandatory=$true)]
        [Parameter(ParameterSetName='ADFSFarmCreateLocalDatabaseDisableAutoCertRollover', Mandatory=$true)]
        [Parameter(ParameterSetName='ADFSFarmCreateSharedDatabaseDisableAutoCertRollover', Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [pscredential]
        ${ServiceAccountCredential},

        [Parameter(ParameterSetName='AdfsFarmCreateLocalDatabaseGmsa', Mandatory=$true)]
        [Parameter(ParameterSetName='AdfsFarmCreateSharedDatabaseGmsa', Mandatory=$true)]
        [Parameter(ParameterSetName='AdfsFarmCreateLocalDatabaseDisableAutoCertRolloverGmsa', Mandatory=$true)]
        [Parameter(ParameterSetName='AdfsFarmCreateSharedDatabaseDisableAutoCertRolloverGmsa', Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${GroupServiceAccountIdentifier},

        [Parameter(ParameterSetName='ADFSFarmCreateLocalDatabaseDisableAutoCertRollover', Mandatory=$true)]
        [Parameter(ParameterSetName='ADFSFarmCreateSharedDatabaseDisableAutoCertRollover', Mandatory=$true)]
        [Parameter(ParameterSetName='AdfsFarmCreateLocalDatabaseDisableAutoCertRolloverGmsa', Mandatory=$true)]
        [Parameter(ParameterSetName='AdfsFarmCreateSharedDatabaseDisableAutoCertRolloverGmsa', Mandatory=$true)]
        [ValidateLength(1, 8192)]
        [string]
        ${SigningCertificateThumbprint},

        [Parameter(ParameterSetName='ADFSFarmCreateSharedDatabase', Mandatory=$true)]
        [Parameter(ParameterSetName='ADFSFarmCreateSharedDatabaseDisableAutoCertRollover', Mandatory=$true)]
        [Parameter(ParameterSetName='AdfsFarmCreateSharedDatabaseGmsa', Mandatory=$true)]
        [Parameter(ParameterSetName='AdfsFarmCreateSharedDatabaseDisableAutoCertRolloverGmsa', Mandatory=$true)]
        [ValidateLength(1, 1024)]
        [string]
        ${SQLConnectionString},

        [switch]
        ${OverwriteConfiguration},

        [ValidateRange(1, 65535)]
        [int]
        ${SSLPort},

        [ValidateRange(1, 65535)]
        [int]
        ${TlsClientPort},

        [ValidateNotNull()]
        [ValidateCount(1, 1)]
        [hashtable]
        ${AdminConfiguration}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Invoke-AdfsFarmBehaviorLevelRaise {
    <#
    .SYNOPSIS
        Invoke-AdfsFarmBehaviorLevelRaise [-Member <string[]>] [-Credential <pscredential>] [-ServiceAccountCredential <pscredential>] [-Force] [-WhatIf] [-Confirm] [<CommonParameters>]

Invoke-AdfsFarmBehaviorLevelRaise [-Member <string[]>] [-Credential <pscredential>] [-GroupServiceAccountIdentifier <string>] [-Force] [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(DefaultParameterSetName='AdfsUpgradeServiceAccount', SupportsShouldProcess=$true, ConfirmImpact='High')]
    param (
        [ValidateNotNullOrEmpty()]
        [string[]]
        ${Member},

        [pscredential]
        ${Credential},

        [Parameter(ParameterSetName='AdfsUpgradeServiceAccount')]
        [pscredential]
        ${ServiceAccountCredential},

        [Parameter(ParameterSetName='AdfsUpgradeGmsaAccount')]
        [string]
        ${GroupServiceAccountIdentifier},

        [switch]
        ${Force}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function New-AdfsAccessControlPolicy {
    <#
    .SYNOPSIS
        New-AdfsAccessControlPolicy -Name <string> [-SourceName <string>] [-Identifier <string>] [-Description <string>] [-PolicyMetadata <PolicyMetadata>] [-PolicyMetadataFile <string>] [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Low')]
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${Name},

        [ValidateNotNullOrEmpty()]
        [string]
        ${SourceName},

        [ValidateNotNullOrEmpty()]
        [string]
        ${Identifier},

        [ValidateNotNullOrEmpty()]
        [string]
        ${Description},

        [ValidateNotNullOrEmpty()]
        [Microsoft.IdentityServer.PolicyModel.Configuration.PolicyTemplate.PolicyMetadata]
        ${PolicyMetadata},

        [ValidateNotNullOrEmpty()]
        [string]
        ${PolicyMetadataFile}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function New-AdfsApplicationGroup {
    <#
    .SYNOPSIS
        New-AdfsApplicationGroup [-Name] <string> [[-ApplicationGroupIdentifier] <string>] [-Description <string>] [-Disabled] [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    param (
        [Parameter(Mandatory=$true, Position=0, ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${Name},

        [Parameter(Position=1, ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${ApplicationGroupIdentifier},

        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [string]
        ${Description},

        [switch]
        ${Disabled},

        [switch]
        ${PassThru}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function New-AdfsAzureMfaTenantCertificate {
    <#
    .SYNOPSIS
        New-AdfsAzureMfaTenantCertificate -TenantId <string> [-Renew <bool>] [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${TenantId},

        [bool]
        ${Renew}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function New-AdfsClaimRuleSet {
    <#
    .SYNOPSIS
        New-AdfsClaimRuleSet -ClaimRule <string[]> [<CommonParameters>]

New-AdfsClaimRuleSet -ClaimRuleFile <string> [<CommonParameters>]
    #>

    [CmdletBinding()]
    param (
        [Parameter(ParameterSetName='FromParams', Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string[]]
        ${ClaimRule},

        [Parameter(ParameterSetName='FromFile', Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${ClaimRuleFile}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function New-AdfsContactPerson {
    <#
    .SYNOPSIS
        New-AdfsContactPerson [-Company <string>] [-EmailAddress <string[]>] [-GivenName <string>] [-TelephoneNumber <string[]>] [-Surname <string>] [<CommonParameters>]
    #>

    [CmdletBinding()]
    param (
        [ValidateNotNullOrEmpty()]
        [string]
        ${Company},

        [ValidateNotNull()]
        [string[]]
        ${EmailAddress},

        [ValidateNotNullOrEmpty()]
        [string]
        ${GivenName},

        [ValidateNotNullOrEmpty()]
        [string[]]
        ${TelephoneNumber},

        [ValidateNotNullOrEmpty()]
        [string]
        ${Surname}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function New-AdfsLdapAttributeToClaimMapping {
    <#
    .SYNOPSIS
        New-AdfsLdapAttributeToClaimMapping [-LdapAttribute] <string> [[-ClaimType] <string>] [<CommonParameters>]
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, Position=0)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${LdapAttribute},

        [Parameter(Position=1)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${ClaimType}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function New-AdfsLdapServerConnection {
    <#
    .SYNOPSIS
        New-AdfsLdapServerConnection [-HostName] <string> [-Port <int>] [-SslMode <LdapSslMode>] [-AuthenticationMethod <LdapAuthenticationMethod>] [-Credential <pscredential>] [<CommonParameters>]
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, Position=0)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${HostName},

        [System.Nullable[int]]
        ${Port},

        [Microsoft.IdentityServer.Management.Resources.LdapSslMode]
        ${SslMode},

        [System.Nullable[Microsoft.IdentityServer.Management.Resources.LdapAuthenticationMethod]]
        ${AuthenticationMethod},

        [pscredential]
        ${Credential}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function New-AdfsOrganization {
    <#
    .SYNOPSIS
        New-AdfsOrganization -DisplayName <string> -OrganizationUrl <uri> [-Name <string>] [<CommonParameters>]
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        [string]
        ${DisplayName},

        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        [uri]
        ${OrganizationUrl},

        [ValidateNotNull()]
        [string]
        ${Name}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function New-AdfsSamlEndpoint {
    <#
    .SYNOPSIS
        New-AdfsSamlEndpoint -Binding <string> -Protocol <string> -Uri <uri> [-IsDefault <bool>] [-Index <int>] [-ResponseUri <uri>] [<CommonParameters>]
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [ValidateSet('Artifact','POST','Redirect','SOAP')]
        [string]
        ${Binding},

        [Parameter(Mandatory=$true)]
        [ValidateSet('SAMLArtifactResolution','SAMLAssertionConsumer','SAMLLogout','SAMLSingleSignOn')]
        [string]
        ${Protocol},

        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        [uri]
        ${Uri},

        [System.Nullable[bool]]
        ${IsDefault},

        [System.Nullable[int]]
        ${Index},

        [uri]
        ${ResponseUri}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function New-AdfsWebTheme {
    <#
    .SYNOPSIS
        New-AdfsWebTheme -Name <string> [-SourceName <string>] [-StyleSheet <hashtable[]>] [-RTLStyleSheetPath <string>] [-OnLoadScriptPath <string>] [-Logo <hashtable[]>] [-Illustration <hashtable[]>] [-AdditionalFileResource <hashtable[]>] [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Low')]
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${Name},

        [ValidateNotNullOrEmpty()]
        [string]
        ${SourceName},

        [ValidateNotNullOrEmpty()]
        [hashtable[]]
        ${StyleSheet},

        [ValidateNotNullOrEmpty()]
        [string]
        ${RTLStyleSheetPath},

        [ValidateNotNullOrEmpty()]
        [string]
        ${OnLoadScriptPath},

        [ValidateNotNullOrEmpty()]
        [hashtable[]]
        ${Logo},

        [ValidateNotNullOrEmpty()]
        [hashtable[]]
        ${Illustration},

        [ValidateNotNullOrEmpty()]
        [hashtable[]]
        ${AdditionalFileResource}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Publish-SslCertificate {
    <#
    .SYNOPSIS
        Publish-SslCertificate -Path <string> -Password <securestring> [<CommonParameters>]

Publish-SslCertificate -RawPfx <byte[]> -Password <securestring> [<CommonParameters>]
    #>

    [CmdletBinding(DefaultParameterSetName='PublishByPfxPath')]
    param (
        [Parameter(ParameterSetName='PublishByPfxPath', Mandatory=$true)]
        [string]
        ${Path},

        [Parameter(ParameterSetName='PublishByPfxData', Mandatory=$true)]
        [byte[]]
        ${RawPfx},

        [Parameter(ParameterSetName='PublishByPfxPath', Mandatory=$true)]
        [Parameter(ParameterSetName='PublishByPfxData', Mandatory=$true)]
        [securestring]
        ${Password}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Register-AdfsAuthenticationProvider {
    <#
    .SYNOPSIS
        Register-AdfsAuthenticationProvider -TypeName <string> -Name <string> [-ConfigurationFilePath <string>] [<CommonParameters>]
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${TypeName},

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${Name},

        [ValidateNotNullOrEmpty()]
        [string]
        ${ConfigurationFilePath}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Register-AdfsThreatDetectionModule {
    <#
    .SYNOPSIS
        Register-AdfsThreatDetectionModule [-Name] <string> [-TypeName] <string> [-ConfigurationFilePath <string>] [<CommonParameters>]
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, Position=1)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${TypeName},

        [Parameter(Mandatory=$true, Position=0)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${Name},

        [ValidateNotNullOrEmpty()]
        [string]
        ${ConfigurationFilePath}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Remove-AdfsAccessControlPolicy {
    <#
    .SYNOPSIS
        Remove-AdfsAccessControlPolicy [-TargetName] <string> [-WhatIf] [-Confirm] [<CommonParameters>]

Remove-AdfsAccessControlPolicy [-TargetIdentifier] <string> [-WhatIf] [-Confirm] [<CommonParameters>]

Remove-AdfsAccessControlPolicy [-TargetAccessControlPolicy] <AdfsAccessControlPolicy> [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    param (
        [Parameter(ParameterSetName='IdentifierName', Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${TargetName},

        [Parameter(ParameterSetName='Identifier', Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${TargetIdentifier},

        [Parameter(ParameterSetName='IdentifierObject', Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [Microsoft.IdentityServer.Management.Resources.AdfsAccessControlPolicy]
        ${TargetAccessControlPolicy}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Remove-AdfsApplicationGroup {
    <#
    .SYNOPSIS
        Remove-AdfsApplicationGroup [-TargetApplicationGroupIdentifier] <string> [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]

Remove-AdfsApplicationGroup [-TargetName] <string> [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]

Remove-AdfsApplicationGroup [-TargetApplicationGroup] <ApplicationGroup> [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(DefaultParameterSetName='ApplicationGroupIdentifier', SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    param (
        [Parameter(ParameterSetName='Name', Mandatory=$true, Position=0, ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${TargetName},

        [Parameter(ParameterSetName='ApplicationGroupIdentifier', Mandatory=$true, Position=0, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${TargetApplicationGroupIdentifier},

        [Parameter(ParameterSetName='ApplicationGroupObject', Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [Microsoft.IdentityServer.Management.Resources.ApplicationGroup]
        ${TargetApplicationGroup},

        [switch]
        ${PassThru}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Remove-AdfsAttributeStore {
    <#
    .SYNOPSIS
        Remove-AdfsAttributeStore [-TargetName] <string> [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]

Remove-AdfsAttributeStore [-TargetAttributeStore] <AttributeStore> [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    param (
        [Parameter(ParameterSetName='Name', Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${TargetName},

        [Parameter(ParameterSetName='InputObject', Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [Microsoft.IdentityServer.Management.Resources.AttributeStore]
        ${TargetAttributeStore},

        [switch]
        ${PassThru}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Remove-AdfsAuthenticationProviderWebContent {
    <#
    .SYNOPSIS
        Remove-AdfsAuthenticationProviderWebContent [[-Locale] <cultureinfo>] -Name <string> [-WhatIf] [-Confirm] [<CommonParameters>]

Remove-AdfsAuthenticationProviderWebContent [-TargetWebContent] <AdfsAuthProviderWebContent> [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(DefaultParameterSetName='IdentifierName', SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    param (
        [Parameter(ParameterSetName='IdentifierName', Position=0)]
        [ValidateNotNull()]
        [cultureinfo]
        ${Locale},

        [Parameter(ParameterSetName='IdentifierName', Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${Name},

        [Parameter(ParameterSetName='IdentifierObject', Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [Microsoft.IdentityServer.Management.Resources.AdfsAuthProviderWebContent]
        ${TargetWebContent}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Remove-AdfsCertificate {
    <#
    .SYNOPSIS
        Remove-AdfsCertificate [-TargetCertificate] <ServiceCertificate> [-WhatIf] [-Confirm] [<CommonParameters>]

Remove-AdfsCertificate -CertificateType <string> -Thumbprint <string> [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(DefaultParameterSetName='TargetCertificate', SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    param (
        [Parameter(ParameterSetName='ByProperties', Mandatory=$true)]
        [ValidateSet('Token-Decrypting','Token-Signing')]
        [string]
        ${CertificateType},

        [Parameter(ParameterSetName='ByProperties', Mandatory=$true, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [string]
        ${Thumbprint},

        [Parameter(ParameterSetName='TargetCertificate', Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [Microsoft.IdentityServer.Management.Resources.ServiceCertificate]
        ${TargetCertificate}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Remove-AdfsClaimDescription {
    <#
    .SYNOPSIS
        Remove-AdfsClaimDescription [-TargetName] <string> [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]

Remove-AdfsClaimDescription [-TargetShortName] <string> [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]

Remove-AdfsClaimDescription [-TargetClaimType] <string> [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]

Remove-AdfsClaimDescription [-TargetClaimDescription] <ClaimDescription> [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    param (
        [Parameter(ParameterSetName='Name', Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [string]
        ${TargetName},

        [Parameter(ParameterSetName='ShortName', Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [string]
        ${TargetShortName},

        [Parameter(ParameterSetName='Identifier', Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [string]
        ${TargetClaimType},

        [Parameter(ParameterSetName='InputObject', Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [Microsoft.IdentityServer.Management.Resources.ClaimDescription]
        ${TargetClaimDescription},

        [switch]
        ${PassThru}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Remove-AdfsClaimsProviderTrust {
    <#
    .SYNOPSIS
        Remove-AdfsClaimsProviderTrust -TargetClaimsProviderTrust <ClaimsProviderTrust> [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]

Remove-AdfsClaimsProviderTrust -TargetCertificate <X509Certificate2> [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]

Remove-AdfsClaimsProviderTrust -TargetIdentifier <string> [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]

Remove-AdfsClaimsProviderTrust -TargetName <string> [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    param (
        [Parameter(ParameterSetName='IdentifierObject', Mandatory=$true, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [Microsoft.IdentityServer.Management.Resources.ClaimsProviderTrust]
        ${TargetClaimsProviderTrust},

        [Parameter(ParameterSetName='TokenSigningCertificates', Mandatory=$true, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]
        ${TargetCertificate},

        [Parameter(ParameterSetName='Identifier', Mandatory=$true, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [string]
        ${TargetIdentifier},

        [Parameter(ParameterSetName='IdentifierName', Mandatory=$true, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [string]
        ${TargetName},

        [switch]
        ${PassThru}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Remove-AdfsClaimsProviderTrustsGroup {
    <#
    .SYNOPSIS
        Remove-AdfsClaimsProviderTrustsGroup -TargetIdentifier <string> [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    param (
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${TargetIdentifier}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Remove-AdfsClient {
    <#
    .SYNOPSIS
        Remove-AdfsClient [-TargetName] <string> [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]

Remove-AdfsClient [-TargetClientId] <string> [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]

Remove-AdfsClient [-TargetClient] <AdfsClient> [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(DefaultParameterSetName='Name', SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    param (
        [Parameter(ParameterSetName='ClientId', Mandatory=$true, Position=0, ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${TargetClientId},

        [Parameter(ParameterSetName='Name', Mandatory=$true, Position=0, ValueFromPipelineByPropertyName=$true)]
        [string]
        ${TargetName},

        [Parameter(ParameterSetName='InputObject', Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [Microsoft.IdentityServer.Management.Resources.AdfsClient]
        ${TargetClient},

        [switch]
        ${PassThru}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Remove-AdfsDeviceRegistrationUpnSuffix {
    <#
    .SYNOPSIS
        Remove-AdfsDeviceRegistrationUpnSuffix [-UpnSuffix] <string> [-Force] [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
    param (
        [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [string]
        ${UpnSuffix},

        [ValidateNotNull()]
        [switch]
        ${Force}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Remove-AdfsFarmNode {
    <#
    .SYNOPSIS
        Remove-AdfsFarmNode -ServiceAccountCredential <pscredential> [<CommonParameters>]

Remove-AdfsFarmNode -GroupServiceAccountIdentifier <string> [-Credential <pscredential>] [<CommonParameters>]
    #>

    [CmdletBinding(DefaultParameterSetName='ADFSRemoveFarmNodeDefault')]
    param (
        [Parameter(ParameterSetName='ADFSRemoveFarmNodeDefault', Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [pscredential]
        ${ServiceAccountCredential},

        [Parameter(ParameterSetName='AdfsRemoveFarmNodeGmsa', Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${GroupServiceAccountIdentifier},

        [Parameter(ParameterSetName='AdfsRemoveFarmNodeGmsa')]
        [ValidateNotNullOrEmpty()]
        [pscredential]
        ${Credential}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Remove-AdfsGlobalWebContent {
    <#
    .SYNOPSIS
        Remove-AdfsGlobalWebContent [[-Locale] <cultureinfo>] [-WhatIf] [-Confirm] [<CommonParameters>]

Remove-AdfsGlobalWebContent [-TargetWebContent] <AdfsGlobalWebContent> [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(DefaultParameterSetName='IdentifierName', SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    param (
        [Parameter(ParameterSetName='IdentifierName', Position=0, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [cultureinfo]
        ${Locale},

        [Parameter(ParameterSetName='IdentifierObject', Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [Microsoft.IdentityServer.Management.Resources.AdfsGlobalWebContent]
        ${TargetWebContent}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Remove-AdfsLocalClaimsProviderTrust {
    <#
    .SYNOPSIS
        Remove-AdfsLocalClaimsProviderTrust -TargetClaimsProviderTrust <LocalClaimsProviderTrust> [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]

Remove-AdfsLocalClaimsProviderTrust -TargetIdentifier <string> [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]

Remove-AdfsLocalClaimsProviderTrust -TargetName <string> [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    param (
        [Parameter(ParameterSetName='IdentifierObject', Mandatory=$true, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [Microsoft.IdentityServer.Management.Resources.LocalClaimsProviderTrust]
        ${TargetClaimsProviderTrust},

        [Parameter(ParameterSetName='Identifier', Mandatory=$true, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [string]
        ${TargetIdentifier},

        [Parameter(ParameterSetName='IdentifierName', Mandatory=$true, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [string]
        ${TargetName},

        [switch]
        ${PassThru}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Remove-AdfsNativeClientApplication {
    <#
    .SYNOPSIS
        Remove-AdfsNativeClientApplication [-TargetIdentifier] <string> [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]

Remove-AdfsNativeClientApplication [-TargetName] <string> [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]

Remove-AdfsNativeClientApplication [-TargetApplication] <NativeClientApplication> [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(DefaultParameterSetName='Identifier', SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    param (
        [Parameter(ParameterSetName='Identifier', Mandatory=$true, Position=0, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${TargetIdentifier},

        [Parameter(ParameterSetName='Name', Mandatory=$true, Position=0, ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${TargetName},

        [Parameter(ParameterSetName='ApplicationObject', Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [Microsoft.IdentityServer.Management.Resources.NativeClientApplication]
        ${TargetApplication},

        [switch]
        ${PassThru}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Remove-AdfsNonClaimsAwareRelyingPartyTrust {
    <#
    .SYNOPSIS
        Remove-AdfsNonClaimsAwareRelyingPartyTrust [-TargetName] <string> [-WhatIf] [-Confirm] [<CommonParameters>]

Remove-AdfsNonClaimsAwareRelyingPartyTrust -TargetIdentifier <string> [-WhatIf] [-Confirm] [<CommonParameters>]

Remove-AdfsNonClaimsAwareRelyingPartyTrust -TargetNonClaimsAwareRelyingPartyTrust <NonClaimsAwareRelyingPartyTrust> [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(DefaultParameterSetName='IdentifierName', SupportsShouldProcess=$true, ConfirmImpact='High')]
    param (
        [Parameter(ParameterSetName='Identifier', Mandatory=$true)]
        [ValidateNotNull()]
        [string]
        ${TargetIdentifier},

        [Parameter(ParameterSetName='IdentifierName', Mandatory=$true, Position=0)]
        [ValidateNotNull()]
        [string]
        ${TargetName},

        [Parameter(ParameterSetName='IdentifierObject', Mandatory=$true, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [Microsoft.IdentityServer.Management.Resources.NonClaimsAwareRelyingPartyTrust]
        ${TargetNonClaimsAwareRelyingPartyTrust}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Remove-AdfsRelyingPartyTrust {
    <#
    .SYNOPSIS
        Remove-AdfsRelyingPartyTrust -TargetIdentifier <string> [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]

Remove-AdfsRelyingPartyTrust -TargetRelyingParty <RelyingPartyTrust> [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]

Remove-AdfsRelyingPartyTrust -TargetName <string> [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    param (
        [Parameter(ParameterSetName='Identifier', Mandatory=$true, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [string]
        ${TargetIdentifier},

        [Parameter(ParameterSetName='IdentifierObject', Mandatory=$true, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [Microsoft.IdentityServer.Management.Resources.RelyingPartyTrust]
        ${TargetRelyingParty},

        [Parameter(ParameterSetName='IdentifierName', Mandatory=$true, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [string]
        ${TargetName},

        [switch]
        ${PassThru}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Remove-AdfsRelyingPartyTrustsGroup {
    <#
    .SYNOPSIS
        Remove-AdfsRelyingPartyTrustsGroup -TargetIdentifier <string> [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    param (
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${TargetIdentifier}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Remove-AdfsRelyingPartyWebContent {
    <#
    .SYNOPSIS
        Remove-AdfsRelyingPartyWebContent [[-Locale] <cultureinfo>] -TargetRelyingPartyName <string> [-WhatIf] [-Confirm] [<CommonParameters>]

Remove-AdfsRelyingPartyWebContent [-TargetRelyingPartyWebContent] <AdfsRelyingPartyWebContent> [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(DefaultParameterSetName='IdentifierName', SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    param (
        [Parameter(ParameterSetName='IdentifierName', Position=0, ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNull()]
        [cultureinfo]
        ${Locale},

        [Parameter(ParameterSetName='IdentifierName', Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [Alias('Name')]
        [ValidateNotNullOrEmpty()]
        [string]
        ${TargetRelyingPartyName},

        [Parameter(ParameterSetName='IdentifierObject', Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [Alias('TargetWebContent')]
        [ValidateNotNull()]
        [Microsoft.IdentityServer.Management.Resources.AdfsRelyingPartyWebContent]
        ${TargetRelyingPartyWebContent}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Remove-AdfsRelyingPartyWebTheme {
    <#
    .SYNOPSIS
        Remove-AdfsRelyingPartyWebTheme [-TargetRelyingPartyName] <string> [-WhatIf] [-Confirm] [<CommonParameters>]

Remove-AdfsRelyingPartyWebTheme [-TargetRelyingPartyWebTheme] <AdfsRelyingPartyWebTheme> [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    param (
        [Parameter(ParameterSetName='IdentifierName', Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [Alias('Name')]
        [ValidateNotNullOrEmpty()]
        [string]
        ${TargetRelyingPartyName},

        [Parameter(ParameterSetName='IdentifierObject', Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [Alias('TargetWebTheme')]
        [ValidateNotNull()]
        [Microsoft.IdentityServer.Management.Resources.AdfsRelyingPartyWebTheme]
        ${TargetRelyingPartyWebTheme}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Remove-AdfsScopeDescription {
    <#
    .SYNOPSIS
        Remove-AdfsScopeDescription [-TargetName] <string> [-WhatIf] [-Confirm] [<CommonParameters>]

Remove-AdfsScopeDescription [-InputObject] <OAuthScopeDescription> [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    param (
        [Parameter(ParameterSetName='Name', Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [string]
        ${TargetName},

        [Parameter(ParameterSetName='InputObject', Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [Microsoft.IdentityServer.Management.Resources.OAuthScopeDescription]
        ${InputObject}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Remove-AdfsServerApplication {
    <#
    .SYNOPSIS
        Remove-AdfsServerApplication [-TargetIdentifier] <string> [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]

Remove-AdfsServerApplication [-TargetName] <string> [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]

Remove-AdfsServerApplication [-TargetApplication] <ServerApplication> [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(DefaultParameterSetName='Identifier', SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    param (
        [Parameter(ParameterSetName='Identifier', Mandatory=$true, Position=0, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${TargetIdentifier},

        [Parameter(ParameterSetName='Name', Mandatory=$true, Position=0, ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${TargetName},

        [Parameter(ParameterSetName='ApplicationObject', Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [Microsoft.IdentityServer.Management.Resources.ServerApplication]
        ${TargetApplication},

        [switch]
        ${PassThru}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Remove-AdfsTrustedFederationPartner {
    <#
    .SYNOPSIS
        Remove-AdfsTrustedFederationPartner [-TargetName] <string> [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]

Remove-AdfsTrustedFederationPartner [-TargetFederationPartnerHostName] <uri> [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]

Remove-AdfsTrustedFederationPartner [-TargetFederationPartner] <AdfsTrustedFederationPartner> [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(DefaultParameterSetName='Name', SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    param (
        [Parameter(ParameterSetName='Name', Mandatory=$true, Position=0, ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNull()]
        [string]
        ${TargetName},

        [Parameter(ParameterSetName='FederationPartnerHostName', Mandatory=$true, Position=0, ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNull()]
        [uri]
        ${TargetFederationPartnerHostName},

        [Parameter(ParameterSetName='InputObject', Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [Microsoft.IdentityServer.Management.Resources.AdfsTrustedFederationPartner]
        ${TargetFederationPartner},

        [switch]
        ${PassThru}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Remove-AdfsWebApiApplication {
    <#
    .SYNOPSIS
        Remove-AdfsWebApiApplication [-TargetIdentifier] <string> [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]

Remove-AdfsWebApiApplication [-TargetName] <string> [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]

Remove-AdfsWebApiApplication [-TargetApplication] <WebApiApplication> [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(DefaultParameterSetName='Identifier', SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    param (
        [Parameter(ParameterSetName='Identifier', Mandatory=$true, Position=0, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${TargetIdentifier},

        [Parameter(ParameterSetName='Name', Mandatory=$true, Position=0, ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${TargetName},

        [Parameter(ParameterSetName='ApplicationObject', Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [Microsoft.IdentityServer.Management.Resources.WebApiApplication]
        ${TargetApplication},

        [switch]
        ${PassThru}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Remove-AdfsWebApplicationProxyRelyingPartyTrust {
    <#
    .SYNOPSIS
        Remove-AdfsWebApplicationProxyRelyingPartyTrust [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
    param ( )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Remove-AdfsWebTheme {
    <#
    .SYNOPSIS
        Remove-AdfsWebTheme [-TargetName] <string> [-WhatIf] [-Confirm] [<CommonParameters>]

Remove-AdfsWebTheme [-TargetWebTheme] <AdfsWebTheme> [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    param (
        [Parameter(ParameterSetName='IdentifierName', Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${TargetName},

        [Parameter(ParameterSetName='IdentifierObject', Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [Microsoft.IdentityServer.Management.Resources.AdfsWebTheme]
        ${TargetWebTheme}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Reset-AdfsAccountLockout {
    <#
    .SYNOPSIS
        Reset-AdfsAccountLockout [-Identity] <string> [-Location] <LockoutLocation> [-Server <string>] [-WhatIf] [-Confirm] [<CommonParameters>]

Reset-AdfsAccountLockout [-Location] <LockoutLocation> -UserPrincipalName <string> [-Server <string>] [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(DefaultParameterSetName='Identity', SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    param (
        [Parameter(ParameterSetName='Upn', Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${UserPrincipalName},

        [Parameter(ParameterSetName='Identity', Mandatory=$true, Position=0, ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${Identity},

        [Parameter(Mandatory=$true, Position=1, ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [Microsoft.IdentityServer.Management.Commands.LockoutLocation]
        ${Location},

        [ValidateNotNullOrEmpty()]
        [string]
        ${Server}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Restore-AdfsFarmBehaviorLevel {
    <#
    .SYNOPSIS
        Restore-AdfsFarmBehaviorLevel -FarmBehavior <int> [-Member <string[]>] [-Credential <pscredential>] [-Force] [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
    param (
        [ValidateNotNullOrEmpty()]
        [string[]]
        ${Member},

        [pscredential]
        ${Credential},

        [Parameter(Mandatory=$true)]
        #[ValidateRange(Win2012R2, Max)]
        [int]
        ${FarmBehavior},

        [switch]
        ${Force}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Revoke-AdfsApplicationPermission {
    <#
    .SYNOPSIS
        Revoke-AdfsApplicationPermission [-TargetIdentifier] <string> [-WhatIf] [-Confirm] [<CommonParameters>]

Revoke-AdfsApplicationPermission [[-TargetClientRoleIdentifier] <string>] [[-TargetServerRoleIdentifier] <string>] [-WhatIf] [-Confirm] [<CommonParameters>]

Revoke-AdfsApplicationPermission [-InputObject] <OAuthPermission> [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(DefaultParameterSetName='Identifier', SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    param (
        [Parameter(ParameterSetName='Identifier', Mandatory=$true, Position=0, ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${TargetIdentifier},

        [Parameter(ParameterSetName='RoleIdentifier', Position=0, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [string]
        ${TargetClientRoleIdentifier},

        [Parameter(ParameterSetName='RoleIdentifier', Position=1, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [string]
        ${TargetServerRoleIdentifier},

        [Parameter(ParameterSetName='InputObject', Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [Microsoft.IdentityServer.Management.Resources.OAuthPermission]
        ${InputObject}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Revoke-AdfsProxyTrust {
    <#
    .SYNOPSIS
        Revoke-AdfsProxyTrust [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
    param ( )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Set-AdfsAccessControlPolicy {
    <#
    .SYNOPSIS
        Set-AdfsAccessControlPolicy [-TargetName] <string> [-Name <string>] [-Identifier <string>] [-Description <string>] [-PolicyMetadata <PolicyMetadata>] [-PolicyMetadataFile <string>] [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]

Set-AdfsAccessControlPolicy [-TargetIdentifier] <string> [-Name <string>] [-Identifier <string>] [-Description <string>] [-PolicyMetadata <PolicyMetadata>] [-PolicyMetadataFile <string>] [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]

Set-AdfsAccessControlPolicy [-TargetAccessControlPolicy] <AdfsAccessControlPolicy> [-Name <string>] [-Identifier <string>] [-Description <string>] [-PolicyMetadata <PolicyMetadata>] [-PolicyMetadataFile <string>] [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Low')]
    param (
        [ValidateNotNullOrEmpty()]
        [string]
        ${Name},

        [ValidateNotNullOrEmpty()]
        [string]
        ${Identifier},

        [ValidateNotNullOrEmpty()]
        [string]
        ${Description},

        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [Microsoft.IdentityServer.PolicyModel.Configuration.PolicyTemplate.PolicyMetadata]
        ${PolicyMetadata},

        [ValidateNotNullOrEmpty()]
        [string]
        ${PolicyMetadataFile},

        [switch]
        ${PassThru},

        [Parameter(ParameterSetName='IdentifierName', Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${TargetName},

        [Parameter(ParameterSetName='Identifier', Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${TargetIdentifier},

        [Parameter(ParameterSetName='IdentifierObject', Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [Microsoft.IdentityServer.Management.Resources.AdfsAccessControlPolicy]
        ${TargetAccessControlPolicy}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Set-AdfsAccountActivity {
    <#
    .SYNOPSIS
        Set-AdfsAccountActivity [-Identity] <string> [[-AdditionalFamiliarIps] <string[]>] [-Clear] [-Server <string>] [-WhatIf] [-Confirm] [<CommonParameters>]

Set-AdfsAccountActivity [[-AdditionalFamiliarIps] <string[]>] -UserPrincipalName <string> [-Clear] [-Server <string>] [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(DefaultParameterSetName='Identity', SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    param (
        [Parameter(ParameterSetName='Upn', Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${UserPrincipalName},

        [Parameter(ParameterSetName='Identity', Mandatory=$true, Position=0, ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${Identity},

        [Parameter(Position=1, ValueFromPipelineByPropertyName=$true)]
        [string[]]
        ${AdditionalFamiliarIps},

        [switch]
        ${Clear},

        [ValidateNotNullOrEmpty()]
        [string]
        ${Server}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Set-AdfsAdditionalAuthenticationRule {
    <#
    .SYNOPSIS
        Set-AdfsAdditionalAuthenticationRule [-AdditionalAuthenticationRules] <string> [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]

Set-AdfsAdditionalAuthenticationRule [-AdditionalAuthenticationRulesFile] <string> [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(DefaultParameterSetName='RuleSets', SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    param (
        [Parameter(ParameterSetName='RuleSets', Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [AllowNull()]
        [string]
        ${AdditionalAuthenticationRules},

        [Parameter(ParameterSetName='RuleSetFile', Mandatory=$true, Position=0)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${AdditionalAuthenticationRulesFile},

        [switch]
        ${PassThru}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Set-AdfsAlternateTlsClientBinding {
    <#
    .SYNOPSIS
        Set-AdfsAlternateTlsClientBinding [-Thumbprint <string>] [-Member <string[]>] [-Force <bool>] [-RemoteCredential <pscredential>] [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
    param (
        [ValidateNotNullOrEmpty()]
        [string]
        ${Thumbprint},

        [ValidateNotNullOrEmpty()]
        [string[]]
        ${Member},

        [bool]
        ${Force},

        [pscredential]
        ${RemoteCredential}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Set-AdfsApplicationGroup {
    <#
    .SYNOPSIS
        Set-AdfsApplicationGroup [-TargetApplicationGroupIdentifier] <string> [-Name <string>] [-ApplicationGroupIdentifier <string>] [-Description <string>] [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]

Set-AdfsApplicationGroup [-TargetName] <string> [-Name <string>] [-ApplicationGroupIdentifier <string>] [-Description <string>] [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]

Set-AdfsApplicationGroup [-TargetApplicationGroup] <ApplicationGroup> [-Name <string>] [-ApplicationGroupIdentifier <string>] [-Description <string>] [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(DefaultParameterSetName='ApplicationGroupIdentifier', SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    param (
        [Parameter(ParameterSetName='Name', Mandatory=$true, Position=0, ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${TargetName},

        [Parameter(ParameterSetName='ApplicationGroupIdentifier', Mandatory=$true, Position=0, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${TargetApplicationGroupIdentifier},

        [Parameter(ParameterSetName='ApplicationGroupObject', Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [Microsoft.IdentityServer.Management.Resources.ApplicationGroup]
        ${TargetApplicationGroup},

        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${Name},

        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${ApplicationGroupIdentifier},

        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [string]
        ${Description},

        [switch]
        ${PassThru}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Set-AdfsApplicationPermission {
    <#
    .SYNOPSIS
        Set-AdfsApplicationPermission [-TargetIdentifier] <string> [-ScopeNames <string[]>] [-Description <string>] [-WhatIf] [-Confirm] [<CommonParameters>]

Set-AdfsApplicationPermission [-TargetIdentifier] <string> -AddScope <string[]> [-Description <string>] [-WhatIf] [-Confirm] [<CommonParameters>]

Set-AdfsApplicationPermission [-TargetIdentifier] <string> -RemoveScope <string[]> [-Description <string>] [-WhatIf] [-Confirm] [<CommonParameters>]

Set-AdfsApplicationPermission [-InputObject] <OAuthPermission> [-ScopeNames <string[]>] [-Description <string>] [-WhatIf] [-Confirm] [<CommonParameters>]

Set-AdfsApplicationPermission [-InputObject] <OAuthPermission> -AddScope <string[]> [-Description <string>] [-WhatIf] [-Confirm] [<CommonParameters>]

Set-AdfsApplicationPermission [-InputObject] <OAuthPermission> -RemoveScope <string[]> [-Description <string>] [-WhatIf] [-Confirm] [<CommonParameters>]

Set-AdfsApplicationPermission [[-TargetClientRoleIdentifier] <string>] [[-TargetServerRoleIdentifier] <string>] [-ScopeNames <string[]>] [-Description <string>] [-WhatIf] [-Confirm] [<CommonParameters>]

Set-AdfsApplicationPermission [[-TargetClientRoleIdentifier] <string>] [[-TargetServerRoleIdentifier] <string>] -AddScope <string[]> [-Description <string>] [-WhatIf] [-Confirm] [<CommonParameters>]

Set-AdfsApplicationPermission [[-TargetClientRoleIdentifier] <string>] [[-TargetServerRoleIdentifier] <string>] -RemoveScope <string[]> [-Description <string>] [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(DefaultParameterSetName='Identifier', SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    param (
        [Parameter(ParameterSetName='Identifier', Mandatory=$true, Position=0, ValueFromPipelineByPropertyName=$true)]
        [Parameter(ParameterSetName='IdentifierAddScope', Mandatory=$true, Position=0, ValueFromPipelineByPropertyName=$true)]
        [Parameter(ParameterSetName='IdentifierRemoveScope', Mandatory=$true, Position=0, ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${TargetIdentifier},

        [Parameter(ParameterSetName='InputObject', Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [Parameter(ParameterSetName='InputObjectAddScope', Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [Parameter(ParameterSetName='InputObjectRemoveScope', Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [Microsoft.IdentityServer.Management.Resources.OAuthPermission]
        ${InputObject},

        [Parameter(ParameterSetName='RoleIdentifier', Position=0, ValueFromPipelineByPropertyName=$true)]
        [Parameter(ParameterSetName='RoleIdentifierAddScope', Position=0, ValueFromPipelineByPropertyName=$true)]
        [Parameter(ParameterSetName='RoleIdentifierRemoveScope', Position=0, ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${TargetClientRoleIdentifier},

        [Parameter(ParameterSetName='RoleIdentifier', Position=1, ValueFromPipelineByPropertyName=$true)]
        [Parameter(ParameterSetName='RoleIdentifierAddScope', Position=1, ValueFromPipelineByPropertyName=$true)]
        [Parameter(ParameterSetName='RoleIdentifierRemoveScope', Position=1, ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${TargetServerRoleIdentifier},

        [Parameter(ParameterSetName='InputObject', ValueFromPipelineByPropertyName=$true)]
        [Parameter(ParameterSetName='Identifier', ValueFromPipelineByPropertyName=$true)]
        [Parameter(ParameterSetName='RoleIdentifier', ValueFromPipelineByPropertyName=$true)]
        [string[]]
        ${ScopeNames},

        [Parameter(ParameterSetName='InputObjectAddScope', Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [Parameter(ParameterSetName='IdentifierAddScope', Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [Parameter(ParameterSetName='RoleIdentifierAddScope', Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [string[]]
        ${AddScope},

        [Parameter(ParameterSetName='InputObjectRemoveScope', Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [Parameter(ParameterSetName='IdentifierRemoveScope', Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [Parameter(ParameterSetName='RoleIdentifierRemoveScope', Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [string[]]
        ${RemoveScope},

        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [string]
        ${Description}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Set-AdfsAttributeStore {
    <#
    .SYNOPSIS
        Set-AdfsAttributeStore [-TargetName] <string> [-Name <string>] [-Configuration <hashtable>] [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]

Set-AdfsAttributeStore [-TargetAttributeStore] <AttributeStore> [-Name <string>] [-Configuration <hashtable>] [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    param (
        [ValidateNotNull()]
        [string]
        ${Name},

        [ValidateNotNull()]
        [hashtable]
        ${Configuration},

        [Parameter(ParameterSetName='Name', Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${TargetName},

        [Parameter(ParameterSetName='InputObject', Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [Microsoft.IdentityServer.Management.Resources.AttributeStore]
        ${TargetAttributeStore},

        [switch]
        ${PassThru}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Set-AdfsAuthenticationProviderWebContent {
    <#
    .SYNOPSIS
        Set-AdfsAuthenticationProviderWebContent [[-Locale] <cultureinfo>] -Name <string> [-DisplayName <string>] [-Description <string>] [-UserNotProvisionedErrorMessage <string>] [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]

Set-AdfsAuthenticationProviderWebContent [-TargetWebContent] <AdfsAuthProviderWebContent> [-DisplayName <string>] [-Description <string>] [-UserNotProvisionedErrorMessage <string>] [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(DefaultParameterSetName='IdentifierName', SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    param (
        [string]
        ${DisplayName},

        [string]
        ${Description},

        [string]
        ${UserNotProvisionedErrorMessage},

        [switch]
        ${PassThru},

        [Parameter(ParameterSetName='IdentifierName', Position=0)]
        [ValidateNotNull()]
        [cultureinfo]
        ${Locale},

        [Parameter(ParameterSetName='IdentifierName', Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${Name},

        [Parameter(ParameterSetName='IdentifierObject', Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [Microsoft.IdentityServer.Management.Resources.AdfsAuthProviderWebContent]
        ${TargetWebContent}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Set-AdfsAzureMfaTenant {
    <#
    .SYNOPSIS
        Set-AdfsAzureMfaTenant -TenantId <string> -ClientId <string> [-Environment <string>] [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${TenantId},

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${ClientId},

        [ValidateNotNullOrEmpty()]
        [ValidateSet('Public','China','Germany','USGov')]
        [string]
        ${Environment}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Set-AdfsCertificate {
    <#
    .SYNOPSIS
        Set-AdfsCertificate -CertificateType <string> -Thumbprint <string> [-IsPrimary] [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Low')]
    param (
        [Parameter(Mandatory=$true)]
        [ValidateSet('Service-Communications','Token-Decrypting','Token-Signing')]
        [string]
        ${CertificateType},

        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [string]
        ${Thumbprint},

        [switch]
        ${IsPrimary},

        [switch]
        ${PassThru}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Set-AdfsCertificateAuthority {
    <#
    .SYNOPSIS
        Set-AdfsCertificateAuthority -SelfIssued [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]

Set-AdfsCertificateAuthority -RolloverSigningCertificate [-ForcePromotion] [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]

Set-AdfsCertificateAuthority -EnrollmentAgent [-CertificateAuthority <string>] [-LogonCertificateTemplate <string>] [-WindowsHelloCertificateTemplate <string>] [-EnrollmentAgentCertificateTemplate <string>] [-AutoEnrollEnabled <bool>] [-CertificateGenerationThresholdDays <int>] [-WindowsHelloCertificateProxyEnabled <bool>] [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Low')]
    param (
        [Parameter(ParameterSetName='SelfIssued', Mandatory=$true)]
        [switch]
        ${SelfIssued},

        [Parameter(ParameterSetName='RolloverSigningCertificate', Mandatory=$true)]
        [switch]
        ${RolloverSigningCertificate},

        [Parameter(ParameterSetName='RolloverSigningCertificate')]
        [switch]
        ${ForcePromotion},

        [Parameter(ParameterSetName='EnrollmentAgentConfiguration', Mandatory=$true)]
        [switch]
        ${EnrollmentAgent},

        [Parameter(ParameterSetName='EnrollmentAgentConfiguration')]
        [Obsolete('CertificateAuthority is obsolete. Adfs server doesn''t require this attribute anymore. ADFS will target all the CA configured on the server')]
        [string]
        ${CertificateAuthority},

        [Parameter(ParameterSetName='EnrollmentAgentConfiguration')]
        [string]
        ${LogonCertificateTemplate},

        [Parameter(ParameterSetName='EnrollmentAgentConfiguration')]
        [string]
        ${WindowsHelloCertificateTemplate},

        [Parameter(ParameterSetName='EnrollmentAgentConfiguration')]
        [string]
        ${EnrollmentAgentCertificateTemplate},

        [Parameter(ParameterSetName='EnrollmentAgentConfiguration')]
        [System.Nullable[bool]]
        ${AutoEnrollEnabled},

        [Parameter(ParameterSetName='EnrollmentAgentConfiguration')]
        [System.Nullable[int]]
        ${CertificateGenerationThresholdDays},

        [Parameter(ParameterSetName='EnrollmentAgentConfiguration')]
        [System.Nullable[bool]]
        ${WindowsHelloCertificateProxyEnabled},

        [switch]
        ${PassThru}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Set-AdfsCertSharingContainer {
    <#
    .SYNOPSIS
        Set-AdfsCertSharingContainer -ServiceAccount <string> [-Credential <pscredential>] [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    param (
        [Parameter(Mandatory=$true)]
        [string]
        ${ServiceAccount},

        [pscredential]
        ${Credential}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Set-AdfsClaimDescription {
    <#
    .SYNOPSIS
        Set-AdfsClaimDescription [-TargetName] <string> [-IsAccepted <bool>] [-IsOffered <bool>] [-IsRequired <bool>] [-Notes <string>] [-Name <string>] [-ClaimType <string>] [-ShortName <string>] [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]

Set-AdfsClaimDescription [-TargetShortName] <string> [-IsAccepted <bool>] [-IsOffered <bool>] [-IsRequired <bool>] [-Notes <string>] [-Name <string>] [-ClaimType <string>] [-ShortName <string>] [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]

Set-AdfsClaimDescription [-TargetClaimType] <string> [-IsAccepted <bool>] [-IsOffered <bool>] [-IsRequired <bool>] [-Notes <string>] [-Name <string>] [-ClaimType <string>] [-ShortName <string>] [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]

Set-AdfsClaimDescription [-TargetClaimDescription] <ClaimDescription> [-IsAccepted <bool>] [-IsOffered <bool>] [-IsRequired <bool>] [-Notes <string>] [-Name <string>] [-ClaimType <string>] [-ShortName <string>] [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    param (
        [System.Nullable[bool]]
        ${IsAccepted},

        [System.Nullable[bool]]
        ${IsOffered},

        [System.Nullable[bool]]
        ${IsRequired},

        [string]
        ${Notes},

        [string]
        ${Name},

        [string]
        ${ClaimType},

        [string]
        ${ShortName},

        [Parameter(ParameterSetName='Name', Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [string]
        ${TargetName},

        [Parameter(ParameterSetName='ShortName', Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [string]
        ${TargetShortName},

        [Parameter(ParameterSetName='Identifier', Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [string]
        ${TargetClaimType},

        [Parameter(ParameterSetName='InputObject', Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [Microsoft.IdentityServer.Management.Resources.ClaimDescription]
        ${TargetClaimDescription},

        [switch]
        ${PassThru}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Set-AdfsClaimsProviderTrust {
    <#
    .SYNOPSIS
        Set-AdfsClaimsProviderTrust -TargetClaimsProviderTrust <ClaimsProviderTrust> [-Name <string>] [-Identifier <string>] [-SignatureAlgorithm <string>] [-TokenSigningCertificate <X509Certificate2[]>] [-MetadataUrl <uri>] [-AcceptanceTransformRules <string>] [-AcceptanceTransformRulesFile <string>] [-AllowCreate <bool>] [-AutoUpdateEnabled <bool>] [-CustomMFAUri <uri>] [-SupportsMFA <bool>] [-WSFedEndpoint <uri>] [-EncryptionCertificate <X509Certificate2>] [-EncryptionCertificateRevocationCheck <string>] [-MonitoringEnabled <bool>] [-Notes <string>] [-OrganizationalAccountSuffix <string[]>] [-LookupForests <string[]>] [-AlternateLoginID <string>] [-Force] [-ClaimOffered <ClaimDescription[]>] [-SamlEndpoint <SamlEndpoint[]>] [-ProtocolProfile <string>] [-RequiredNameIdFormat <uri>] [-EncryptedNameIdRequired <bool>] [-SignedSamlRequestsRequired <bool>] [-SamlAuthenticationRequestIndex <uint16>] [-SamlAuthenticationRequestParameters <string>] [-SamlAuthenticationRequestProtocolBinding <string>] [-SigningCertificateRevocationCheck <string>] [-PromptLoginFederation <PromptLoginFederation>] [-PromptLoginFallbackAuthenticationType <string>] [-AnchorClaimType <string>] [-DomainCredential <pscredential>] [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]

Set-AdfsClaimsProviderTrust -TargetCertificate <X509Certificate2> [-Name <string>] [-Identifier <string>] [-SignatureAlgorithm <string>] [-TokenSigningCertificate <X509Certificate2[]>] [-MetadataUrl <uri>] [-AcceptanceTransformRules <string>] [-AcceptanceTransformRulesFile <string>] [-AllowCreate <bool>] [-AutoUpdateEnabled <bool>] [-CustomMFAUri <uri>] [-SupportsMFA <bool>] [-WSFedEndpoint <uri>] [-EncryptionCertificate <X509Certificate2>] [-EncryptionCertificateRevocationCheck <string>] [-MonitoringEnabled <bool>] [-Notes <string>] [-OrganizationalAccountSuffix <string[]>] [-LookupForests <string[]>] [-AlternateLoginID <string>] [-Force] [-ClaimOffered <ClaimDescription[]>] [-SamlEndpoint <SamlEndpoint[]>] [-ProtocolProfile <string>] [-RequiredNameIdFormat <uri>] [-EncryptedNameIdRequired <bool>] [-SignedSamlRequestsRequired <bool>] [-SamlAuthenticationRequestIndex <uint16>] [-SamlAuthenticationRequestParameters <string>] [-SamlAuthenticationRequestProtocolBinding <string>] [-SigningCertificateRevocationCheck <string>] [-PromptLoginFederation <PromptLoginFederation>] [-PromptLoginFallbackAuthenticationType <string>] [-AnchorClaimType <string>] [-DomainCredential <pscredential>] [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]

Set-AdfsClaimsProviderTrust -TargetIdentifier <string> [-Name <string>] [-Identifier <string>] [-SignatureAlgorithm <string>] [-TokenSigningCertificate <X509Certificate2[]>] [-MetadataUrl <uri>] [-AcceptanceTransformRules <string>] [-AcceptanceTransformRulesFile <string>] [-AllowCreate <bool>] [-AutoUpdateEnabled <bool>] [-CustomMFAUri <uri>] [-SupportsMFA <bool>] [-WSFedEndpoint <uri>] [-EncryptionCertificate <X509Certificate2>] [-EncryptionCertificateRevocationCheck <string>] [-MonitoringEnabled <bool>] [-Notes <string>] [-OrganizationalAccountSuffix <string[]>] [-LookupForests <string[]>] [-AlternateLoginID <string>] [-Force] [-ClaimOffered <ClaimDescription[]>] [-SamlEndpoint <SamlEndpoint[]>] [-ProtocolProfile <string>] [-RequiredNameIdFormat <uri>] [-EncryptedNameIdRequired <bool>] [-SignedSamlRequestsRequired <bool>] [-SamlAuthenticationRequestIndex <uint16>] [-SamlAuthenticationRequestParameters <string>] [-SamlAuthenticationRequestProtocolBinding <string>] [-SigningCertificateRevocationCheck <string>] [-PromptLoginFederation <PromptLoginFederation>] [-PromptLoginFallbackAuthenticationType <string>] [-AnchorClaimType <string>] [-DomainCredential <pscredential>] [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]

Set-AdfsClaimsProviderTrust -TargetName <string> [-Name <string>] [-Identifier <string>] [-SignatureAlgorithm <string>] [-TokenSigningCertificate <X509Certificate2[]>] [-MetadataUrl <uri>] [-AcceptanceTransformRules <string>] [-AcceptanceTransformRulesFile <string>] [-AllowCreate <bool>] [-AutoUpdateEnabled <bool>] [-CustomMFAUri <uri>] [-SupportsMFA <bool>] [-WSFedEndpoint <uri>] [-EncryptionCertificate <X509Certificate2>] [-EncryptionCertificateRevocationCheck <string>] [-MonitoringEnabled <bool>] [-Notes <string>] [-OrganizationalAccountSuffix <string[]>] [-LookupForests <string[]>] [-AlternateLoginID <string>] [-Force] [-ClaimOffered <ClaimDescription[]>] [-SamlEndpoint <SamlEndpoint[]>] [-ProtocolProfile <string>] [-RequiredNameIdFormat <uri>] [-EncryptedNameIdRequired <bool>] [-SignedSamlRequestsRequired <bool>] [-SamlAuthenticationRequestIndex <uint16>] [-SamlAuthenticationRequestParameters <string>] [-SamlAuthenticationRequestProtocolBinding <string>] [-SigningCertificateRevocationCheck <string>] [-PromptLoginFederation <PromptLoginFederation>] [-PromptLoginFallbackAuthenticationType <string>] [-AnchorClaimType <string>] [-DomainCredential <pscredential>] [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    param (
        [ValidateNotNullOrEmpty()]
        [string]
        ${Name},

        [ValidateNotNull()]
        [string]
        ${Identifier},

        [ValidateSet('http://www.w3.org/2000/09/xmldsig#rsa-sha1','http://www.w3.org/2001/04/xmldsig-more#rsa-sha256')]
        [string]
        ${SignatureAlgorithm},

        [ValidateNotNull()]
        [System.Security.Cryptography.X509Certificates.X509Certificate2[]]
        ${TokenSigningCertificate},

        [uri]
        ${MetadataUrl},

        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [string]
        ${AcceptanceTransformRules},

        [ValidateNotNullOrEmpty()]
        [string]
        ${AcceptanceTransformRulesFile},

        [System.Nullable[bool]]
        ${AllowCreate},

        [System.Nullable[bool]]
        ${AutoUpdateEnabled},

        [uri]
        ${CustomMFAUri},

        [bool]
        ${SupportsMFA},

        [uri]
        ${WSFedEndpoint},

        [System.Security.Cryptography.X509Certificates.X509Certificate2]
        ${EncryptionCertificate},

        [ValidateSet('CheckChain','CheckChainCacheOnly','CheckChainExcludeRoot','CheckChainExcludeRootCacheOnly','CheckEndCert','CheckEndCertCacheOnly','None')]
        [string]
        ${EncryptionCertificateRevocationCheck},

        [System.Nullable[bool]]
        ${MonitoringEnabled},

        [ValidateNotNullOrEmpty()]
        [string]
        ${Notes},

        [string[]]
        ${OrganizationalAccountSuffix},

        [string[]]
        ${LookupForests},

        [string]
        ${AlternateLoginID},

        [ValidateNotNullOrEmpty()]
        [switch]
        ${Force},

        [Parameter(ValueFromPipeline=$true)]
        [Microsoft.IdentityServer.Management.Resources.ClaimDescription[]]
        ${ClaimOffered},

        [Parameter(ValueFromPipeline=$true)]
        [Microsoft.IdentityServer.Management.Resources.SamlEndpoint[]]
        ${SamlEndpoint},

        [ValidateSet('WsFed-SAML','WSFederation','SAML')]
        [string]
        ${ProtocolProfile},

        [uri]
        ${RequiredNameIdFormat},

        [ValidateNotNull()]
        [System.Nullable[bool]]
        ${EncryptedNameIdRequired},

        [ValidateNotNull()]
        [System.Nullable[bool]]
        ${SignedSamlRequestsRequired},

        [System.Nullable[uint16]]
        ${SamlAuthenticationRequestIndex},

        [ValidateSet('Index','None','','ProtocolBinding','Url','UrlWithProtocolBinding')]
        [string]
        ${SamlAuthenticationRequestParameters},

        [ValidateSet('Artifact','','POST','Redirect')]
        [string]
        ${SamlAuthenticationRequestProtocolBinding},

        [ValidateSet('CheckChain','CheckChainCacheOnly','CheckChainExcludeRoot','CheckChainExcludeRootCacheOnly','CheckEndCert','CheckEndCertCacheOnly','None')]
        [string]
        ${SigningCertificateRevocationCheck},

        [Microsoft.IdentityServer.PolicyModel.Configuration.PromptLoginFederation]
        ${PromptLoginFederation},

        [string]
        ${PromptLoginFallbackAuthenticationType},

        [string]
        ${AnchorClaimType},

        [pscredential]
        ${DomainCredential},

        [Parameter(ParameterSetName='IdentifierObject', Mandatory=$true, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [Microsoft.IdentityServer.Management.Resources.ClaimsProviderTrust]
        ${TargetClaimsProviderTrust},

        [Parameter(ParameterSetName='TokenSigningCertificates', Mandatory=$true, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]
        ${TargetCertificate},

        [Parameter(ParameterSetName='Identifier', Mandatory=$true, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [string]
        ${TargetIdentifier},

        [Parameter(ParameterSetName='IdentifierName', Mandatory=$true, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [string]
        ${TargetName},

        [switch]
        ${PassThru}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Set-AdfsClient {
    <#
    .SYNOPSIS
        Set-AdfsClient [-TargetName] <string> [-Force] [-ClientId <string>] [-Name <string>] [-RedirectUri <string[]>] [-Description <string>] [-ADUserPrincipalName <string>] [-JWTSigningCertificate <X509Certificate2[]>] [-JWTSigningCertificateRevocationCheck <RevocationSetting>] [-ChangeClientSecret] [-ResetClientSecret] [-JWKSUri <uri>] [-ReloadJWTSigningKeys] [-JWKSFile <string>] [-LogoutUri <string>] [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]

Set-AdfsClient [-TargetClientId] <string> [-Force] [-ClientId <string>] [-Name <string>] [-RedirectUri <string[]>] [-Description <string>] [-ADUserPrincipalName <string>] [-JWTSigningCertificate <X509Certificate2[]>] [-JWTSigningCertificateRevocationCheck <RevocationSetting>] [-ChangeClientSecret] [-ResetClientSecret] [-JWKSUri <uri>] [-ReloadJWTSigningKeys] [-JWKSFile <string>] [-LogoutUri <string>] [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]

Set-AdfsClient [-TargetClient] <AdfsClient> [-Force] [-ClientId <string>] [-Name <string>] [-RedirectUri <string[]>] [-Description <string>] [-ADUserPrincipalName <string>] [-JWTSigningCertificate <X509Certificate2[]>] [-JWTSigningCertificateRevocationCheck <RevocationSetting>] [-ChangeClientSecret] [-ResetClientSecret] [-JWKSUri <uri>] [-ReloadJWTSigningKeys] [-JWKSFile <string>] [-LogoutUri <string>] [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(DefaultParameterSetName='Name', SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    param (
        [ValidateNotNullOrEmpty()]
        [switch]
        ${Force},

        [Parameter(ParameterSetName='ClientId', Mandatory=$true, Position=0, ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${TargetClientId},

        [Parameter(ParameterSetName='Name', Mandatory=$true, Position=0, ValueFromPipelineByPropertyName=$true)]
        [string]
        ${TargetName},

        [Parameter(ParameterSetName='InputObject', Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [Microsoft.IdentityServer.Management.Resources.AdfsClient]
        ${TargetClient},

        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${ClientId},

        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${Name},

        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [string[]]
        ${RedirectUri},

        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [string]
        ${Description},

        [string]
        ${ADUserPrincipalName},

        [System.Security.Cryptography.X509Certificates.X509Certificate2[]]
        ${JWTSigningCertificate},

        [Microsoft.IdentityServer.PolicyModel.Configuration.RevocationSetting]
        ${JWTSigningCertificateRevocationCheck},

        [switch]
        ${ChangeClientSecret},

        [switch]
        ${ResetClientSecret},

        [uri]
        ${JWKSUri},

        [switch]
        ${ReloadJWTSigningKeys},

        [string]
        ${JWKSFile},

        [ValidateNotNull()]
        [string]
        ${LogoutUri},

        [switch]
        ${PassThru}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Set-AdfsDebugLogConsumersConfiguration {
    <#
    .SYNOPSIS
        Set-AdfsDebugLogConsumersConfiguration -Consumer <DebugLogConsumer> [-WhatIf] [-Confirm] [-Share <string>] [-Enable <bool>] [-EnabledLogLevels <string[]>] [<CommonParameters>]
    #>

    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        [Microsoft.IdentityServer.Management.Commands.DebugLogConsumer]
        ${Consumer}
    )

    dynamicparam {
        $parameters = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary

        # Share
        $attributes = New-Object System.Collections.Generic.List[Attribute]

        $attribute = New-Object System.Management.Automation.ParameterAttribute
        $attributes.Add($attribute)

        $attribute = New-Object System.Management.Automation.ValidateNotNullOrEmptyAttribute
        $attributes.Add($attribute)

        $parameter = New-Object System.Management.Automation.RuntimeDefinedParameter("Share", [System.String], $attributes)
        $parameters.Add("Share", $parameter)

        # Enable
        $attributes = New-Object System.Collections.Generic.List[Attribute]

        $attribute = New-Object System.Management.Automation.ParameterAttribute
        $attributes.Add($attribute)

        $attribute = New-Object System.Management.Automation.ValidateNotNullAttribute
        $attributes.Add($attribute)

        $parameter = New-Object System.Management.Automation.RuntimeDefinedParameter("Enable", [System.Nullable`1[System.Boolean]], $attributes)
        $parameters.Add("Enable", $parameter)

        # EnabledLogLevels
        $attributes = New-Object System.Collections.Generic.List[Attribute]

        $attribute = New-Object System.Management.Automation.ParameterAttribute
        $attributes.Add($attribute)

        $attribute = New-Object System.Management.Automation.ValidateSetAttribute('None', 'Verbose', 'Info', 'Warning', 'Error', 'Critical')
        $attributes.Add($attribute)

        $parameter = New-Object System.Management.Automation.RuntimeDefinedParameter("EnabledLogLevels", [System.String[]], $attributes)
        $parameters.Add("EnabledLogLevels", $parameter)

        return $parameters
    }

    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Set-AdfsDeviceRegistration {
    <#
    .SYNOPSIS
        Set-AdfsDeviceRegistration -MaximumInactiveDays <uint32> [-AccessControlPolicyName <string>] [-AccessControlPolicyParameters <Object>] [-WhatIf] [-Confirm] [<CommonParameters>]

Set-AdfsDeviceRegistration -DevicesPerUser <uint32> [-AccessControlPolicyName <string>] [-AccessControlPolicyParameters <Object>] [-WhatIf] [-Confirm] [<CommonParameters>]

Set-AdfsDeviceRegistration -ServiceAccountIdentifier <string> -Credential <pscredential> [-AccessControlPolicyName <string>] [-AccessControlPolicyParameters <Object>] [-WhatIf] [-Confirm] [<CommonParameters>]

Set-AdfsDeviceRegistration -IssuanceCertificate [-AccessControlPolicyName <string>] [-AccessControlPolicyParameters <Object>] [-WhatIf] [-Confirm] [<CommonParameters>]

Set-AdfsDeviceRegistration [-AccessControlPolicyName <string>] [-AccessControlPolicyParameters <Object>] [-AllowedAuthenticationClassReferences <string[]>] [-IssuanceAuthorizationRules <string>] [-IssuanceAuthorizationRulesFile <string>] [-IssuanceTransformRules <string>] [-IssuanceTransformRulesFile <string>] [-AdditionalAuthenticationRules <string>] [-AdditionalAuthenticationRulesFile <string>] [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Low')]
    param (
        [Parameter(ParameterSetName='NumberOfInactiveDays', Mandatory=$true, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [uint32]
        ${MaximumInactiveDays},

        [Parameter(ParameterSetName='NumberOfDevicesPerUser', Mandatory=$true, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [uint32]
        ${DevicesPerUser},

        [Parameter(ParameterSetName='ServiceAccountIdentifier', Mandatory=$true, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [string]
        ${ServiceAccountIdentifier},

        [Parameter(ParameterSetName='ServiceAccountIdentifier', Mandatory=$true)]
        [ValidateNotNull()]
        [pscredential]
        ${Credential},

        [Parameter(ParameterSetName='IssuanceCertificate', Mandatory=$true, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [switch]
        ${IssuanceCertificate},

        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [string]
        ${AccessControlPolicyName},

        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [System.Object]
        ${AccessControlPolicyParameters},

        [Parameter(ParameterSetName='RelyingParty')]
        [ValidateNotNull()]
        [string[]]
        ${AllowedAuthenticationClassReferences},

        [Parameter(ParameterSetName='RelyingParty', ValueFromPipeline=$true)]
        [string]
        ${IssuanceAuthorizationRules},

        [Parameter(ParameterSetName='RelyingParty')]
        [ValidateNotNullOrEmpty()]
        [string]
        ${IssuanceAuthorizationRulesFile},

        [Parameter(ParameterSetName='RelyingParty', ValueFromPipeline=$true)]
        [string]
        ${IssuanceTransformRules},

        [Parameter(ParameterSetName='RelyingParty')]
        [ValidateNotNullOrEmpty()]
        [string]
        ${IssuanceTransformRulesFile},

        [Parameter(ParameterSetName='RelyingParty', ValueFromPipeline=$true)]
        [string]
        ${AdditionalAuthenticationRules},

        [Parameter(ParameterSetName='RelyingParty')]
        [ValidateNotNullOrEmpty()]
        [string]
        ${AdditionalAuthenticationRulesFile}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Set-AdfsDeviceRegistrationUpnSuffix {
    <#
    .SYNOPSIS
        Set-AdfsDeviceRegistrationUpnSuffix [-Force] [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    param (
        [Parameter(ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [switch]
        ${Force}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Set-AdfsDirectoryProperties {
    <#
    .SYNOPSIS
        Set-AdfsDirectoryProperties [-AddUpnSuffix <string[]>] [-RemoveUpnSuffix <string[]>] [-AddNetbiosName <string[]>] [-RemoveNetbiosName <string[]>] [<CommonParameters>]
    #>

    [CmdletBinding()]
    param (
        [string[]]
        ${AddUpnSuffix},

        [string[]]
        ${RemoveUpnSuffix},

        [string[]]
        ${AddNetbiosName},

        [string[]]
        ${RemoveNetbiosName}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Set-AdfsEndpoint {
    <#
    .SYNOPSIS
        Set-AdfsEndpoint [[-TargetAddressPath] <string>] -Proxy <bool> [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]

Set-AdfsEndpoint -TargetEndpoint <Endpoint> -Proxy <bool> [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]

Set-AdfsEndpoint [-TargetFullUrl] <uri> -Proxy <bool> [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    param (
        [Parameter(ParameterSetName='Address', Position=0, ValueFromPipeline=$true)]
        [AllowNull()]
        [string]
        ${TargetAddressPath},

        [Parameter(ParameterSetName='TargetObject', Mandatory=$true, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [Microsoft.IdentityServer.Management.Resources.Endpoint]
        ${TargetEndpoint},

        [Parameter(ParameterSetName='FullUrl', Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [uri]
        ${TargetFullUrl},

        [Parameter(Mandatory=$true)]
        [bool]
        ${Proxy},

        [switch]
        ${PassThru}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Set-AdfsFarmInformation {
    <#
    .SYNOPSIS
        Set-AdfsFarmInformation [-RemoveNode <string[]>] [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Low')]
    param (
        [string[]]
        ${RemoveNode}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Set-AdfsGlobalAuthenticationPolicy {
    <#
    .SYNOPSIS
        Set-AdfsGlobalAuthenticationPolicy [-Force] [-AdditionalAuthenticationProvider <string[]>] [-DeviceAuthenticationEnabled <bool>] [-AllowAdditionalAuthenticationAsPrimary <bool>] [-EnablePaginatedAuthenticationPages <bool>] [-DeviceAuthenticationMethod <DeviceAuthenticationMethod>] [-AllowDeviceAuthAsPrimaryForDomainJoinedDevices <bool>] [-PrimaryExtranetAuthenticationProvider <string[]>] [-PrimaryIntranetAuthenticationProvider <string[]>] [-WindowsIntegratedFallbackEnabled <bool>] [-ClientAuthenticationMethods <ClientAuthenticationMethod>] [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(DefaultParameterSetName='IdentifierName', SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    param (
        [ValidateNotNullOrEmpty()]
        [switch]
        ${Force},

        [string[]]
        ${AdditionalAuthenticationProvider},

        [bool]
        ${DeviceAuthenticationEnabled},

        [bool]
        ${AllowAdditionalAuthenticationAsPrimary},

        [bool]
        ${EnablePaginatedAuthenticationPages},

        [Microsoft.IdentityServer.PolicyModel.Configuration.DeviceAuthenticationMethod]
        ${DeviceAuthenticationMethod},

        [bool]
        ${AllowDeviceAuthAsPrimaryForDomainJoinedDevices},

        [string[]]
        ${PrimaryExtranetAuthenticationProvider},

        [string[]]
        ${PrimaryIntranetAuthenticationProvider},

        [bool]
        ${WindowsIntegratedFallbackEnabled},

        [Microsoft.IdentityServer.PolicyModel.Configuration.ClientAuthenticationMethod]
        ${ClientAuthenticationMethods},

        [switch]
        ${PassThru}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Set-AdfsGlobalWebContent {
    <#
    .SYNOPSIS
        Set-AdfsGlobalWebContent [[-Locale] <cultureinfo>] [-CompanyName <string>] [-HelpDeskLink <uri>] [-HelpDeskLinkText <string>] [-HomeLink <uri>] [-HomeLinkText <string>] [-HomeRealmDiscoveryOtherOrganizationDescriptionText <string>] [-HomeRealmDiscoveryPageDescriptionText <string>] [-OrganizationalNameDescriptionText <string>] [-PrivacyLink <uri>] [-PrivacyLinkText <string>] [-CertificatePageDescriptionText <string>] [-SignInPageDescriptionText <string>] [-SignOutPageDescriptionText <string>] [-ErrorPageDescriptionText <string>] [-ErrorPageGenericErrorMessage <string>] [-ErrorPageAuthorizationErrorMessage <string>] [-ErrorPageDeviceAuthenticationErrorMessage <string>] [-ErrorPageSupportEmail <string>] [-UpdatePasswordPageDescriptionText <string>] [-SignInPageAdditionalAuthenticationDescriptionText <string>] [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]

Set-AdfsGlobalWebContent [-TargetWebContent] <AdfsGlobalWebContent> [-CompanyName <string>] [-HelpDeskLink <uri>] [-HelpDeskLinkText <string>] [-HomeLink <uri>] [-HomeLinkText <string>] [-HomeRealmDiscoveryOtherOrganizationDescriptionText <string>] [-HomeRealmDiscoveryPageDescriptionText <string>] [-OrganizationalNameDescriptionText <string>] [-PrivacyLink <uri>] [-PrivacyLinkText <string>] [-CertificatePageDescriptionText <string>] [-SignInPageDescriptionText <string>] [-SignOutPageDescriptionText <string>] [-ErrorPageDescriptionText <string>] [-ErrorPageGenericErrorMessage <string>] [-ErrorPageAuthorizationErrorMessage <string>] [-ErrorPageDeviceAuthenticationErrorMessage <string>] [-ErrorPageSupportEmail <string>] [-UpdatePasswordPageDescriptionText <string>] [-SignInPageAdditionalAuthenticationDescriptionText <string>] [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(DefaultParameterSetName='IdentifierName', SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    param (
        [Parameter(ParameterSetName='IdentifierName', Position=0, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [cultureinfo]
        ${Locale},

        [string]
        ${CompanyName},

        [uri]
        ${HelpDeskLink},

        [string]
        ${HelpDeskLinkText},

        [uri]
        ${HomeLink},

        [string]
        ${HomeLinkText},

        [string]
        ${HomeRealmDiscoveryOtherOrganizationDescriptionText},

        [string]
        ${HomeRealmDiscoveryPageDescriptionText},

        [string]
        ${OrganizationalNameDescriptionText},

        [uri]
        ${PrivacyLink},

        [string]
        ${PrivacyLinkText},

        [string]
        ${CertificatePageDescriptionText},

        [string]
        ${SignInPageDescriptionText},

        [string]
        ${SignOutPageDescriptionText},

        [string]
        ${ErrorPageDescriptionText},

        [string]
        ${ErrorPageGenericErrorMessage},

        [string]
        ${ErrorPageAuthorizationErrorMessage},

        [string]
        ${ErrorPageDeviceAuthenticationErrorMessage},

        [string]
        ${ErrorPageSupportEmail},

        [string]
        ${UpdatePasswordPageDescriptionText},

        [string]
        ${SignInPageAdditionalAuthenticationDescriptionText},

        [switch]
        ${PassThru},

        [Parameter(ParameterSetName='IdentifierObject', Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [Microsoft.IdentityServer.Management.Resources.AdfsGlobalWebContent]
        ${TargetWebContent}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Set-AdfsLocalClaimsProviderTrust {
    <#
    .SYNOPSIS
        Set-AdfsLocalClaimsProviderTrust -TargetClaimsProviderTrust <LocalClaimsProviderTrust> [-AcceptanceTransformRules <string>] [-AcceptanceTransformRulesFile <string>] [-Name <string>] [-Notes <string>] [-OrganizationalAccountSuffix <string[]>] [-Force] [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]

Set-AdfsLocalClaimsProviderTrust -TargetIdentifier <string> [-AcceptanceTransformRules <string>] [-AcceptanceTransformRulesFile <string>] [-Name <string>] [-Notes <string>] [-OrganizationalAccountSuffix <string[]>] [-Force] [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]

Set-AdfsLocalClaimsProviderTrust -TargetName <string> [-AcceptanceTransformRules <string>] [-AcceptanceTransformRulesFile <string>] [-Name <string>] [-Notes <string>] [-OrganizationalAccountSuffix <string[]>] [-Force] [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    param (
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [string]
        ${AcceptanceTransformRules},

        [ValidateNotNullOrEmpty()]
        [string]
        ${AcceptanceTransformRulesFile},

        [ValidateNotNullOrEmpty()]
        [string]
        ${Name},

        [ValidateNotNullOrEmpty()]
        [string]
        ${Notes},

        [string[]]
        ${OrganizationalAccountSuffix},

        [ValidateNotNullOrEmpty()]
        [switch]
        ${Force},

        [Parameter(ParameterSetName='IdentifierObject', Mandatory=$true, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [Microsoft.IdentityServer.Management.Resources.LocalClaimsProviderTrust]
        ${TargetClaimsProviderTrust},

        [Parameter(ParameterSetName='Identifier', Mandatory=$true, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [string]
        ${TargetIdentifier},

        [Parameter(ParameterSetName='IdentifierName', Mandatory=$true, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [string]
        ${TargetName},

        [switch]
        ${PassThru}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Set-AdfsNativeClientApplication {
    <#
    .SYNOPSIS
        Set-AdfsNativeClientApplication [-TargetIdentifier] <string> [-Identifier <string>] [-Name <string>] [-RedirectUri <string[]>] [-Description <string>] [-LogoutUri <string>] [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]

Set-AdfsNativeClientApplication [-TargetName] <string> [-Identifier <string>] [-Name <string>] [-RedirectUri <string[]>] [-Description <string>] [-LogoutUri <string>] [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]

Set-AdfsNativeClientApplication [-TargetApplication] <NativeClientApplication> [-Identifier <string>] [-Name <string>] [-RedirectUri <string[]>] [-Description <string>] [-LogoutUri <string>] [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(DefaultParameterSetName='Identifier', SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    param (
        [Parameter(ParameterSetName='Identifier', Mandatory=$true, Position=0, ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${TargetIdentifier},

        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [string[]]
        ${RedirectUri},

        [Parameter(ParameterSetName='Name', Mandatory=$true, Position=0, ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${TargetName},

        [Parameter(ParameterSetName='ApplicationObject', Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [Microsoft.IdentityServer.Management.Resources.NativeClientApplication]
        ${TargetApplication},

        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${Identifier},

        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${Name},

        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [string]
        ${Description},

        [ValidateNotNull()]
        [string]
        ${LogoutUri},

        [switch]
        ${PassThru}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Set-AdfsNonClaimsAwareRelyingPartyTrust {
    <#
    .SYNOPSIS
        Set-AdfsNonClaimsAwareRelyingPartyTrust [-TargetName] <string> [-AlwaysRequireAuthentication] [-Identifier <string[]>] [-IssuanceAuthorizationRules <string>] [-IssuanceAuthorizationRulesFile <string>] [-Name <string>] [-Notes <string>] [-PassThru] [-AdditionalAuthenticationRules <string>] [-AdditionalAuthenticationRulesFile <string>] [-AccessControlPolicyName <string>] [-AccessControlPolicyParameters <Object>] [-ClaimsProviderName <string[]>] [-DeviceAuthenticationMethod <DeviceAuthenticationMethod>] [-WhatIf] [-Confirm] [<CommonParameters>]

Set-AdfsNonClaimsAwareRelyingPartyTrust -TargetIdentifier <string> [-AlwaysRequireAuthentication] [-Identifier <string[]>] [-IssuanceAuthorizationRules <string>] [-IssuanceAuthorizationRulesFile <string>] [-Name <string>] [-Notes <string>] [-PassThru] [-AdditionalAuthenticationRules <string>] [-AdditionalAuthenticationRulesFile <string>] [-AccessControlPolicyName <string>] [-AccessControlPolicyParameters <Object>] [-ClaimsProviderName <string[]>] [-DeviceAuthenticationMethod <DeviceAuthenticationMethod>] [-WhatIf] [-Confirm] [<CommonParameters>]

Set-AdfsNonClaimsAwareRelyingPartyTrust -TargetNonClaimsAwareRelyingPartyTrust <NonClaimsAwareRelyingPartyTrust> [-AlwaysRequireAuthentication] [-Identifier <string[]>] [-IssuanceAuthorizationRules <string>] [-IssuanceAuthorizationRulesFile <string>] [-Name <string>] [-Notes <string>] [-PassThru] [-AdditionalAuthenticationRules <string>] [-AdditionalAuthenticationRulesFile <string>] [-AccessControlPolicyName <string>] [-AccessControlPolicyParameters <Object>] [-ClaimsProviderName <string[]>] [-DeviceAuthenticationMethod <DeviceAuthenticationMethod>] [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(DefaultParameterSetName='IdentifierName', SupportsShouldProcess=$true, ConfirmImpact='Low')]
    param (
        [switch]
        ${AlwaysRequireAuthentication},

        [ValidateNotNull()]
        [string[]]
        ${Identifier},

        [string]
        ${IssuanceAuthorizationRules},

        [ValidateNotNullOrEmpty()]
        [string]
        ${IssuanceAuthorizationRulesFile},

        [ValidateNotNullOrEmpty()]
        [string]
        ${Name},

        [ValidateNotNullOrEmpty()]
        [string]
        ${Notes},

        [switch]
        ${PassThru},

        [string]
        ${AdditionalAuthenticationRules},

        [ValidateNotNullOrEmpty()]
        [string]
        ${AdditionalAuthenticationRulesFile},

        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [string]
        ${AccessControlPolicyName},

        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [System.Object]
        ${AccessControlPolicyParameters},

        [string[]]
        ${ClaimsProviderName},

        [System.Nullable[Microsoft.IdentityServer.PolicyModel.Configuration.DeviceAuthenticationMethod]]
        ${DeviceAuthenticationMethod},

        [Parameter(ParameterSetName='Identifier', Mandatory=$true)]
        [ValidateNotNull()]
        [string]
        ${TargetIdentifier},

        [Parameter(ParameterSetName='IdentifierName', Mandatory=$true, Position=0)]
        [ValidateNotNull()]
        [string]
        ${TargetName},

        [Parameter(ParameterSetName='IdentifierObject', Mandatory=$true, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [Microsoft.IdentityServer.Management.Resources.NonClaimsAwareRelyingPartyTrust]
        ${TargetNonClaimsAwareRelyingPartyTrust}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Set-AdfsProperties {
    <#
    .SYNOPSIS
        Set-AdfsProperties [-AuthenticationContextOrder <uri[]>] [-AcceptableIdentifiers <uri[]>] [-AddProxyAuthorizationRules <string>] [-ArtifactDbConnection <string>] [-AuditLevel <string[]>] [-AutoCertificateRollover <bool>] [-CertificateCriticalThreshold <int>] [-CertificateDuration <int>] [-CertificateGenerationThreshold <int>] [-CertificatePromotionThreshold <int>] [-CertificateRolloverInterval <int>] [-CertificateThresholdMultiplier <int>] [-ClientCertRevocationCheck <string>] [-ContactPerson <ContactPerson>] [-DisplayName <string>] [-EnableOAuthLogout <bool>] [-EnableOAuthDeviceFlow <bool>] [-AdditionalErrorPageInfo <ErrorShowLevel>] [-SendLogsCacheSizeInMb <long>] [-SendLogsEnabled <bool>] [-FederationPassiveAddress <string>] [-HostName <string>] [-HttpPort <int>] [-HttpsPort <int>] [-IntranetUseLocalClaimsProvider <bool>] [-TlsClientPort <int>] [-Identifier <uri>] [-LogLevel <string[]>] [-MonitoringInterval <int>] [-NetTcpPort <int>] [-NtlmOnlySupportedClientAtProxy <bool>] [-OrganizationInfo <Organization>] [-PreventTokenReplays <bool>] [-ExtendedProtectionTokenCheck <string>] [-ProxyTrustTokenLifetime <int>] [-ReplayCacheExpirationInterval <int>] [-SignedSamlRequestsRequired <bool>] [-SamlMessageDeliveryWindow <int>] [-SignSamlAuthnRequests <bool>] [-SsoLifetime <int>] [-SsoEnabled <bool>] [-PersistentSsoLifetimeMins <int>] [-KmsiLifetimeMins <int>] [-EnablePersistentSso <bool>] [-PersistentSsoCutoffTime <datetime>] [-EnableKmsi <bool>] [-WIASupportedUserAgents <string[]>] [-BrowserSsoSupportedUserAgents <string[]>] [-BrowserSsoEnabled <bool>] [-LoopDetectionTimeIntervalInSeconds <int>] [-LoopDetectionMaximumTokensIssuedInInterval <int>] [-EnableLoopDetection <bool>] [-ExtranetLockoutThreshold <int>] [-ExtranetLockoutThresholdFamiliarLocation <int>] [-ExtranetLockoutMode <ExtranetLockoutModes>] [-EnableExtranetLockout <bool>] [-ExtranetObservationWindow <timespan>] [-ExtranetLockoutRequirePDC <bool>] [-SendClientRequestIdAsQueryStringParameter <bool>] [-GlobalRelyingPartyClaimsIssuancePolicy <string>] [-EnableLocalAuthenticationTypes <bool>] [-AllowedActiveDirectoryUserPrincipalNames <string[]>] [-AllowedActiveDirectoryNetbiosNames <string[]>] [-EnableRelayStateForIdpInitiatedSignOn <bool>] [-DelegateServiceAdministration <string>] [-AllowSystemServiceAdministration <bool>] [-AllowLocalAdminsServiceAdministration <bool>] [-DeviceUsageWindowInDays <int>] [-EnableIdPInitiatedSignonPage <bool>] [-IgnoreTokenBinding <bool>] [-IdTokenIssuer <uri>] [-PromptLoginFederation <PromptLoginFederation>] [-PromptLoginFallbackAuthenticationType <string>] [-AddBannedIps <string[]>] [-RemoveBannedIps <string[]>] [-WindowsHelloKeyVerification <WindowsHelloKeyVerificationOptions>] [-Force] [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    param (
        [uri[]]
        ${AuthenticationContextOrder},

        [uri[]]
        ${AcceptableIdentifiers},

        [string]
        ${AddProxyAuthorizationRules},

        [string]
        ${ArtifactDbConnection},

        [ValidateSet('None','Basic','Verbose')]
        [string[]]
        ${AuditLevel},

        [System.Nullable[bool]]
        ${AutoCertificateRollover},

        [System.Nullable[int]]
        ${CertificateCriticalThreshold},

        [System.Nullable[int]]
        ${CertificateDuration},

        [System.Nullable[int]]
        ${CertificateGenerationThreshold},

        [System.Nullable[int]]
        ${CertificatePromotionThreshold},

        [System.Nullable[int]]
        ${CertificateRolloverInterval},

        [System.Nullable[int]]
        ${CertificateThresholdMultiplier},

        [ValidateSet('CheckChain','CheckChainCacheOnly','CheckChainExcludeRoot','CheckChainExcludeRootCacheOnly','CheckEndCert','CheckEndCertCacheOnly','None')]
        [string]
        ${ClientCertRevocationCheck},

        [Microsoft.IdentityServer.Management.Resources.ContactPerson]
        ${ContactPerson},

        [ValidateNotNull()]
        [string]
        ${DisplayName},

        [Obsolete()]
        [System.Nullable[bool]]
        ${EnableOAuthLogout},

        [System.Nullable[bool]]
        ${EnableOAuthDeviceFlow},

        [ValidateNotNull()]
        [System.Nullable[Microsoft.IdentityServer.PolicyModel.Configuration.ErrorShowLevel]]
        ${AdditionalErrorPageInfo},

        [ValidateRange(0, 9223372036854775807)]
        [System.Nullable[long]]
        ${SendLogsCacheSizeInMb},

        [ValidateNotNull()]
        [System.Nullable[bool]]
        ${SendLogsEnabled},

        [string]
        ${FederationPassiveAddress},

        [ValidateNotNull()]
        [string]
        ${HostName},

        [System.Nullable[int]]
        ${HttpPort},

        [System.Nullable[int]]
        ${HttpsPort},

        [bool]
        ${IntranetUseLocalClaimsProvider},

        [System.Nullable[int]]
        ${TlsClientPort},

        [ValidateNotNull()]
        [uri]
        ${Identifier},

        [ValidateSet('Errors','FailureAudits','Information','Verbose','None','SuccessAudits','Warnings')]
        [string[]]
        ${LogLevel},

        [System.Nullable[int]]
        ${MonitoringInterval},

        [System.Nullable[int]]
        ${NetTcpPort},

        [System.Nullable[bool]]
        ${NtlmOnlySupportedClientAtProxy},

        [Microsoft.IdentityServer.Management.Resources.Organization]
        ${OrganizationInfo},

        [System.Nullable[bool]]
        ${PreventTokenReplays},

        [ValidateSet('Allow','Require','None')]
        [string]
        ${ExtendedProtectionTokenCheck},

        [ValidateRange(1, 2147483647)]
        [System.Nullable[int]]
        ${ProxyTrustTokenLifetime},

        [ValidateRange(0, 2147483647)]
        [System.Nullable[int]]
        ${ReplayCacheExpirationInterval},

        [System.Nullable[bool]]
        ${SignedSamlRequestsRequired},

        [System.Nullable[int]]
        ${SamlMessageDeliveryWindow},

        [System.Nullable[bool]]
        ${SignSamlAuthnRequests},

        [ValidateRange(1, 2147483647)]
        [int]
        ${SsoLifetime},

        [bool]
        ${SsoEnabled},

        [ValidateRange(1, 2628000)]
        [int]
        ${PersistentSsoLifetimeMins},

        [ValidateRange(1, 2628000)]
        [int]
        ${KmsiLifetimeMins},

        [bool]
        ${EnablePersistentSso},

        [datetime]
        ${PersistentSsoCutoffTime},

        [bool]
        ${EnableKmsi},

        [string[]]
        ${WIASupportedUserAgents},

        [string[]]
        ${BrowserSsoSupportedUserAgents},

        [bool]
        ${BrowserSsoEnabled},

        [ValidateRange(5, 2147483647)]
        [int]
        ${LoopDetectionTimeIntervalInSeconds},

        [ValidateRange(1, 2147483647)]
        [int]
        ${LoopDetectionMaximumTokensIssuedInInterval},

        [bool]
        ${EnableLoopDetection},

        [ValidateRange(1, 2147483647)]
        [System.Nullable[int]]
        ${ExtranetLockoutThreshold},

        [ValidateRange(1, 2147483647)]
        [System.Nullable[int]]
        ${ExtranetLockoutThresholdFamiliarLocation},

        [Microsoft.IdentityServer.PolicyModel.Configuration.ExtranetLockoutModes]
        ${ExtranetLockoutMode},

        [System.Nullable[bool]]
        ${EnableExtranetLockout},

        [System.Nullable[timespan]]
        ${ExtranetObservationWindow},

        [System.Nullable[bool]]
        ${ExtranetLockoutRequirePDC},

        [bool]
        ${SendClientRequestIdAsQueryStringParameter},

        [string]
        ${GlobalRelyingPartyClaimsIssuancePolicy},

        [bool]
        ${EnableLocalAuthenticationTypes},

        [string[]]
        ${AllowedActiveDirectoryUserPrincipalNames},

        [string[]]
        ${AllowedActiveDirectoryNetbiosNames},

        [bool]
        ${EnableRelayStateForIdpInitiatedSignOn},

        [string]
        ${DelegateServiceAdministration},

        [bool]
        ${AllowSystemServiceAdministration},

        [bool]
        ${AllowLocalAdminsServiceAdministration},

        [ValidateRange(1, 2147483647)]
        [System.Nullable[int]]
        ${DeviceUsageWindowInDays},

        [System.Nullable[bool]]
        ${EnableIdPInitiatedSignonPage},

        [System.Nullable[bool]]
        ${IgnoreTokenBinding},

        [ValidateNotNull()]
        [uri]
        ${IdTokenIssuer},

        [Microsoft.IdentityServer.PolicyModel.Configuration.PromptLoginFederation]
        ${PromptLoginFederation},

        [string]
        ${PromptLoginFallbackAuthenticationType},

        [ValidateNotNullOrEmpty()]
        [string[]]
        ${AddBannedIps},

        [ValidateNotNullOrEmpty()]
        [string[]]
        ${RemoveBannedIps},

        [System.Nullable[Microsoft.IdentityServer.PolicyModel.Configuration.WindowsHelloKeyVerificationOptions]]
        ${WindowsHelloKeyVerification},

        [switch]
        ${Force},

        [switch]
        ${PassThru}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Set-AdfsRegistrationHosts {
    <#
    .SYNOPSIS
        Set-AdfsRegistrationHosts [-UpnSuffixes] <string[]> [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    param (
        [Parameter(Mandatory=$true, Position=0)]
        [string[]]
        ${UpnSuffixes},

        [switch]
        ${PassThru}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Set-AdfsRelyingPartyTrust {
    <#
    .SYNOPSIS
        Set-AdfsRelyingPartyTrust -TargetIdentifier <string> [-AllowedAuthenticationClassReferences <string[]>] [-Name <string>] [-NotBeforeSkew <int>] [-EnableJWT <bool>] [-Identifier <string[]>] [-EncryptionCertificate <X509Certificate2>] [-EncryptionCertificateRevocationCheck <string>] [-EncryptClaims <bool>] [-MetadataUrl <uri>] [-IssuanceAuthorizationRules <string>] [-IssuanceAuthorizationRulesFile <string>] [-DelegationAuthorizationRules <string>] [-DelegationAuthorizationRulesFile <string>] [-ImpersonationAuthorizationRules <string>] [-ImpersonationAuthorizationRulesFile <string>] [-IssuanceTransformRules <string>] [-IssuanceTransformRulesFile <string>] [-AdditionalAuthenticationRules <string>] [-AdditionalAuthenticationRulesFile <string>] [-AccessControlPolicyName <string>] [-AccessControlPolicyParameters <Object>] [-AutoUpdateEnabled <bool>] [-WSFedEndpoint <uri>] [-AdditionalWSFedEndpoint <string[]>] [-ClaimsProviderName <string[]>] [-MonitoringEnabled <bool>] [-Notes <string>] [-ClaimAccepted <ClaimDescription[]>] [-SamlEndpoint <SamlEndpoint[]>] [-ProtocolProfile <string>] [-RequestSigningCertificate <X509Certificate2[]>] [-EncryptedNameIdRequired <bool>] [-SignedSamlRequestsRequired <bool>] [-SamlResponseSignature <string>] [-SignatureAlgorithm <string>] [-SigningCertificateRevocationCheck <string>] [-TokenLifetime <int>] [-AlwaysRequireAuthentication <bool>] [-AllowedClientTypes <AllowedClientTypes>] [-IssueOAuthRefreshTokensTo <RefreshTokenIssuanceDeviceTypes>] [-RefreshTokenProtectionEnabled <bool>] [-RequestMFAFromClaimsProviders <bool>] [-DeviceAuthenticationMethod <DeviceAuthenticationMethod>] [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]

Set-AdfsRelyingPartyTrust -TargetRelyingParty <RelyingPartyTrust> [-AllowedAuthenticationClassReferences <string[]>] [-Name <string>] [-NotBeforeSkew <int>] [-EnableJWT <bool>] [-Identifier <string[]>] [-EncryptionCertificate <X509Certificate2>] [-EncryptionCertificateRevocationCheck <string>] [-EncryptClaims <bool>] [-MetadataUrl <uri>] [-IssuanceAuthorizationRules <string>] [-IssuanceAuthorizationRulesFile <string>] [-DelegationAuthorizationRules <string>] [-DelegationAuthorizationRulesFile <string>] [-ImpersonationAuthorizationRules <string>] [-ImpersonationAuthorizationRulesFile <string>] [-IssuanceTransformRules <string>] [-IssuanceTransformRulesFile <string>] [-AdditionalAuthenticationRules <string>] [-AdditionalAuthenticationRulesFile <string>] [-AccessControlPolicyName <string>] [-AccessControlPolicyParameters <Object>] [-AutoUpdateEnabled <bool>] [-WSFedEndpoint <uri>] [-AdditionalWSFedEndpoint <string[]>] [-ClaimsProviderName <string[]>] [-MonitoringEnabled <bool>] [-Notes <string>] [-ClaimAccepted <ClaimDescription[]>] [-SamlEndpoint <SamlEndpoint[]>] [-ProtocolProfile <string>] [-RequestSigningCertificate <X509Certificate2[]>] [-EncryptedNameIdRequired <bool>] [-SignedSamlRequestsRequired <bool>] [-SamlResponseSignature <string>] [-SignatureAlgorithm <string>] [-SigningCertificateRevocationCheck <string>] [-TokenLifetime <int>] [-AlwaysRequireAuthentication <bool>] [-AllowedClientTypes <AllowedClientTypes>] [-IssueOAuthRefreshTokensTo <RefreshTokenIssuanceDeviceTypes>] [-RefreshTokenProtectionEnabled <bool>] [-RequestMFAFromClaimsProviders <bool>] [-DeviceAuthenticationMethod <DeviceAuthenticationMethod>] [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]

Set-AdfsRelyingPartyTrust -TargetName <string> [-AllowedAuthenticationClassReferences <string[]>] [-Name <string>] [-NotBeforeSkew <int>] [-EnableJWT <bool>] [-Identifier <string[]>] [-EncryptionCertificate <X509Certificate2>] [-EncryptionCertificateRevocationCheck <string>] [-EncryptClaims <bool>] [-MetadataUrl <uri>] [-IssuanceAuthorizationRules <string>] [-IssuanceAuthorizationRulesFile <string>] [-DelegationAuthorizationRules <string>] [-DelegationAuthorizationRulesFile <string>] [-ImpersonationAuthorizationRules <string>] [-ImpersonationAuthorizationRulesFile <string>] [-IssuanceTransformRules <string>] [-IssuanceTransformRulesFile <string>] [-AdditionalAuthenticationRules <string>] [-AdditionalAuthenticationRulesFile <string>] [-AccessControlPolicyName <string>] [-AccessControlPolicyParameters <Object>] [-AutoUpdateEnabled <bool>] [-WSFedEndpoint <uri>] [-AdditionalWSFedEndpoint <string[]>] [-ClaimsProviderName <string[]>] [-MonitoringEnabled <bool>] [-Notes <string>] [-ClaimAccepted <ClaimDescription[]>] [-SamlEndpoint <SamlEndpoint[]>] [-ProtocolProfile <string>] [-RequestSigningCertificate <X509Certificate2[]>] [-EncryptedNameIdRequired <bool>] [-SignedSamlRequestsRequired <bool>] [-SamlResponseSignature <string>] [-SignatureAlgorithm <string>] [-SigningCertificateRevocationCheck <string>] [-TokenLifetime <int>] [-AlwaysRequireAuthentication <bool>] [-AllowedClientTypes <AllowedClientTypes>] [-IssueOAuthRefreshTokensTo <RefreshTokenIssuanceDeviceTypes>] [-RefreshTokenProtectionEnabled <bool>] [-RequestMFAFromClaimsProviders <bool>] [-DeviceAuthenticationMethod <DeviceAuthenticationMethod>] [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    param (
        [ValidateNotNull()]
        [string[]]
        ${AllowedAuthenticationClassReferences},

        [ValidateNotNullOrEmpty()]
        [string]
        ${Name},

        [ValidateRange(0, 15)]
        [System.Nullable[int]]
        ${NotBeforeSkew},

        [System.Nullable[bool]]
        ${EnableJWT},

        [ValidateNotNull()]
        [string[]]
        ${Identifier},

        [System.Security.Cryptography.X509Certificates.X509Certificate2]
        ${EncryptionCertificate},

        [ValidateSet('CheckChain','CheckChainCacheOnly','CheckChainExcludeRoot','CheckChainExcludeRootCacheOnly','CheckEndCert','CheckEndCertCacheOnly','None')]
        [string]
        ${EncryptionCertificateRevocationCheck},

        [System.Nullable[bool]]
        ${EncryptClaims},

        [uri]
        ${MetadataUrl},

        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [string]
        ${IssuanceAuthorizationRules},

        [ValidateNotNullOrEmpty()]
        [string]
        ${IssuanceAuthorizationRulesFile},

        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [string]
        ${DelegationAuthorizationRules},

        [ValidateNotNullOrEmpty()]
        [string]
        ${DelegationAuthorizationRulesFile},

        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [string]
        ${ImpersonationAuthorizationRules},

        [ValidateNotNullOrEmpty()]
        [string]
        ${ImpersonationAuthorizationRulesFile},

        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [string]
        ${IssuanceTransformRules},

        [ValidateNotNullOrEmpty()]
        [string]
        ${IssuanceTransformRulesFile},

        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [string]
        ${AdditionalAuthenticationRules},

        [ValidateNotNullOrEmpty()]
        [string]
        ${AdditionalAuthenticationRulesFile},

        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [string]
        ${AccessControlPolicyName},

        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [System.Object]
        ${AccessControlPolicyParameters},

        [System.Nullable[bool]]
        ${AutoUpdateEnabled},

        [uri]
        ${WSFedEndpoint},

        [string[]]
        ${AdditionalWSFedEndpoint},

        [string[]]
        ${ClaimsProviderName},

        [System.Nullable[bool]]
        ${MonitoringEnabled},

        [ValidateNotNullOrEmpty()]
        [string]
        ${Notes},

        [Parameter(ValueFromPipeline=$true)]
        [Microsoft.IdentityServer.Management.Resources.ClaimDescription[]]
        ${ClaimAccepted},

        [Parameter(ValueFromPipeline=$true)]
        [string[]]
        ${SamlEndpoint},

        [ValidateSet('WsFed-SAML','WSFederation','SAML')]
        [string]
        ${ProtocolProfile},

        [Parameter(ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [System.Security.Cryptography.X509Certificates.X509Certificate2[]]
        ${RequestSigningCertificate},

        [ValidateNotNull()]
        [System.Nullable[bool]]
        ${EncryptedNameIdRequired},

        [ValidateNotNull()]
        [System.Nullable[bool]]
        ${SignedSamlRequestsRequired},

        [ValidateSet('AssertionOnly','MessageAndAssertion','MessageOnly')]
        [string]
        ${SamlResponseSignature},

        [ValidateSet('http://www.w3.org/2000/09/xmldsig#rsa-sha1','http://www.w3.org/2001/04/xmldsig-more#rsa-sha256')]
        [string]
        ${SignatureAlgorithm},

        [ValidateSet('CheckChain','CheckChainCacheOnly','CheckChainExcludeRoot','CheckChainExcludeRootCacheOnly','CheckEndCert','CheckEndCertCacheOnly','None')]
        [string]
        ${SigningCertificateRevocationCheck},

        [System.Nullable[int]]
        ${TokenLifetime},

        [bool]
        ${AlwaysRequireAuthentication},

        [Microsoft.IdentityServer.Protocols.PolicyStore.AllowedClientTypes]
        ${AllowedClientTypes},

        [Microsoft.IdentityServer.Protocols.PolicyStore.RefreshTokenIssuanceDeviceTypes]
        ${IssueOAuthRefreshTokensTo},

        [System.Nullable[bool]]
        ${RefreshTokenProtectionEnabled},

        [ValidateNotNull()]
        [System.Nullable[bool]]
        ${RequestMFAFromClaimsProviders},

        [System.Nullable[Microsoft.IdentityServer.PolicyModel.Configuration.DeviceAuthenticationMethod]]
        ${DeviceAuthenticationMethod},

        [Parameter(ParameterSetName='Identifier', Mandatory=$true, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [string]
        ${TargetIdentifier},

        [Parameter(ParameterSetName='IdentifierObject', Mandatory=$true, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [Microsoft.IdentityServer.Management.Resources.RelyingPartyTrust]
        ${TargetRelyingParty},

        [Parameter(ParameterSetName='IdentifierName', Mandatory=$true, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [string]
        ${TargetName},

        [switch]
        ${PassThru}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Set-AdfsRelyingPartyWebContent {
    <#
    .SYNOPSIS
        Set-AdfsRelyingPartyWebContent [[-Locale] <cultureinfo>] -TargetRelyingPartyName <string> [-CertificatePageDescriptionText <string>] [-CompanyName <string>] [-ErrorPageDescriptionText <string>] [-ErrorPageGenericErrorMessage <string>] [-ErrorPageAuthorizationErrorMessage <string>] [-ErrorPageDeviceAuthenticationErrorMessage <string>] [-ErrorPageSupportEmail <string>] [-HelpDeskLink <uri>] [-HelpDeskLinkText <string>] [-HomeLink <uri>] [-HomeLinkText <string>] [-HomeRealmDiscoveryOtherOrganizationDescriptionText <string>] [-HomeRealmDiscoveryPageDescriptionText <string>] [-OrganizationalNameDescriptionText <string>] [-PrivacyLink <uri>] [-PrivacyLinkText <string>] [-SignInPageDescriptionText <string>] [-SignInPageAdditionalAuthenticationDescriptionText <string>] [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]

Set-AdfsRelyingPartyWebContent [-TargetRelyingPartyWebContent] <AdfsRelyingPartyWebContent> [-CertificatePageDescriptionText <string>] [-CompanyName <string>] [-ErrorPageDescriptionText <string>] [-ErrorPageGenericErrorMessage <string>] [-ErrorPageAuthorizationErrorMessage <string>] [-ErrorPageDeviceAuthenticationErrorMessage <string>] [-ErrorPageSupportEmail <string>] [-HelpDeskLink <uri>] [-HelpDeskLinkText <string>] [-HomeLink <uri>] [-HomeLinkText <string>] [-HomeRealmDiscoveryOtherOrganizationDescriptionText <string>] [-HomeRealmDiscoveryPageDescriptionText <string>] [-OrganizationalNameDescriptionText <string>] [-PrivacyLink <uri>] [-PrivacyLinkText <string>] [-SignInPageDescriptionText <string>] [-SignInPageAdditionalAuthenticationDescriptionText <string>] [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(DefaultParameterSetName='IdentifierName', SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    param (
        [string]
        ${CertificatePageDescriptionText},

        [string]
        ${CompanyName},

        [string]
        ${ErrorPageDescriptionText},

        [string]
        ${ErrorPageGenericErrorMessage},

        [string]
        ${ErrorPageAuthorizationErrorMessage},

        [string]
        ${ErrorPageDeviceAuthenticationErrorMessage},

        [string]
        ${ErrorPageSupportEmail},

        [uri]
        ${HelpDeskLink},

        [string]
        ${HelpDeskLinkText},

        [uri]
        ${HomeLink},

        [string]
        ${HomeLinkText},

        [string]
        ${HomeRealmDiscoveryOtherOrganizationDescriptionText},

        [string]
        ${HomeRealmDiscoveryPageDescriptionText},

        [string]
        ${OrganizationalNameDescriptionText},

        [uri]
        ${PrivacyLink},

        [string]
        ${PrivacyLinkText},

        [string]
        ${SignInPageDescriptionText},

        [string]
        ${SignInPageAdditionalAuthenticationDescriptionText},

        [switch]
        ${PassThru},

        [Parameter(ParameterSetName='IdentifierName', Position=0, ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNull()]
        [cultureinfo]
        ${Locale},

        [Parameter(ParameterSetName='IdentifierName', Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [Alias('Name')]
        [ValidateNotNullOrEmpty()]
        [string]
        ${TargetRelyingPartyName},

        [Parameter(ParameterSetName='IdentifierObject', Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [Alias('TargetWebContent')]
        [ValidateNotNull()]
        [Microsoft.IdentityServer.Management.Resources.AdfsRelyingPartyWebContent]
        ${TargetRelyingPartyWebContent}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Set-AdfsRelyingPartyWebTheme {
    <#
    .SYNOPSIS
        Set-AdfsRelyingPartyWebTheme [-TargetRelyingPartyName] <string> [-StyleSheet <hashtable[]>] [-RTLStyleSheetPath <string>] [-OnLoadScriptPath <string>] [-Logo <hashtable[]>] [-Illustration <hashtable[]>] [-SourceWebThemeName <string>] [-SourceRelyingPartyName <string>] [-WhatIf] [-Confirm] [<CommonParameters>]

Set-AdfsRelyingPartyWebTheme [-TargetRelyingPartyWebTheme] <AdfsRelyingPartyWebTheme> [-StyleSheet <hashtable[]>] [-RTLStyleSheetPath <string>] [-OnLoadScriptPath <string>] [-Logo <hashtable[]>] [-Illustration <hashtable[]>] [-SourceWebThemeName <string>] [-SourceRelyingPartyName <string>] [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(DefaultParameterSetName='IdentifierName', SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    param (
        [ValidateNotNullOrEmpty()]
        [hashtable[]]
        ${StyleSheet},

        [string]
        ${RTLStyleSheetPath},

        [string]
        ${OnLoadScriptPath},

        [ValidateNotNullOrEmpty()]
        [hashtable[]]
        ${Logo},

        [ValidateNotNullOrEmpty()]
        [hashtable[]]
        ${Illustration},

        [ValidateNotNullOrEmpty()]
        [string]
        ${SourceWebThemeName},

        [ValidateNotNullOrEmpty()]
        [string]
        ${SourceRelyingPartyName},

        [Parameter(ParameterSetName='IdentifierName', Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [Alias('Name')]
        [ValidateNotNullOrEmpty()]
        [string]
        ${TargetRelyingPartyName},

        [Parameter(ParameterSetName='IdentifierObject', Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [Alias('TargetWebTheme')]
        [ValidateNotNull()]
        [Microsoft.IdentityServer.Management.Resources.AdfsRelyingPartyWebTheme]
        ${TargetRelyingPartyWebTheme}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Set-AdfsResponseHeaders {
    <#
    .SYNOPSIS
        Set-AdfsResponseHeaders [-RemoveHeaders <string[]>] [-EnablePublicKeyPinning <bool>] [-PublicKeyPinningReportUri <uri>] [-PublicKeyPrimary <string>] [-PublicKeySecondary <string>] [-EnableCORS <bool>] [-EnableResponseHeaders <bool>] [-CORSTrustedOrigins <string[]>] [-AdditionalPublicKeys <string[]>] [-WhatIf] [-Confirm] [<CommonParameters>]

Set-AdfsResponseHeaders -SetHeaderName <string> -SetHeaderValue <string> [-RemoveHeaders <string[]>] [-EnablePublicKeyPinning <bool>] [-PublicKeyPinningReportUri <uri>] [-PublicKeyPrimary <string>] [-PublicKeySecondary <string>] [-EnableCORS <bool>] [-EnableResponseHeaders <bool>] [-CORSTrustedOrigins <string[]>] [-AdditionalPublicKeys <string[]>] [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(DefaultParameterSetName='DefaultSet', SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    param (
        [Parameter(ParameterSetName='SetHeader', Mandatory=$true)]
        [string]
        ${SetHeaderName},

        [Parameter(ParameterSetName='SetHeader', Mandatory=$true)]
        [string]
        ${SetHeaderValue},

        [string[]]
        ${RemoveHeaders},

        [System.Nullable[bool]]
        ${EnablePublicKeyPinning},

        [uri]
        ${PublicKeyPinningReportUri},

        [string]
        ${PublicKeyPrimary},

        [string]
        ${PublicKeySecondary},

        [System.Nullable[bool]]
        ${EnableCORS},

        [System.Nullable[bool]]
        ${EnableResponseHeaders},

        [string[]]
        ${CORSTrustedOrigins},

        [string[]]
        ${AdditionalPublicKeys}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Set-AdfsScopeDescription {
    <#
    .SYNOPSIS
        Set-AdfsScopeDescription [-Description <string>] [-WhatIf] [-Confirm] [<CommonParameters>]

Set-AdfsScopeDescription [-TargetName] <string> [-Description <string>] [-WhatIf] [-Confirm] [<CommonParameters>]

Set-AdfsScopeDescription [-InputObject] <OAuthScopeDescription> [-Description <string>] [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(DefaultParameterSetName='Identifier', SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    param (
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [string]
        ${Description},

        [Parameter(ParameterSetName='Name', Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [string]
        ${TargetName},

        [Parameter(ParameterSetName='InputObject', Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [Microsoft.IdentityServer.Management.Resources.OAuthScopeDescription]
        ${InputObject}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Set-AdfsServerApplication {
    <#
    .SYNOPSIS
        Set-AdfsServerApplication [-TargetIdentifier] <string> [-Identifier <string>] [-Name <string>] [-RedirectUri <string[]>] [-Description <string>] [-ADUserPrincipalName <string>] [-JWTSigningCertificate <X509Certificate2[]>] [-JWTSigningCertificateRevocationCheck <RevocationSetting>] [-ChangeClientSecret] [-ResetClientSecret] [-JWKSUri <uri>] [-ReloadJWTSigningKeys] [-JWKSFile <string>] [-LogoutUri <string>] [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]

Set-AdfsServerApplication [-TargetName] <string> [-Identifier <string>] [-Name <string>] [-RedirectUri <string[]>] [-Description <string>] [-ADUserPrincipalName <string>] [-JWTSigningCertificate <X509Certificate2[]>] [-JWTSigningCertificateRevocationCheck <RevocationSetting>] [-ChangeClientSecret] [-ResetClientSecret] [-JWKSUri <uri>] [-ReloadJWTSigningKeys] [-JWKSFile <string>] [-LogoutUri <string>] [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]

Set-AdfsServerApplication [-TargetApplication] <ServerApplication> [-Identifier <string>] [-Name <string>] [-RedirectUri <string[]>] [-Description <string>] [-ADUserPrincipalName <string>] [-JWTSigningCertificate <X509Certificate2[]>] [-JWTSigningCertificateRevocationCheck <RevocationSetting>] [-ChangeClientSecret] [-ResetClientSecret] [-JWKSUri <uri>] [-ReloadJWTSigningKeys] [-JWKSFile <string>] [-LogoutUri <string>] [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(DefaultParameterSetName='Identifier', SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    param (
        [Parameter(ParameterSetName='Identifier', Mandatory=$true, Position=0, ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${TargetIdentifier},

        [Parameter(ParameterSetName='Name', Mandatory=$true, Position=0, ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${TargetName},

        [Parameter(ParameterSetName='ApplicationObject', Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [Microsoft.IdentityServer.Management.Resources.ServerApplication]
        ${TargetApplication},

        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${Identifier},

        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${Name},

        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [string[]]
        ${RedirectUri},

        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [string]
        ${Description},

        [string]
        ${ADUserPrincipalName},

        [System.Security.Cryptography.X509Certificates.X509Certificate2[]]
        ${JWTSigningCertificate},

        [Microsoft.IdentityServer.PolicyModel.Configuration.RevocationSetting]
        ${JWTSigningCertificateRevocationCheck},

        [switch]
        ${ChangeClientSecret},

        [switch]
        ${ResetClientSecret},

        [uri]
        ${JWKSUri},

        [switch]
        ${ReloadJWTSigningKeys},

        [string]
        ${JWKSFile},

        [ValidateNotNull()]
        [string]
        ${LogoutUri},

        [switch]
        ${PassThru}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Set-AdfsSslCertificate {
    <#
    .SYNOPSIS
        Set-AdfsSslCertificate -Thumbprint <string> [-Member <string[]>] [-Force <bool>] [-RemoteCredential <pscredential>] [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    param (
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [string]
        ${Thumbprint},

        [ValidateNotNullOrEmpty()]
        [string[]]
        ${Member},

        [bool]
        ${Force},

        [pscredential]
        ${RemoteCredential}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Set-AdfsSyncProperties {
    <#
    .SYNOPSIS
        Set-AdfsSyncProperties [-PrimaryComputerName <string>] [-PrimaryComputerPort <int>] [-PollDuration <int>] [-Role <string>] [<CommonParameters>]
    #>

    [CmdletBinding()]
    param (
        [string]
        ${PrimaryComputerName},

        [System.Nullable[int]]
        ${PrimaryComputerPort},

        [System.Nullable[int]]
        ${PollDuration},

        [ValidateNotNullOrEmpty()]
        [string]
        ${Role}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Set-AdfsTrustedFederationPartner {
    <#
    .SYNOPSIS
        Set-AdfsTrustedFederationPartner [-TargetName] <string> [-FederationPartnerHostName <uri>] [-Name <string>] [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]

Set-AdfsTrustedFederationPartner [-TargetFederationPartnerHostName] <uri> [-FederationPartnerHostName <uri>] [-Name <string>] [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]

Set-AdfsTrustedFederationPartner [-TargetFederationPartner] <AdfsTrustedFederationPartner> [-FederationPartnerHostName <uri>] [-Name <string>] [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(DefaultParameterSetName='Name', SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    param (
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [uri]
        ${FederationPartnerHostName},

        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${Name},

        [Parameter(ParameterSetName='Name', Mandatory=$true, Position=0, ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNull()]
        [string]
        ${TargetName},

        [Parameter(ParameterSetName='FederationPartnerHostName', Mandatory=$true, Position=0, ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNull()]
        [uri]
        ${TargetFederationPartnerHostName},

        [Parameter(ParameterSetName='InputObject', Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [Microsoft.IdentityServer.Management.Resources.AdfsTrustedFederationPartner]
        ${TargetFederationPartner},

        [switch]
        ${PassThru}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Set-AdfsWebApiApplication {
    <#
    .SYNOPSIS
        Set-AdfsWebApiApplication [-TargetIdentifier] <string> [-AllowedAuthenticationClassReferences <string[]>] [-AlwaysRequireAuthentication <bool>] [-ClaimsProviderName <string[]>] [-Name <string>] [-NotBeforeSkew <int>] [-Identifier <string[]>] [-IssuanceAuthorizationRules <string>] [-IssuanceAuthorizationRulesFile <string>] [-DelegationAuthorizationRules <string>] [-DelegationAuthorizationRulesFile <string>] [-ImpersonationAuthorizationRules <string>] [-ImpersonationAuthorizationRulesFile <string>] [-IssuanceTransformRules <string>] [-IssuanceTransformRulesFile <string>] [-AdditionalAuthenticationRules <string>] [-AdditionalAuthenticationRulesFile <string>] [-AccessControlPolicyName <string>] [-AccessControlPolicyParameters <Object>] [-Description <string>] [-TokenLifetime <int>] [-AllowedClientTypes <AllowedClientTypes>] [-IssueOAuthRefreshTokensTo <RefreshTokenIssuanceDeviceTypes>] [-RefreshTokenProtectionEnabled <bool>] [-RequestMFAFromClaimsProviders <bool>] [-DeviceAuthenticationMethod <DeviceAuthenticationMethod>] [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]

Set-AdfsWebApiApplication [-TargetName] <string> [-AllowedAuthenticationClassReferences <string[]>] [-AlwaysRequireAuthentication <bool>] [-ClaimsProviderName <string[]>] [-Name <string>] [-NotBeforeSkew <int>] [-Identifier <string[]>] [-IssuanceAuthorizationRules <string>] [-IssuanceAuthorizationRulesFile <string>] [-DelegationAuthorizationRules <string>] [-DelegationAuthorizationRulesFile <string>] [-ImpersonationAuthorizationRules <string>] [-ImpersonationAuthorizationRulesFile <string>] [-IssuanceTransformRules <string>] [-IssuanceTransformRulesFile <string>] [-AdditionalAuthenticationRules <string>] [-AdditionalAuthenticationRulesFile <string>] [-AccessControlPolicyName <string>] [-AccessControlPolicyParameters <Object>] [-Description <string>] [-TokenLifetime <int>] [-AllowedClientTypes <AllowedClientTypes>] [-IssueOAuthRefreshTokensTo <RefreshTokenIssuanceDeviceTypes>] [-RefreshTokenProtectionEnabled <bool>] [-RequestMFAFromClaimsProviders <bool>] [-DeviceAuthenticationMethod <DeviceAuthenticationMethod>] [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]

Set-AdfsWebApiApplication [-TargetApplication] <WebApiApplication> [-AllowedAuthenticationClassReferences <string[]>] [-AlwaysRequireAuthentication <bool>] [-ClaimsProviderName <string[]>] [-Name <string>] [-NotBeforeSkew <int>] [-Identifier <string[]>] [-IssuanceAuthorizationRules <string>] [-IssuanceAuthorizationRulesFile <string>] [-DelegationAuthorizationRules <string>] [-DelegationAuthorizationRulesFile <string>] [-ImpersonationAuthorizationRules <string>] [-ImpersonationAuthorizationRulesFile <string>] [-IssuanceTransformRules <string>] [-IssuanceTransformRulesFile <string>] [-AdditionalAuthenticationRules <string>] [-AdditionalAuthenticationRulesFile <string>] [-AccessControlPolicyName <string>] [-AccessControlPolicyParameters <Object>] [-Description <string>] [-TokenLifetime <int>] [-AllowedClientTypes <AllowedClientTypes>] [-IssueOAuthRefreshTokensTo <RefreshTokenIssuanceDeviceTypes>] [-RefreshTokenProtectionEnabled <bool>] [-RequestMFAFromClaimsProviders <bool>] [-DeviceAuthenticationMethod <DeviceAuthenticationMethod>] [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(DefaultParameterSetName='Identifier', SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    param (
        [Parameter(ParameterSetName='Identifier', Mandatory=$true, Position=0, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${TargetIdentifier},

        [Parameter(ParameterSetName='Name', Mandatory=$true, Position=0, ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${TargetName},

        [Parameter(ParameterSetName='ApplicationObject', Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [Microsoft.IdentityServer.Management.Resources.WebApiApplication]
        ${TargetApplication},

        [ValidateNotNull()]
        [string[]]
        ${AllowedAuthenticationClassReferences},

        [bool]
        ${AlwaysRequireAuthentication},

        [string[]]
        ${ClaimsProviderName},

        [ValidateNotNullOrEmpty()]
        [string]
        ${Name},

        [ValidateRange(0, 15)]
        [System.Nullable[int]]
        ${NotBeforeSkew},

        [ValidateNotNullOrEmpty()]
        [string[]]
        ${Identifier},

        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [string]
        ${IssuanceAuthorizationRules},

        [ValidateNotNullOrEmpty()]
        [string]
        ${IssuanceAuthorizationRulesFile},

        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [string]
        ${DelegationAuthorizationRules},

        [ValidateNotNullOrEmpty()]
        [string]
        ${DelegationAuthorizationRulesFile},

        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [string]
        ${ImpersonationAuthorizationRules},

        [ValidateNotNullOrEmpty()]
        [string]
        ${ImpersonationAuthorizationRulesFile},

        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [string]
        ${IssuanceTransformRules},

        [ValidateNotNullOrEmpty()]
        [string]
        ${IssuanceTransformRulesFile},

        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [string]
        ${AdditionalAuthenticationRules},

        [ValidateNotNullOrEmpty()]
        [string]
        ${AdditionalAuthenticationRulesFile},

        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [string]
        ${AccessControlPolicyName},

        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [System.Object]
        ${AccessControlPolicyParameters},

        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${Description},

        [System.Nullable[int]]
        ${TokenLifetime},

        [Microsoft.IdentityServer.Protocols.PolicyStore.AllowedClientTypes]
        ${AllowedClientTypes},

        [Microsoft.IdentityServer.Protocols.PolicyStore.RefreshTokenIssuanceDeviceTypes]
        ${IssueOAuthRefreshTokensTo},

        [System.Nullable[bool]]
        ${RefreshTokenProtectionEnabled},

        [ValidateNotNull()]
        [System.Nullable[bool]]
        ${RequestMFAFromClaimsProviders},

        [System.Nullable[Microsoft.IdentityServer.PolicyModel.Configuration.DeviceAuthenticationMethod]]
        ${DeviceAuthenticationMethod},

        [switch]
        ${PassThru}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Set-AdfsWebApplicationProxyRelyingPartyTrust {
    <#
    .SYNOPSIS
        Set-AdfsWebApplicationProxyRelyingPartyTrust [-AlwaysRequireAuthentication <bool>] [-Identifier <string[]>] [-AccessControlPolicyName <string>] [-AccessControlPolicyParameters <Object>] [-IssuanceAuthorizationRules <string>] [-IssuanceAuthorizationRulesFile <string>] [-IssuanceTransformRules <string>] [-IssuanceTransformRulesFile <string>] [-AdditionalAuthenticationRules <string>] [-AdditionalAuthenticationRulesFile <string>] [-Name <string>] [-NotBeforeSkew <int>] [-Notes <string>] [-PassThru] [-TokenLifetime <int>] [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Low')]
    param (
        [bool]
        ${AlwaysRequireAuthentication},

        [ValidateNotNull()]
        [string[]]
        ${Identifier},

        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [string]
        ${AccessControlPolicyName},

        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [System.Object]
        ${AccessControlPolicyParameters},

        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [string]
        ${IssuanceAuthorizationRules},

        [ValidateNotNullOrEmpty()]
        [string]
        ${IssuanceAuthorizationRulesFile},

        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [string]
        ${IssuanceTransformRules},

        [ValidateNotNullOrEmpty()]
        [string]
        ${IssuanceTransformRulesFile},

        [ValidateNotNullOrEmpty()]
        [string]
        ${AdditionalAuthenticationRules},

        [ValidateNotNullOrEmpty()]
        [string]
        ${AdditionalAuthenticationRulesFile},

        [ValidateNotNullOrEmpty()]
        [string]
        ${Name},

        [ValidateRange(0, 15)]
        [int]
        ${NotBeforeSkew},

        [ValidateNotNullOrEmpty()]
        [string]
        ${Notes},

        [switch]
        ${PassThru},

        [int]
        ${TokenLifetime}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Set-AdfsWebConfig {
    <#
    .SYNOPSIS
        Set-AdfsWebConfig [-ActiveThemeName <string>] [-CDCCookieReader <uri>] [-CDCCookieWriter <uri>] [-HRDCookieLifetime <int>] [-HRDCookieEnabled <bool>] [-ContextCookieEnabled <bool>] [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    param (
        [ValidateNotNullOrEmpty()]
        [string]
        ${ActiveThemeName},

        [uri]
        ${CDCCookieReader},

        [uri]
        ${CDCCookieWriter},

        [ValidateRange(1, 2147483647)]
        [int]
        ${HRDCookieLifetime},

        [bool]
        ${HRDCookieEnabled},

        [bool]
        ${ContextCookieEnabled},

        [switch]
        ${PassThru}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Set-AdfsWebTheme {
    <#
    .SYNOPSIS
        Set-AdfsWebTheme [-TargetName] <string> [-StyleSheet <hashtable[]>] [-RTLStyleSheetPath <string>] [-OnLoadScriptPath <string>] [-Logo <hashtable[]>] [-Illustration <hashtable[]>] [-AdditionalFileResource <hashtable[]>] [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]

Set-AdfsWebTheme [-TargetWebTheme] <AdfsWebTheme> [-StyleSheet <hashtable[]>] [-RTLStyleSheetPath <string>] [-OnLoadScriptPath <string>] [-Logo <hashtable[]>] [-Illustration <hashtable[]>] [-AdditionalFileResource <hashtable[]>] [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(DefaultParameterSetName='IdentifierName', SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    param (
        [ValidateNotNullOrEmpty()]
        [hashtable[]]
        ${StyleSheet},

        [string]
        ${RTLStyleSheetPath},

        [string]
        ${OnLoadScriptPath},

        [ValidateNotNullOrEmpty()]
        [hashtable[]]
        ${Logo},

        [ValidateNotNullOrEmpty()]
        [hashtable[]]
        ${Illustration},

        [ValidateNotNullOrEmpty()]
        [hashtable[]]
        ${AdditionalFileResource},

        [switch]
        ${PassThru},

        [Parameter(ParameterSetName='IdentifierName', Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${TargetName},

        [Parameter(ParameterSetName='IdentifierObject', Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [Microsoft.IdentityServer.Management.Resources.AdfsWebTheme]
        ${TargetWebTheme}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Test-AdfsFarmBehaviorLevelRaise {
    <#
    .SYNOPSIS
        Test-AdfsFarmBehaviorLevelRaise [-Member <string[]>] [-Credential <pscredential>] [-ServiceAccountCredential <pscredential>] [-Force] [<CommonParameters>]

Test-AdfsFarmBehaviorLevelRaise [-Member <string[]>] [-Credential <pscredential>] [-GroupServiceAccountIdentifier <string>] [-Force] [<CommonParameters>]
    #>

    [CmdletBinding(DefaultParameterSetName='AdfsUpgradeServiceAccount')]
    param (
        [ValidateNotNullOrEmpty()]
        [string[]]
        ${Member},

        [pscredential]
        ${Credential},

        [Parameter(ParameterSetName='AdfsUpgradeServiceAccount')]
        [pscredential]
        ${ServiceAccountCredential},

        [Parameter(ParameterSetName='AdfsUpgradeGmsaAccount')]
        [string]
        ${GroupServiceAccountIdentifier},

        [switch]
        ${Force}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Test-AdfsFarmBehaviorLevelRestore {
    <#
    .SYNOPSIS
        Test-AdfsFarmBehaviorLevelRestore -FarmBehavior <int> [-Member <string[]>] [-Credential <pscredential>] [-Force] [<CommonParameters>]
    #>

    [CmdletBinding()]
    param (
        [ValidateNotNullOrEmpty()]
        [string[]]
        ${Member},

        [pscredential]
        ${Credential},

        [Parameter(Mandatory=$true)]
        #[ValidateRange(Win2012R2, Max)]
        [int]
        ${FarmBehavior},

        [switch]
        ${Force}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Test-AdfsFarmInstallation {
    <#
    .SYNOPSIS
        Test-AdfsFarmInstallation -FederationServiceName <string> -ServiceAccountCredential <pscredential> [-CertificateThumbprint <string>] [-Credential <pscredential>] [-FederationServiceDisplayName <string>] [-OverwriteConfiguration] [-SSLPort <int>] [-TlsClientPort <int>] [-AdminConfiguration <hashtable>] [<CommonParameters>]

Test-AdfsFarmInstallation -DecryptionCertificateThumbprint <string> -FederationServiceName <string> -ServiceAccountCredential <pscredential> -SigningCertificateThumbprint <string> [-CertificateThumbprint <string>] [-Credential <pscredential>] [-FederationServiceDisplayName <string>] [-OverwriteConfiguration] [-SSLPort <int>] [-TlsClientPort <int>] [-AdminConfiguration <hashtable>] [<CommonParameters>]

Test-AdfsFarmInstallation -DecryptionCertificateThumbprint <string> -FederationServiceName <string> -ServiceAccountCredential <pscredential> -SigningCertificateThumbprint <string> -SQLConnectionString <string> [-CertificateThumbprint <string>] [-Credential <pscredential>] [-FederationServiceDisplayName <string>] [-OverwriteConfiguration] [-SSLPort <int>] [-TlsClientPort <int>] [-AdminConfiguration <hashtable>] [<CommonParameters>]

Test-AdfsFarmInstallation -DecryptionCertificateThumbprint <string> -FederationServiceName <string> -GroupServiceAccountIdentifier <string> -SigningCertificateThumbprint <string> [-CertificateThumbprint <string>] [-Credential <pscredential>] [-FederationServiceDisplayName <string>] [-OverwriteConfiguration] [-SSLPort <int>] [-TlsClientPort <int>] [-AdminConfiguration <hashtable>] [<CommonParameters>]

Test-AdfsFarmInstallation -DecryptionCertificateThumbprint <string> -FederationServiceName <string> -GroupServiceAccountIdentifier <string> -SigningCertificateThumbprint <string> -SQLConnectionString <string> [-CertificateThumbprint <string>] [-Credential <pscredential>] [-FederationServiceDisplayName <string>] [-OverwriteConfiguration] [-SSLPort <int>] [-TlsClientPort <int>] [-AdminConfiguration <hashtable>] [<CommonParameters>]

Test-AdfsFarmInstallation -FederationServiceName <string> -ServiceAccountCredential <pscredential> -SQLConnectionString <string> [-CertificateThumbprint <string>] [-Credential <pscredential>] [-FederationServiceDisplayName <string>] [-OverwriteConfiguration] [-SSLPort <int>] [-TlsClientPort <int>] [-AdminConfiguration <hashtable>] [<CommonParameters>]

Test-AdfsFarmInstallation -FederationServiceName <string> -GroupServiceAccountIdentifier <string> [-CertificateThumbprint <string>] [-Credential <pscredential>] [-FederationServiceDisplayName <string>] [-OverwriteConfiguration] [-SSLPort <int>] [-TlsClientPort <int>] [-AdminConfiguration <hashtable>] [<CommonParameters>]

Test-AdfsFarmInstallation -FederationServiceName <string> -GroupServiceAccountIdentifier <string> -SQLConnectionString <string> [-CertificateThumbprint <string>] [-Credential <pscredential>] [-FederationServiceDisplayName <string>] [-OverwriteConfiguration] [-SSLPort <int>] [-TlsClientPort <int>] [-AdminConfiguration <hashtable>] [<CommonParameters>]
    #>

    [CmdletBinding(DefaultParameterSetName='ADFSFarmCreateLocalDatabase')]
    param (
        [ValidateLength(1, 8192)]
        [string]
        ${CertificateThumbprint},

        [pscredential]
        ${Credential},

        [Parameter(ParameterSetName='ADFSFarmCreateLocalDatabaseDisableAutoCertRollover', Mandatory=$true)]
        [Parameter(ParameterSetName='ADFSFarmCreateSharedDatabaseDisableAutoCertRollover', Mandatory=$true)]
        [Parameter(ParameterSetName='AdfsFarmCreateLocalDatabaseDisableAutoCertRolloverGmsa', Mandatory=$true)]
        [Parameter(ParameterSetName='AdfsFarmCreateSharedDatabaseDisableAutoCertRolloverGmsa', Mandatory=$true)]
        [ValidateLength(1, 8192)]
        [string]
        ${DecryptionCertificateThumbprint},

        [Parameter(Mandatory=$true)]
        [ValidateLength(1, 255)]
        [string]
        ${FederationServiceName},

        [ValidateLength(0, 8192)]
        [string]
        ${FederationServiceDisplayName},

        [Parameter(ParameterSetName='ADFSFarmCreateLocalDatabase', Mandatory=$true)]
        [Parameter(ParameterSetName='ADFSFarmCreateSharedDatabase', Mandatory=$true)]
        [Parameter(ParameterSetName='ADFSFarmCreateLocalDatabaseDisableAutoCertRollover', Mandatory=$true)]
        [Parameter(ParameterSetName='ADFSFarmCreateSharedDatabaseDisableAutoCertRollover', Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [pscredential]
        ${ServiceAccountCredential},

        [Parameter(ParameterSetName='AdfsFarmCreateLocalDatabaseGmsa', Mandatory=$true)]
        [Parameter(ParameterSetName='AdfsFarmCreateSharedDatabaseGmsa', Mandatory=$true)]
        [Parameter(ParameterSetName='AdfsFarmCreateLocalDatabaseDisableAutoCertRolloverGmsa', Mandatory=$true)]
        [Parameter(ParameterSetName='AdfsFarmCreateSharedDatabaseDisableAutoCertRolloverGmsa', Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${GroupServiceAccountIdentifier},

        [Parameter(ParameterSetName='ADFSFarmCreateLocalDatabaseDisableAutoCertRollover', Mandatory=$true)]
        [Parameter(ParameterSetName='ADFSFarmCreateSharedDatabaseDisableAutoCertRollover', Mandatory=$true)]
        [Parameter(ParameterSetName='AdfsFarmCreateLocalDatabaseDisableAutoCertRolloverGmsa', Mandatory=$true)]
        [Parameter(ParameterSetName='AdfsFarmCreateSharedDatabaseDisableAutoCertRolloverGmsa', Mandatory=$true)]
        [ValidateLength(1, 8192)]
        [string]
        ${SigningCertificateThumbprint},

        [Parameter(ParameterSetName='ADFSFarmCreateSharedDatabase', Mandatory=$true)]
        [Parameter(ParameterSetName='ADFSFarmCreateSharedDatabaseDisableAutoCertRollover', Mandatory=$true)]
        [Parameter(ParameterSetName='AdfsFarmCreateSharedDatabaseGmsa', Mandatory=$true)]
        [Parameter(ParameterSetName='AdfsFarmCreateSharedDatabaseDisableAutoCertRolloverGmsa', Mandatory=$true)]
        [ValidateLength(1, 1024)]
        [string]
        ${SQLConnectionString},

        [switch]
        ${OverwriteConfiguration},

        [ValidateRange(1, 65535)]
        [int]
        ${SSLPort},

        [ValidateRange(1, 65535)]
        [int]
        ${TlsClientPort},

        [ValidateNotNull()]
        [ValidateCount(1, 1)]
        [hashtable]
        ${AdminConfiguration}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Test-AdfsFarmJoin {
    <#
    .SYNOPSIS
        Test-AdfsFarmJoin -GroupServiceAccountIdentifier <string> -PrimaryComputerName <string> [-CertificateThumbprint <string>] [-Credential <pscredential>] [-PrimaryComputerPort <int>] [<CommonParameters>]

Test-AdfsFarmJoin -ServiceAccountCredential <pscredential> -PrimaryComputerName <string> [-CertificateThumbprint <string>] [-Credential <pscredential>] [-PrimaryComputerPort <int>] [<CommonParameters>]

Test-AdfsFarmJoin -ServiceAccountCredential <pscredential> -SQLConnectionString <string> [-CertificateThumbprint <string>] [-Credential <pscredential>] [-FarmBehavior <int>] [<CommonParameters>]

Test-AdfsFarmJoin -GroupServiceAccountIdentifier <string> -SQLConnectionString <string> [-CertificateThumbprint <string>] [-Credential <pscredential>] [-FarmBehavior <int>] [<CommonParameters>]
    #>

    [CmdletBinding(DefaultParameterSetName='AdfsFarmJoinWidGmsa')]
    param (
        [ValidateLength(1, 8192)]
        [string]
        ${CertificateThumbprint},

        [Parameter(ParameterSetName='ADFSFarmJoinWidSvcAcct', Mandatory=$true)]
        [Parameter(ParameterSetName='ADFSFarmJoinSqlSvcAcct', Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [pscredential]
        ${ServiceAccountCredential},

        [Parameter(ParameterSetName='AdfsFarmJoinWidGmsa', Mandatory=$true)]
        [Parameter(ParameterSetName='AdfsFarmJoinSqlGmsa', Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${GroupServiceAccountIdentifier},

        [ValidateNotNullOrEmpty()]
        [pscredential]
        ${Credential},

        [Parameter(ParameterSetName='AdfsFarmJoinSqlGmsa', Mandatory=$true)]
        [Parameter(ParameterSetName='ADFSFarmJoinSqlSvcAcct', Mandatory=$true)]
        [ValidateLength(1, 1024)]
        [string]
        ${SQLConnectionString},

        [Parameter(ParameterSetName='AdfsFarmJoinWidGmsa', Mandatory=$true)]
        [Parameter(ParameterSetName='ADFSFarmJoinWidSvcAcct', Mandatory=$true)]
        [ValidateLength(1, 255)]
        [string]
        ${PrimaryComputerName},

        [Parameter(ParameterSetName='AdfsFarmJoinWidGmsa')]
        [Parameter(ParameterSetName='ADFSFarmJoinWidSvcAcct')]
        [ValidateRange(1, 65535)]
        [int]
        ${PrimaryComputerPort},

        [Parameter(ParameterSetName='AdfsFarmJoinSqlGmsa')]
        [Parameter(ParameterSetName='ADFSFarmJoinSqlSvcAcct')]
        #[ValidateRange(Win2012R2, Max)]
        [int]
        ${FarmBehavior}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Unregister-AdfsAuthenticationProvider {
    <#
    .SYNOPSIS
        Unregister-AdfsAuthenticationProvider [-Name] <string> [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
    param (
        [Parameter(Mandatory=$true, Position=0)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${Name}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Unregister-AdfsThreatDetectionModule {
    <#
    .SYNOPSIS
        Unregister-AdfsThreatDetectionModule [-Name] <string> [<CommonParameters>]
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, Position=0)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${Name}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Update-AdfsCertificate {
    <#
    .SYNOPSIS
        Update-AdfsCertificate [[-CertificateType] <string>] [-Urgent] [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    param (
        [Parameter(Position=0)]
        [ValidateSet('Token-Decrypting','Token-Signing')]
        [string]
        ${CertificateType},

        [switch]
        ${Urgent},

        [switch]
        ${PassThru}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Update-AdfsClaimsProviderTrust {
    <#
    .SYNOPSIS
        Update-AdfsClaimsProviderTrust -TargetClaimsProviderTrust <ClaimsProviderTrust> [-MetadataFile <string>] [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]

Update-AdfsClaimsProviderTrust -TargetCertificate <X509Certificate2> [-MetadataFile <string>] [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]

Update-AdfsClaimsProviderTrust -TargetIdentifier <string> [-MetadataFile <string>] [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]

Update-AdfsClaimsProviderTrust -TargetName <string> [-MetadataFile <string>] [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    param (
        [ValidateNotNullOrEmpty()]
        [string]
        ${MetadataFile},

        [Parameter(ParameterSetName='IdentifierObject', Mandatory=$true, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [Microsoft.IdentityServer.Management.Resources.ClaimsProviderTrust]
        ${TargetClaimsProviderTrust},

        [Parameter(ParameterSetName='TokenSigningCertificates', Mandatory=$true, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]
        ${TargetCertificate},

        [Parameter(ParameterSetName='Identifier', Mandatory=$true, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [string]
        ${TargetIdentifier},

        [Parameter(ParameterSetName='IdentifierName', Mandatory=$true, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [string]
        ${TargetName},

        [switch]
        ${PassThru}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

function Update-AdfsRelyingPartyTrust {
    <#
    .SYNOPSIS
        Update-AdfsRelyingPartyTrust -TargetIdentifier <string> [-MetadataFile <string>] [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]

Update-AdfsRelyingPartyTrust -TargetRelyingParty <RelyingPartyTrust> [-MetadataFile <string>] [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]

Update-AdfsRelyingPartyTrust -TargetName <string> [-MetadataFile <string>] [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]
    #>

    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    param (
        [ValidateNotNullOrEmpty()]
        [string]
        ${MetadataFile},

        [Parameter(ParameterSetName='Identifier', Mandatory=$true, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [string]
        ${TargetIdentifier},

        [Parameter(ParameterSetName='IdentifierObject', Mandatory=$true, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [Microsoft.IdentityServer.Management.Resources.RelyingPartyTrust]
        ${TargetRelyingParty},

        [Parameter(ParameterSetName='IdentifierName', Mandatory=$true, ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [string]
        ${TargetName},

        [switch]
        ${PassThru}
    )
    end {
        throw '{0}: StubNotImplemented' -f $MyInvocation.MyCommand
    }
}

