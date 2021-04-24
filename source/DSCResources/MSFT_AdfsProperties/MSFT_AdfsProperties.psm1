<#
    .SYNOPSIS
        DSC module for the ADFS Properties resource

    .DESCRIPTION
        The AdfsProperties DSC resource manages all the associated properties for the Active Directory Federation
        Services (AD FS) service.

    .PARAMETER FederationServiceName
        Key - String
        Specifies the DNS name of the federation service.

    .PARAMETER AdditionalErrorPageInfo
        Write - String
        Allowed values: Private, Detailed, None
        Specifies the level of additional information that is displayed on ADFS error pages. This property is only
        supported in Windows Server 2019 and above.


    .PARAMETER AuthenticationContextOrder
        Write - String
        Specifies an array of authentication contexts, in order of relative strength. Specify each authentication
        context as a URI.

    .PARAMETER AcceptableIdentifiers
        Write - String
        Specifies an array of identifiers that are acceptable names for the Federation Service when it checks the
        audience for claims that it receives from another claims provider.

    .PARAMETER ArtifactDbConnection
        Write - String
        Specifies the connection string to use for the database that maintains the artifacts that the artifact
        resolution service uses.

    .PARAMETER AuditLevel
        Write - String
        Allowed values: None, Basic, Verbose
        Specifies an array of audit levels.

    .PARAMETER AutoCertificateRollover
        Write - Boolean
        Indicates whether the system manages certificates for the administrator and generates new certificates before
        the expiration date of current certificates.

    .PARAMETER CertificateCriticalThreshold
        Write - Sint32
        Specifies the period of time, in days, prior to the expiration of a current primary signing or decryption
        certificate. When a certificate reaches this threshold, the Federation Service initiates the automatic
        certificate rollover service, generates a new certificate, and promotes it as the primary certificate. This
        rollover process occurs even if the critical threshold interval does not provide sufficient time for partners
        to replicate the new metadata. Specify a short period of time that is used only in extreme conditions when the
        Federation Service has not been able to generate a new certificate in advance.

    .PARAMETER CertificateDuration
        Write - Sint32
        Specifies the period of time, in days, that any certificates that the Federation Service generates remain
        valid.

    .PARAMETER CertificateGenerationThreshold
        Write - Sint32
        Specifies the period of time, in days, that any certificates that the Federation Service generates remain
        valid. The default value is 365 days.

    .PARAMETER CertificatePromotionThreshold
        Write - Sint32
        Specifies the period of time, in days, during which a newly generated certificate remains a secondary
        certificate before being promoted as the primary certificate. The default value is 5 days.

    .PARAMETER CertificateRolloverInterval
        Write - Sint32
        Specifies the certificate rollover interval, in minutes. This value determines the frequency at which the
        Federation Service initiates the rollover service by polling to check whether new certificates need to be
        generated. The default value is 720 minutes.

    .PARAMETER CertificateThresholdMultiplier
        Write - Sint32
        Specifies the certificate threshold multiplier. By default, this parameter uses the number of minutes in a day
        (1440) as a multiplier. Change this value only if you want to use a more finely detailed measure of time, such
        as less than a single day, for calculating the time periods for other certificate threshold parameters.

    .PARAMETER EnableOAuthDeviceFlow
        Write - Boolean
        Enabled the OAuth Device Flow.

    .PARAMETER HostName
        Write - String
        Specifies the network addressable host name of the Federation Service.

    .PARAMETER HttpPort
        Write - Sint32
        Specifies the HTTP port for the server.

    .PARAMETER HttpsPort
        Write - Sint32
        Specifies the HTTPS port for the server.

    .PARAMETER IntranetUseLocalClaimsProvider
        Write - Boolean
        Indicates whether all web based requests from the intranet default to the default Active Directory claims
        provider. Use this parameter only when there is more than one claims provider trust in AD FS and you want all
        user access from the intranet to use the default Active Directory for authentication.

    .PARAMETER TlsClientPort
        Write - Sint32
        Specifies the port number where AD FS listens for user certificate authentication requests. Use this only when
        user certificate authentication is used in AD FS.

    .PARAMETER Identifier
        Write - String
        Specifies the URI that uniquely identifies the Federation Service.

    .PARAMETER LogLevel
        Write - String
        Allowed values: Errors, FailureAudits, Information, Verbose, SuccessAudits, Warnings, None
        Specifies an array of log detail. The array defines which types of events to record.

    .PARAMETER MonitoringInterval
        Write - Sint32
        Specifies the frequency, in minutes, with which the Federation Service monitors the federation metadata of
        relying parties and claims providers that are enabled for federation metadata monitoring.

    .PARAMETER NetTcpPort
        Write - Sint32
        Specifies the TCP port number for the server.

    .PARAMETER NtlmOnlySupportedClientAtProxy
        Write - Boolean
        Indicates whether to enable support for NTLM-based authentication in situations where the active federation
        server proxy does not support Negotiate method of authentication. This setting only affects the Windows
        transport endpoint.

    .PARAMETER PreventTokenReplays
        Write - Boolean
        Indicates whether the Federation Service prevents the replay of security tokens.

    .PARAMETER ExtendedProtectionTokenCheck
        Write - String
        Allowed values: Require, Allow, None
        Specifies the level of extended protection for authentication supported by the federation server. Extended
        Protection for Authentication helps protect against man-in-the-middle (MITM) attacks, in which an attacker
        intercepts a client's credentials and forwards them to a server. Protection against such attacks is made
        possible through a Channel Binding Token (CBT) which can be either required, allowed or not required by the
        server when establishing communications with clients.

    .PARAMETER ProxyTrustTokenLifetime
        Write - Sint32
        Specifies the valid token lifetime, in minutes, for proxy trust tokens. This value is used by the federation
        server proxy to authenticate with its associated federation server.

    .PARAMETER ReplayCacheExpirationInterval
        Write - Sint32
        Specifies the cache duration, in minutes, for token replay detection. This value determines the lifetime for
        tokens in the replay cache. When the age of a cached token exceeds this interval, the Federation Service
        determines the token has expired and does not allow replay of it.

    .PARAMETER SignedSamlRequestsRequired
        Write - Boolean
        Indicates whether the Federation Service requires signed SAML protocol requests from the relying party. If you
        specify a value of $True, the Federation Service rejects unsigned SAML protocol requests.

    .PARAMETER SamlMessageDeliveryWindow
        Write - Sint32
        Specifies the duration, in minutes, for which the Security Assertion Markup Language (SAML) messages sent by
        the Federation Service are considered valid.

    .PARAMETER SignSamlAuthnRequests
        Write - Boolean
        Indicates whether the Federation Service signs SAML protocol authentication requests to claims providers.

    .PARAMETER SsoLifetime
        Write - Sint32
        Specifies the duration, in minutes, of the single sign-on (SSO) experience for Web browser clients.

    .PARAMETER PersistentSsoLifetimeMins
        Write - Sint32
        Specifies the duration, in minutes, of the persistent SSO experience.

    .PARAMETER KmsiLifetimeMins
        Write - Sint32
        Specifies the lifetime of the sign on status for KMSI.

    .PARAMETER EnablePersistentSso
        Write - Boolean
        Indicates whether to store the SSO token in persistent cookies for devices joined to a workplace.

    .PARAMETER PersistentSsoCutoffTime
        Write - DateTime
        Specifies the earliest issue time of accepted persistent single sign-on (SSO) tokens and OAuth refresh tokens.
        Persistent SSO tokens or OAuth refresh tokens issued before this time will be rejected. Use this only to reject
        all prior SSO state across all users and force users to provide fresh credentials.

    .PARAMETER EnableKmsi
        Write - Boolean
        Indicates whether to enable the Keep Me Signed In (KMSI) option for form-based authentication. KMSI is limited
        to providing only 24 hours of SSO. Note that a workplace joined device gets 7 days of SSO by default and does
        not need this option enabled.

    .PARAMETER WIASupportedUserAgents
        Write - String
        Specifies an array of acceptable user agents that support seamless sign-in with Windows Integrated
        Authentication. If AD FS receives a token request and policy selects Windows Integrated Authentication, AD FS
        uses this list to determine if it needs to fall back to forms-based authentication. When the user agent for the
        incoming request is not in this list, AD FS falls back to forms-based authentication.

    .PARAMETER BrowserSsoSupportedUserAgents
        Write - String
        Specifies an array of user agents that are supported for browser SSO.

    .PARAMETER BrowserSsoEnabled
        Write - Boolean
        Indicates that browser single sign-on (SSO) is enabled.

    .PARAMETER LoopDetectionTimeIntervalInSeconds
        Write - Sint32
        Specifies the time interval in seconds for AD FS to track multiple token requests that are occurring and being
        rejected by the relying party causing a redirect back to AD FS for a new token request. Use in conjunction with
        the LoopDetectionMaximumTokensIssuedInInterval parameter.

    .PARAMETER LoopDetectionMaximumTokensIssuedInInterval
        Write - Sint32
        Specifies the maximum number of tokens that can be issued within the time period specified by the
        LoopDetectionTimeIntervalInSeconds parameter before AD FS will reject the request and present an error to the
        user. Use in conjunction with the LoopDetectionMaximumTokensIssuedInInterval parameter.

    .PARAMETER EnableLoopDetection
        Write - Boolean
        Indicates whether to enable loop detection. Loops occur when a relying party continuously rejects a valid
        security token and redirects back to AD FS. The cycle terminates after 6 loops have been detected.

    .PARAMETER ExtranetLockoutMode
        Write - String
        Allowed values: ADFSSmartLockoutLogOnly, ADFSSmartLockoutEnforce
        Specifies the maximum number of bad password attempts permitted against the directory before the account is
        throttled when accessing applications from the extranet for familiar locations. If you use Active Directory
        Domain Services account lockout policies, it is strongly recommended that you set this threshold to a value
        that is less than the threshold in AD DS to avoid lockout of the user inside and outside the network. This
        property is only supported in Windows Server 2019 and above.

    .PARAMETER ExtranetLockoutThreshold
        Write - Sint32
        Specifies the maximum number of bad password attempts permitted against the directory before the account is
        throttled when accessing applications from the extranet for unfamiliar locations. If you use Active Directory
        Domain Services account lockout policies, it is strongly recommended that you set this threshold to a value
        that is less than the threshold in AD DS to avoid lockout of the user inside and outside the network.

    .PARAMETER ExtranetLockoutThresholdFamiliarLocation
        Write - Sint32
        Specifies the maximum number of bad password attempts permitted against the directory before the account is
        throttled when accessing applications from the extranet for familiar locations. If you use Active Directory
        Domain Services account lockout policies, it is strongly recommended that you set this threshold to a value
        that is less than the threshold in AD DS to avoid lockout of the user inside and outside the network. This
        property is only supported in Windows Server 2019 and above.

    .PARAMETER EnableExtranetLockout
        Write - Boolean
        Indicates whether to enable the lockout algorithm for extranet. When enabled, AD FS checks attributes in Active
        Directory for the user before validating the credential. If the user is determined to be in lockout state, AD
        FS will deny the request to the user when accessing from the extranet, to prevent random login attempts from
        the extranet. Intranet access will continue to be validated against Active Directory.

    .PARAMETER ExtranetObservationWindow
        Write - String
        Specifies the timespan of the lockout observation window. AD FS will reset a throttled state of an account when
        more than one observation window has expired since the last bad password attempt, as reported by Active
        Directory Domain Services. It is also possible that the last bad password field in AD DS is cleared by AD DS
        based on its own observation windows. In this case, AD FS will allow the request to be passed onto AD DS for
        validation.

    .PARAMETER ExtranetLockoutRequirePDC
        Write - Boolean
        Specifies whether extranet lockout requires a primary domain controller (PDC).

    .PARAMETER SendClientRequestIdAsQueryStringParameter
        Write - Boolean
        Indicates whether the client request id, or activity id, is sent as a query string on any redirect from AD FS
        that is sent to itself. This enables all servers in AD FS to use the same client request id when logging any
        messages in eventlogs, traces and audits. As a result, it is easier to troubleshoot a single request across
        multiple AD FS servers in the farm. The default value is $True.

    .PARAMETER GlobalRelyingPartyClaimsIssuancePolicy
        Write - String
        Specifies a global relying party claims issuance policy.

    .PARAMETER EnableLocalAuthenticationTypes
        Write - Boolean
        Indicates that local authentication types are enabled.

    .PARAMETER EnableRelayStateForIdpInitiatedSignOn
        Write - Boolean
        Indicates that relay state for issuing distribution point (IDP) initiated sign-on is enabled.

    .PARAMETER DelegateServiceAdministration
        Write - String
        Specifies the delegate service administration.

    .PARAMETER AllowSystemServiceAdministration
        Write - Boolean
        Indicates that system service administration is allowed.

    .PARAMETER AllowLocalAdminsServiceAdministration
        Write - Boolean
        Indicates that local administrator service administration is allowed.

    .PARAMETER DeviceUsageWindowInDays
        Write - Sint32
        Specifies the length of the device usage window in days.

    .PARAMETER EnableIdPInitiatedSignonPage
        Write - Boolean
        Specifies whether to enable the EnableIdPInitiatedSignonPage property.

    .PARAMETER IgnoreTokenBinding
        Write - Boolean
        Specifies whether to ignore token binding.

    .PARAMETER IdTokenIssuer
        Write - String
        Specifies the URI of the token issuer.
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

        Name                     | Module
        -------------------------|----------------
        Get-AdfsProperties       | Adfs
        Assert-Module            | AdfsDsc.Common
        Assert-AdfsService       | AdfsDsc.Common
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

    # Check of the ADFS PowerShell module is installed
    Assert-Module -ModuleName $script:psModuleName

    # Check if the ADFS Service is present and running
    Assert-AdfsService @commonParms

    try
    {
        $targetResource = Get-AdfsProperties
    }
    catch
    {
        $errorMessage = $script:localizedData.GettingResourceErrorMessage -f $FederationServiceName
        New-InvalidOperationException -Message $errorMessage -Error $_
    }

    $returnValue = @{
        FederationServiceName = $FederationServiceName
    }

    $resourceProperties = @{
        AdditionalErrorPageInfo                    = 'AdditionalErrorPageInfo'
        AuthenticationContextOrder                 = 'AuthenticationContextOrder'
        AcceptableIdentifiers                      = 'AcceptableIdentifiers'
        ArtifactDbConnection                       = 'ArtifactDbConnection'
        AuditLevel                                 = 'AuditLevel'
        AutoCertificateRollover                    = 'AutoCertificateRollover'
        CertificateCriticalThreshold               = 'CertificateCriticalThreshold'
        CertificateDuration                        = 'CertificateDuration'
        CertificateGenerationThreshold             = 'CertificateGenerationThreshold'
        CertificatePromotionThreshold              = 'CertificatePromotionThreshold'
        CertificateRolloverInterval                = 'CertificateRolloverInterval'
        CertificateThresholdMultiplier             = 'CertificateThresholdMultiplier'
        EnableOAuthDeviceFlow                      = 'EnableOAuthDeviceFlow'
        HostName                                   = 'HostName'
        HttpPort                                   = 'HttpPort'
        HttpsPort                                  = 'HttpsPort'
        IntranetUseLocalClaimsProvider             = 'IntranetUseLocalClaimsProvider'
        TlsClientPort                              = 'TlsClientPort'
        Identifier                                 = 'Identifier'
        LogLevel                                   = 'LogLevel'
        MonitoringInterval                         = 'MonitoringInterval'
        NetTcpPort                                 = 'NetTcpPort'
        NtlmOnlySupportedClientAtProxy             = 'NtlmOnlySupportedClientAtProxy'
        PreventTokenReplays                        = 'PreventTokenReplays'
        ExtendedProtectionTokenCheck               = 'ExtendedProtectionTokenCheck'
        ProxyTrustTokenLifetime                    = 'ProxyTrustTokenLifetime'
        ReplayCacheExpirationInterval              = 'ReplayCacheExpirationInterval'
        SignedSamlRequestsRequired                 = 'SignedSamlRequestsRequired'
        SamlMessageDeliveryWindow                  = 'SamlMessageDeliveryWindow'
        SignSamlAuthnRequests                      = 'SignSamlAuthnRequests'
        SsoLifetime                                = 'SsoLifetime'
        PersistentSsoLifetimeMins                  = 'PersistentSsoLifetimeMins'
        KmsiLifetimeMins                           = 'KmsiLifetimeMins'
        EnablePersistentSso                        = 'PersistentSsoEnabled'
        PersistentSsoCutoffTime                    = 'PersistentSsoCutoffTime'
        EnableKmsi                                 = 'KmsiEnabled'
        WIASupportedUserAgents                     = 'WIASupportedUserAgents'
        BrowserSsoSupportedUserAgents              = 'BrowserSsoSupportedUserAgents'
        BrowserSsoEnabled                          = 'BrowserSsoEnabled'
        LoopDetectionTimeIntervalInSeconds         = 'LoopDetectionTimeIntervalInSeconds'
        LoopDetectionMaximumTokensIssuedInInterval = 'LoopDetectionMaximumTokensIssuedInInterval'
        EnableLoopDetection                        = 'LoopDetectionEnabled'
        ExtranetLockoutThreshold                   = 'ExtranetLockoutThreshold'
        ExtranetLockoutThresholdFamiliarLocation   = 'ExtranetLockoutThresholdFamiliarLocation'
        EnableExtranetLockout                      = 'ExtranetLockoutEnabled'
        ExtranetLockoutMode                        = 'ExtranetLockoutMode'
        ExtranetObservationWindow                  = 'ExtranetObservationWindow'
        ExtranetLockoutRequirePDC                  = 'ExtranetLockoutRequirePDC'
        SendClientRequestIdAsQueryStringParameter  = 'SendClientRequestIdAsQueryStringParameter'
        GlobalRelyingPartyClaimsIssuancePolicy     = 'GlobalRelyingPartyClaimsIssuancePolicy'
        EnableLocalAuthenticationTypes             = 'LocalAuthenticationTypesEnabled'
        EnableRelayStateForIdpInitiatedSignOn      = 'RelayStateForIdpInitiatedSignOnEnabled'
        DelegateServiceAdministration              = 'DelegateServiceAdministration'
        AllowSystemServiceAdministration           = 'AllowSystemServiceAdministration'
        AllowLocalAdminsServiceAdministration      = 'AllowLocalAdminsServiceAdministration'
        DeviceUsageWindowInDays                    = 'DeviceUsageWindowInDays'
        EnableIdPInitiatedSignonPage               = 'EnableIdPInitiatedSignonPage'
        IgnoreTokenBinding                         = 'IgnoreTokenBinding'
        IdTokenIssuer                              = 'IdTokenIssuer'
    }

    foreach ($property in $resourceProperties.Keys)
    {
        if ($targetResource.PSObject.Properties.Name -contains $resourceProperties[$property] )
        {
            $returnValue += @{
                $property = $targetResource.$($resourceProperties[$property])
            }
        }
        else
        {
            $returnValue += @{
                $property = $null
            }
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

        Name                          | Module
        ------------------------------|----------------
        Set-AdfsProperties            | Adfs
        Compare-ResourcePropertyState | AdfsDsc.Common
    #>

    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $FederationServiceName,

        [Parameter()]
        [System.String[]]
        $AcceptableIdentifiers,

        [Parameter()]
        [System.String]
        [ValidateSet('Private', 'Detailed', 'None')]
        $AdditionalErrorPageInfo,

        [Parameter()]
        [System.String]
        $ArtifactDbConnection,

        [Parameter()]
        [ValidateSet('None', 'Basic', 'Verbose')]
        [System.String[]]
        $AuditLevel,

        [Parameter()]
        [System.String[]]
        $AuthenticationContextOrder,

        [Parameter()]
        [System.Boolean]
        $AutoCertificateRollover,

        [Parameter()]
        [System.Int32]
        $CertificateCriticalThreshold,

        [Parameter()]
        [System.Int32]
        $CertificateDuration,

        [Parameter()]
        [System.Int32]
        $CertificateGenerationThreshold,

        [Parameter()]
        [System.Int32]
        $CertificatePromotionThreshold,

        [Parameter()]
        [System.Int32]
        $CertificateRolloverInterval,

        [Parameter()]
        [System.Int32]
        $CertificateThresholdMultiplier,

        [Parameter()]
        [System.Boolean]
        $EnableOAuthDeviceFlow,

        [Parameter()]
        [System.String]
        $HostName,

        [Parameter()]
        [System.Int32]
        $HttpPort,

        [Parameter()]
        [System.Int32]
        $HttpsPort,

        [Parameter()]
        [System.Boolean]
        $IntranetUseLocalClaimsProvider,

        [Parameter()]
        [System.Int32]
        $TlsClientPort,

        [Parameter()]
        [System.String]
        $Identifier,

        [Parameter()]
        [ValidateSet('Errors', 'FailureAudits', 'Information', 'Verbose', 'SuccessAudits', 'Warnings', 'None')]
        [System.String[]]
        $LogLevel,

        [Parameter()]
        [System.Int32]
        $MonitoringInterval,

        [Parameter()]
        [System.Int32]
        $NetTcpPort,

        [Parameter()]
        [System.Boolean]
        $NtlmOnlySupportedClientAtProxy,

        [Parameter()]
        [System.Boolean]
        $PreventTokenReplays,

        [Parameter()]
        [ValidateSet('Require', 'Allow', 'None')]
        [System.String]
        $ExtendedProtectionTokenCheck,

        [Parameter()]
        [System.Int32]
        $ProxyTrustTokenLifetime,

        [Parameter()]
        [System.Int32]
        $ReplayCacheExpirationInterval,

        [Parameter()]
        [System.Boolean]
        $SignedSamlRequestsRequired,

        [Parameter()]
        [System.Int32]
        $SamlMessageDeliveryWindow,

        [Parameter()]
        [System.Boolean]
        $SignSamlAuthnRequests,

        [Parameter()]
        [System.Int32]
        $SsoLifetime,

        [Parameter()]
        [System.Int32]
        $PersistentSsoLifetimeMins,

        [Parameter()]
        [System.Int32]
        $KmsiLifetimeMins,

        [Parameter()]
        [System.Boolean]
        $EnablePersistentSso,

        [Parameter()]
        [System.DateTime]
        $PersistentSsoCutoffTime,

        [Parameter()]
        [System.Boolean]
        $EnableKmsi,

        [Parameter()]
        [System.String[]]
        $WIASupportedUserAgents,

        [Parameter()]
        [System.String[]]
        $BrowserSsoSupportedUserAgents,

        [Parameter()]
        [System.Boolean]
        $BrowserSsoEnabled,

        [Parameter()]
        [System.Int32]
        $LoopDetectionTimeIntervalInSeconds,

        [Parameter()]
        [System.Int32]
        $LoopDetectionMaximumTokensIssuedInInterval,

        [Parameter()]
        [System.Boolean]
        $EnableLoopDetection,

        [Parameter()]
        [System.String]
        [ValidateSet('ADFSSmartLockoutLogOnly', 'ADFSSmartLockoutEnforce')]
        $ExtranetLockoutMode,

        [Parameter()]
        [System.Int32]
        $ExtranetLockoutThreshold,

        [Parameter()]
        [System.Int32]
        $ExtranetLockoutThresholdFamiliarLocation,

        [Parameter()]
        [System.Boolean]
        $EnableExtranetLockout,

        [Parameter()]
        [System.String]
        $ExtranetObservationWindow,

        [Parameter()]
        [System.Boolean]
        $ExtranetLockoutRequirePDC,

        [Parameter()]
        [System.Boolean]
        $SendClientRequestIdAsQueryStringParameter,

        [Parameter()]
        [System.String]
        $GlobalRelyingPartyClaimsIssuancePolicy,

        [Parameter()]
        [System.Boolean]
        $EnableLocalAuthenticationTypes,

        [Parameter()]
        [System.Boolean]
        $EnableRelayStateForIdpInitiatedSignOn,

        [Parameter()]
        [System.String]
        $DelegateServiceAdministration,

        [Parameter()]
        [System.Boolean]
        $AllowSystemServiceAdministration,

        [Parameter()]
        [System.Boolean]
        $AllowLocalAdminsServiceAdministration,

        [Parameter()]
        [System.Int32]
        $DeviceUsageWindowInDays,

        [Parameter()]
        [System.Boolean]
        $EnableIdPInitiatedSignonPage,

        [Parameter()]
        [System.Boolean]
        $IgnoreTokenBinding,

        [Parameter()]
        [System.String]
        $IdTokenIssuer
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

    $getTargetResourceParms = @{
        FederationServiceName = $FederationServiceName
    }
    $targetResource = Get-TargetResource @getTargetResourceParms

    $setAdfsPropertiesParameters = (Get-Command -Name 'Set-AdfsProperties').Parameters.Keys
    foreach ($parameter in $parameters.keys)
    {
        if ($setAdfsPropertiesParameters -notcontains $parameter)
        {
            $errorMessage = ($script:localizedData.UnsupportedParameterErrorMessage -f
                (Get-CimInstance -Class Win32_OperatingSystem).Caption)
            New-InvalidArgumentException -Message $errorMessage -ArgumentName $parameter
        }
    }

    $propertiesNotInDesiredState = (
        Compare-ResourcePropertyState -CurrentValues $targetResource -DesiredValues $parameters `
            @commonParms | Where-Object -Property InDesiredState -eq $false)

    $setParameters = @{ }
    foreach ($property in $propertiesNotInDesiredState)
    {
        Write-Verbose -Message ($script:localizedData.SettingResourcePropertyMessage -f
            $FederationServiceName, $property.ParameterName, ($property.Expected -join ', '))

        $setParameters.add($property.ParameterName, $property.Expected)
    }

    try
    {
        Set-AdfsProperties @setParameters
    }
    catch
    {
        $errorMessage = $script:localizedData.SettingResourceErrorMessage -f $FederationServiceName
        New-InvalidOperationException -Message $errorMessage -Error $_
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
        $AcceptableIdentifiers,

        [Parameter()]
        [System.String]
        [ValidateSet('Private', 'Detailed', 'None')]
        $AdditionalErrorPageInfo,

        [Parameter()]
        [System.String]
        $ArtifactDbConnection,

        [Parameter()]
        [ValidateSet('None', 'Basic', 'Verbose')]
        [System.String[]]
        $AuditLevel,

        [Parameter()]
        [System.String[]]
        $AuthenticationContextOrder,

        [Parameter()]
        [System.Boolean]
        $AutoCertificateRollover,

        [Parameter()]
        [System.Int32]
        $CertificateCriticalThreshold,

        [Parameter()]
        [System.Int32]
        $CertificateDuration,

        [Parameter()]
        [System.Int32]
        $CertificateGenerationThreshold,

        [Parameter()]
        [System.Int32]
        $CertificatePromotionThreshold,

        [Parameter()]
        [System.Int32]
        $CertificateRolloverInterval,

        [Parameter()]
        [System.Int32]
        $CertificateThresholdMultiplier,

        [Parameter()]
        [System.Boolean]
        $EnableOAuthDeviceFlow,

        [Parameter()]
        [System.String]
        $HostName,

        [Parameter()]
        [System.Int32]
        $HttpPort,

        [Parameter()]
        [System.Int32]
        $HttpsPort,

        [Parameter()]
        [System.Boolean]
        $IntranetUseLocalClaimsProvider,

        [Parameter()]
        [System.Int32]
        $TlsClientPort,

        [Parameter()]
        [System.String]
        $Identifier,

        [Parameter()]
        [ValidateSet('Errors', 'FailureAudits', 'Information', 'Verbose', 'SuccessAudits', 'Warnings', 'None')]
        [System.String[]]
        $LogLevel,

        [Parameter()]
        [System.Int32]
        $MonitoringInterval,

        [Parameter()]
        [System.Int32]
        $NetTcpPort,

        [Parameter()]
        [System.Boolean]
        $NtlmOnlySupportedClientAtProxy,

        [Parameter()]
        [System.Boolean]
        $PreventTokenReplays,

        [Parameter()]
        [ValidateSet('Require', 'Allow', 'None')]
        [System.String]
        $ExtendedProtectionTokenCheck,

        [Parameter()]
        [System.Int32]
        $ProxyTrustTokenLifetime,

        [Parameter()]
        [System.Int32]
        $ReplayCacheExpirationInterval,

        [Parameter()]
        [System.Boolean]
        $SignedSamlRequestsRequired,

        [Parameter()]
        [System.Int32]
        $SamlMessageDeliveryWindow,

        [Parameter()]
        [System.Boolean]
        $SignSamlAuthnRequests,

        [Parameter()]
        [System.Int32]
        $SsoLifetime,

        [Parameter()]
        [System.Int32]
        $PersistentSsoLifetimeMins,

        [Parameter()]
        [System.Int32]
        $KmsiLifetimeMins,

        [Parameter()]
        [System.Boolean]
        $EnablePersistentSso,

        [Parameter()]
        [System.DateTime]
        $PersistentSsoCutoffTime,

        [Parameter()]
        [System.Boolean]
        $EnableKmsi,

        [Parameter()]
        [System.String[]]
        $WIASupportedUserAgents,

        [Parameter()]
        [System.String[]]
        $BrowserSsoSupportedUserAgents,

        [Parameter()]
        [System.Boolean]
        $BrowserSsoEnabled,

        [Parameter()]
        [System.Int32]
        $LoopDetectionTimeIntervalInSeconds,

        [Parameter()]
        [System.Int32]
        $LoopDetectionMaximumTokensIssuedInInterval,

        [Parameter()]
        [System.Boolean]
        $EnableLoopDetection,

        [Parameter()]
        [System.String]
        [ValidateSet('ADFSSmartLockoutLogOnly', 'ADFSSmartLockoutEnforce')]
        $ExtranetLockoutMode,

        [Parameter()]
        [System.Int32]
        $ExtranetLockoutThreshold,

        [Parameter()]
        [System.Int32]
        $ExtranetLockoutThresholdFamiliarLocation,

        [Parameter()]
        [System.Boolean]
        $EnableExtranetLockout,

        [Parameter()]
        [System.String]
        $ExtranetObservationWindow,

        [Parameter()]
        [System.Boolean]
        $ExtranetLockoutRequirePDC,

        [Parameter()]
        [System.Boolean]
        $SendClientRequestIdAsQueryStringParameter,

        [Parameter()]
        [System.String]
        $GlobalRelyingPartyClaimsIssuancePolicy,

        [Parameter()]
        [System.Boolean]
        $EnableLocalAuthenticationTypes,

        [Parameter()]
        [System.Boolean]
        $EnableRelayStateForIdpInitiatedSignOn,

        [Parameter()]
        [System.String]
        $DelegateServiceAdministration,

        [Parameter()]
        [System.Boolean]
        $AllowSystemServiceAdministration,

        [Parameter()]
        [System.Boolean]
        $AllowLocalAdminsServiceAdministration,

        [Parameter()]
        [System.Int32]
        $DeviceUsageWindowInDays,

        [Parameter()]
        [System.Boolean]
        $EnableIdPInitiatedSignonPage,

        [Parameter()]
        [System.Boolean]
        $IgnoreTokenBinding,

        [Parameter()]
        [System.String]
        $IdTokenIssuer
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
