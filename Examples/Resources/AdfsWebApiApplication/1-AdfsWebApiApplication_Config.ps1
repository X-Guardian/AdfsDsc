<#PSScriptInfo
.VERSION 1.0.0
.GUID 124183ca-eddb-4ea8-8c9b-48e4000ccff8
.AUTHOR Microsoft Corporation
.COMPANYNAME Microsoft Corporation
.COPYRIGHT (c) Microsoft Corporation. All rights reserved.
.TAGS DSCConfiguration
.LICENSEURI https://github.com/X-Guardian/AdfsDsc/blob/master/LICENSE
.PROJECTURI https://github.com/X-Guardian/AdfsDsc
.ICONURI
.EXTERNALMODULEDEPENDENCIES
.REQUIREDSCRIPTS
.EXTERNALSCRIPTDEPENDENCIES
.RELEASENOTES First version.
.PRIVATEDATA 2016-Datacenter,2016-Datacenter-Server-Core
#>

#Requires -module AdfsDsc

<#
    .DESCRIPTION
        This configuration will ...
#>

$LdapClaimsTransformRule = @'
@RuleTemplate = "LdapClaims"
@RuleName = "LDAP Email Address"
c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname", Issuer == "AD AUTHORITY"]
 => issue(store = "Active Directory", types = ("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"), query = ";mail;{0}", param = c.Value);
'@

$EmitGroupClaimsTransformRule = @'
@RuleTemplate = "EmitGroupClaims"
@RuleName = "IDscan Users SRV EU-West-1"
c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/groupsid", Value == "S-1-5-21-2624039266-918686060-4041204886-1128", Issuer == "AD AUTHORITY"]
 => issue(Type = "http://schemas.microsoft.com/ws/2008/06/identity/claims/role", Value = "IDScan User", Issuer = c.Issuer, OriginalIssuer = c.OriginalIssuer, ValueType = c.ValueType);
'@

Configuration AdfsWebApiApplication_Config
{
    param()

    Import-DscResource -ModuleName AdfsDsc

    Node localhost
    {
        AdfsWebApiApplication WebApiApp1
        {
            Name                                 = 'AppGroup1 - Web API'
            ApplicationGroupIdentifier           = 'AppGroup1'
            Identifier                           = 'e7bfb303-c5f6-4028-a360-b6293d41338c'
            Description                          = 'App1 Web Api'
            AccessControlPolicyName              = 'Permit everyone'
            IssuanceTransformRules               = $ADEmailAddressTransformRule
            AllowedAuthenticationClassReferences = ''
            ClaimsProviderName                   = ''
            IssuanceAuthorizationRules           = ''
            DelegationAuthorizationRules         = ''
            ImpersonationAuthorizationRules      = ''
            AdditionalAuthenticationRules        = ''
            NotBeforeSkew                        = 5
            TokenLifetime                        = 90
            AlwaysRequireAuthentication          = $false
            AllowedClientTypes                   = 'Public'
            IssueOAuthRefreshTokensTo            = 'AllDevices'
            RefreshTokenProtectionEnabled        = $true
            RequestMFAFromClaimsProviders        = $true
        }
    }
}
