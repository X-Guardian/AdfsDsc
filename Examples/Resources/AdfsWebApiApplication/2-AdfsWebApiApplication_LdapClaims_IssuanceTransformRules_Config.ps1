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
        This configuration will add a Web API application role to an application in Active Directory Federation
        Services (AD FS).
#>

Configuration AdfsWebApiApplication_LdapClaims_IssuanceTransformRules_Config
{
    param()

    Import-DscResource -ModuleName AdfsDsc

    Node localhost
    {
        AdfsWebApiApplication WebApiApp1
        {
            Name                          = 'AppGroup1 - Web API'
            ApplicationGroupIdentifier    = 'AppGroup1'
            Identifier                    = 'e7bfb303-c5f6-4028-a360-b6293d41338c'
            Description                   = 'App1 Web Api'
            AccessControlPolicyName       = 'Permit everyone'
            AlwaysRequireAuthentication   = $false
            AllowedClientTypes            = 'Public', 'Confidential'
            IssueOAuthRefreshTokensTo     = 'AllDevices'
            NotBeforeSkew                 = 0
            RefreshTokenProtectionEnabled = $true
            RequestMFAFromClaimsProviders = $false
            TokenLifetime                 = 0
            IssuanceTransformRules        = @(
                MSFT_AdfsIssuanceTransformRule
                {
                    TemplateName   = 'LdapClaims'
                    Name           = 'App1 Ldap Claims'
                    AttributeStore = 'Active Directory'
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
                }
            )
        }
    }
}
