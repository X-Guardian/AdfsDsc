<#PSScriptInfo
.VERSION 1.0.0
.GUID 06035ace-52fa-4d92-b7f0-8a4780f60fbf
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
        This configuration will add a relying party trust with a Group Claims issuance transform rule in Active
        Directory Federation Services (AD FS).
#>

Configuration AdfsRelyingPartyTrust_EmitGroupClaims_IssuanceTransformRules_Config
{

    Import-DscResource -Module AdfsDsc

    Node localhost
    {
        AdfsRelyingPartyTrust WebApp1
        {
            Name                    = 'WebApp1'
            Enabled                 = $true
            Notes                   = 'This is a trust for https://webapp1.fabrikam.com'
            WSFedEndpoint           = 'https://webapp1.fabrikam.com'
            Identifier              = 'https://webapp1.fabrikam.com'
            AccessControlPolicyName = 'Permit Everyone'
            IssuanceTransformRules  = @(
                MSFT_AdfsIssuanceTransformRule
                {
                    TemplateName       = 'EmitGroupClaims'
                    Name               = 'App1 User Role Claim'
                    GroupName          = 'App1 Users'
                    OutgoingClaimType  = 'http://schemas.microsoft.com/ws/2008/06/identity/claims/role'
                    OutgoingClaimValue = 'User'
                }
            )
        }
    }
}
