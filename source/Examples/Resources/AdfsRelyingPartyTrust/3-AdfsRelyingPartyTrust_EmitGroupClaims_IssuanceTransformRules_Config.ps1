<#PSScriptInfo
.VERSION 1.0.0
.GUID 7e6b225e-0f0e-404f-886b-3e9429e92810
.AUTHOR DSC Community
.COMPANYNAME DSC Community
.COPYRIGHT (c) DSC Community. All rights reserved.
.TAGS DSCConfiguration
.LICENSEURI https://github.com/X-Guardian/AdfsDsc/blob/master/LICENSE
.PROJECTURI https://github.com/X-Guardian/AdfsDsc
.ICONURI https://dsccommunity.org/images/DSC_Logo_300p.png
.EXTERNALMODULEDEPENDENCIES
.REQUIREDSCRIPTS
.EXTERNALSCRIPTDEPENDENCIES
.RELEASENOTES Updated author and copyright notice.
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
