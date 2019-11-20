<#PSScriptInfo
.VERSION 1.0.0
.GUID 3f13bb31-2cd7-4a3d-b11e-d56efaf213f2
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
        This configuration will add a relying party trust with a SAML Endpoint in Active Directory Federation
        Services (AD FS).
#>

Configuration AdfsRelyingPartyTrust_SamlEndpoint_Config
{
    param()

    Import-DscResource -ModuleName AdfsDsc

    Node localhost
    {
        AdfsRelyingPartyTrust WebApp1
        {
            Name                          = 'WebApp1'
            Enabled                       = $true
            Notes                         = 'This is a trust for https://webapp1.fabrikam.com'
            Identifier                    = 'https://webapp1.fabrikam.com'
            AccessControlPolicyName       = 'Permit everyone'
            SamlEndpoint = @(
                MSFT_AdfsSamlEndpoint
                {
                    Binding     = 'POST'
                    Index       = 0
                    IsDefault   = $false
                    Protocol    = 'SAMLAssertionConsumer'
                    Uri         = 'https://webapp1.fabrikam.com'
                }
            )
        }
    }
}
