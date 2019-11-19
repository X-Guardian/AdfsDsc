<#PSScriptInfo
.VERSION 1.0.0
.GUID a7b4beac-7e2d-4a6e-b4ce-2fadef7d7f24
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
        This configuration will add a relying party trust with access control policy parameters in Active Directory
        Federation Services (AD FS).
#>

Configuration AdfsRelyingPArtyTrust_AccessControlPolicyParameters_Config
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
            WSFedEndpoint                 = 'https://webapp1.fabrikam.com'
            Identifier                    = 'https://webapp1.fabrikam.com'
            AccessControlPolicyName       = 'Permit specific group'
            AccessControlPolicyParameters = MSFT_AdfsAccessControlPolicyParameters
            {
                GroupParameter = @(
                    'CONTOSO\AppGroup1 Users'
                    'CONTOSO\AppGroup1 Admins'
                )
            }
        }
    }
}
