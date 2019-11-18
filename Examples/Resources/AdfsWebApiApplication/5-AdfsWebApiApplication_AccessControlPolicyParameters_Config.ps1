<#PSScriptInfo
.VERSION 1.0.0
.GUID a80e9f9d-149d-4834-a7b8-08103159bab3
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
        This configuration will add a Web API application role with access control policy parameters to an application
        in Active Directory Federation Services (AD FS).
#>

Configuration AdfsWebApiApplication_AccessControlPolicyParameters_Config
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
