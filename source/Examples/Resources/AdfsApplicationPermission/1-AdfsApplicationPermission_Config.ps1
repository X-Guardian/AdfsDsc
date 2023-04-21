<#PSScriptInfo
.VERSION 1.0.0
.GUID b8aad972-f890-4e94-9be5-72b33c2f4403
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
        This configuration will grant an application permission in Active Directory Federation Services (AD FS).
#>

Configuration AdfsApplicationPermission_Config
{
    Import-DscResource -ModuleName AdfsDsc

    Node localhost
    {
        AdfsApplicationPermission AppPermission1
        {
            ClientRoleIdentifier = '168f3ee4-63fc-4723-a61a-6473f6cb515c'
            ServerRoleIdentifier = 'http://schemas.microsoft.com/ws/2009/12/identityserver/selfscope'
            Description          = "This is the AppPermission1 Description"
            ScopeNames           = 'openid'
        }
    }
}
