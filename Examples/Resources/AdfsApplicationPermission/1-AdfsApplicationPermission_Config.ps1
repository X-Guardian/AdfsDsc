<#PSScriptInfo
.VERSION 1.0.0
.GUID b8aad972-f890-4e94-9be5-72b33c2f4403
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

Configuration AdfsApplicationPermission_Config
{
    Import-DscResource -ModuleName AdfsDsc

    Node localhost
    {
        AdfsApplicationPermission AppPermission1
        {
            ClientRoleIdentifier = 'c28bcb5d-ef46-47ed-b520-4f5ac605a082'
            ServerRoleIdentifier = 'c28bcb5d-ef46-47ed-b520-4f5ac605a082'
            Description          = "This is the AppPermission1 Description"
            ScopeNames           = 'openid'
        }
    }
}
