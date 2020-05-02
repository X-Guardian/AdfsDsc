<#PSScriptInfo
.VERSION 1.0.0
.GUID fd56a198-3425-46eb-90d3-8b8e6f027051
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
        This configuration will add a native client application role to an application in Active Directory Federation
        Services (AD FS).
#>

Configuration AdfsNativeClientApplication_Config
{
    Import-DscResource -ModuleName AdfsDsc

    Node localhost
    {
        AdfsNativeClientApplication NativeApp1
        {
            Name                       = 'NativeApp1'
            ApplicationGroupIdentifier = 'AppGroup1'
            Identifier                 = 'e7bfb303-c5f6-4028-a360-b6293d41338c'
            RedirectUri                = 'https://nativeapp1.contoso.com'
            Description                = 'App1 Native App'
            LogoutUri                  = 'https://nativeapp1.contoso.com/logout'
        }
    }
}
