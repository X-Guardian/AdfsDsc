<#PSScriptInfo
.VERSION 1.0.0
.GUID 1031dd4a-1c6d-403f-85f7-3d94c16da42e
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
        This configuration will set the Extranet Lockout properties on the ADFS service.
#>

Configuration AdfsProperties_Config
{
    param()

    Import-DscResource -ModuleName AdfsDsc

    Node localhost
    {
        AdfsProperties ContosoAdfsProperties
        {
            FederationServiceName    = 'sts.contoso.com'
            EnableExtranetLockout    =  $True
            ExtranetLockoutThreshold =  4
        }
    }
}
