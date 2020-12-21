<#PSScriptInfo
.VERSION 1.0.0
.GUID 8eed62ec-04df-4588-83e4-e988fbcf9289
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
        This configuration will create an application group in Active Directory Federation Services (AD FS).
#>

Configuration AdfsApplicationGroup_Config
{
    Import-DscResource -ModuleName AdfsDsc

    Node localhost
    {
        AdfsApplicationGroup AppGroup1
        {
            Name        = 'AppGroup1'
            Description = "This is the AppGroup1 Description"
        }
    }
}
