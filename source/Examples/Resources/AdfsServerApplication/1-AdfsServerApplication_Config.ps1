<#PSScriptInfo
.VERSION 1.0.0
.GUID 2bac0216-bfc3-4e49-8ded-08d748238b32
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
        This configuration will add a server application to an application in Active Directory Federation
        Services (AD FS).
#>

Configuration AdfsServerApplication_Config
{
    Import-DscResource -ModuleName AdfsDsc

    Node localhost
    {
        AdfsServerApplication ServerApp1
        {
            Name                       = 'ServerApp1'
            ApplicationGroupIdentifier = 'AppGroup1'
            Identifier                 = '6de768af-c656-424d-b79c-5024944c3b67'
            RedirectUri                = 'https://serverapp1.contoso.com'
            Description                = 'App1 Server App'
            ADUserPrincipalName        = 'CONTOSO\Svc.App1'
            LogoutUri                  = 'https://serverapp1.contoso.com/logout'
        }
    }
}
