<#PSScriptInfo
.VERSION 1.0.0
.GUID 7c6eb965-9e8a-44bc-aa93-937e015f583f
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

Configuration AdfsGlobalWebContent_Config
{
    param()

    Import-DscResource -ModuleName AdfsDsc

    Node localhost
    {
        AdfsGlobalWebContent ContosoGlobalWebContent
        {
            FederationServiceName = 'sts.contoso.com'
            Locale                = 'en-US'
            CompanyName           = 'Contoso'
            HelpDeskLink          = 'https://helpdesk.contoso.com'
        }
    }
}
