<#PSScriptInfo
.VERSION 1.0.0
.GUID b3183240-635d-4a00-8a5f-b70d4b936d68
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
        This configuration will the company name of the global web content for the invariant locale. If there is no
        logo, the sign-in page displays the company name Contoso.
#>

Configuration AdfsGlobalWebContent_CompanyName_Config
{
    param()

    Import-DscResource -ModuleName AdfsDsc

    Node localhost
    {
        AdfsGlobalWebContent ContosoGlobalWebContent
        {
            FederationServiceName = 'sts.contoso.com'
            Locale                = ''
            CompanyName           = 'Contoso'
        }
    }
}
