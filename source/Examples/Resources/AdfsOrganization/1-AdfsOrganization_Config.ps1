<#PSScriptInfo
.VERSION 1.0.0
.GUID fd4ce394-2584-4465-b074-9239210b143d
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
        This configuration will set organization information that is published in the federation metadata for the
        Federation Service.
#>

Configuration AdfsOrganization_Config
{
    Import-DscResource -ModuleName AdfsDsc

    Node localhost
    {
        AdfsOrganization Organization
        {
            FederationServiceName = 'sts.contoso.com'
            DisplayName           = 'Contoso Inc.'
            Name                  = 'Contoso'
            OrganizationUrl       = 'https://www.contoso.com/'
        }
    }
}
