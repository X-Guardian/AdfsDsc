<#PSScriptInfo
.VERSION 1.0.0
.GUID fd4ce394-2584-4465-b074-9239210b143d
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
