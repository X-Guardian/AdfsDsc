<#PSScriptInfo
.VERSION 1.0.0
.GUID 57f73d3c-6bea-4d9b-8333-09f72b4d5f99
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
        This configuration will add a relying party trust named Fabrikam for federation using the federation metadata
        document published at the specified URL.
#>

Configuration AdfsRelyingPartyTrust_Metadata_Config
{

    Import-DscResource -Module AdfsDsc

    Node localhost
    {
        AdfsRelyingPartyTrust OwaInternal
        {
            Name        = 'Fabrikam'
            MetadataURL = 'https://fabrikam.com/federationmetadata/2007-06/federationmetadata.xml'
        }
    }
}
