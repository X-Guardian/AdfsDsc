<#PSScriptInfo
.VERSION 1.0.0
.GUID 7201dbbb-c6df-4f29-8adb-b0f04cd209f4
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
        This configuration will add the claim description named Role for a custom claim that has the specified claim type.
#>

Configuration AdfsClaimDescription_Config
{
    Import-DscResource -ModuleName AdfsDsc

    Node localhost
    {
        AdfsClaimDescription ClaimDescription
        {
            Name       = 'Role'
            ClaimType  = "https://contoso.com/role"
            IsAccepted = $true
            IsOffered  = $true
            IsRequired = $false
            Notes      = 'The role of the Contoso user'
            ShortName  = 'contosorole'
        }
    }
}
