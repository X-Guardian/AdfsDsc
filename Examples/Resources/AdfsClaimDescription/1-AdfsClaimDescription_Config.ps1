<#PSScriptInfo
.VERSION 1.0.0
.GUID 7201dbbb-c6df-4f29-8adb-b0f04cd209f4
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
