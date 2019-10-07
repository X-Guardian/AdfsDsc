<#PSScriptInfo
.VERSION 1.0.0
.GUID 0d4047c4-5740-486d-8271-bddcc2efae2d
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

Configuration AdfsGlobalAuthenticationPolicy_Config
{
    param()

    Import-DscResource -ModuleName AdfsDsc

    Node localhost
    {
        AdfsGlobalAuthenticationPolicy ContosoGlobalAuthenticationPolicy
        {
            FederationServiceName                  = 'sts.contoso.com'
            AdditionalAuthenticationProvider       = ''
            AllowAdditionalAuthenticationAsPrimary = $true
            ClientAuthenticationMethods            = 'ClientSecretPostAuthentication'
            EnablePaginatedAuthenticationPages     = $true
            DeviceAuthenticationEnabled            = $true
            DeviceAuthenticationMethod             = 'All'
            PrimaryExtranetAuthenticationProvider  = 'FormsAuthentication'
            PrimaryIntranetAuthenticationProvider  = 'WindowsAuthentication', 'FormsAuthentication', 'MicrosoftPassportAuthentication'
            WindowsIntegratedFallbackEnabled       = $true
        }
    }
}
