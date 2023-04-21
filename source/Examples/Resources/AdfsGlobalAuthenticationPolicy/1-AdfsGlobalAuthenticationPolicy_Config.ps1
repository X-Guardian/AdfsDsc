<#PSScriptInfo
.VERSION 1.0.0
.GUID 0d4047c4-5740-486d-8271-bddcc2efae2d
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
        This configuration will set the global authentication policy for the ADFS service.
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
