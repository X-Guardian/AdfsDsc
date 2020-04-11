<#PSScriptInfo
.VERSION 1.0.0
.GUID 03713f74-bac6-4ffb-ac3d-e657bb595f9d
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
        This configuration will set the text to display in the sign-in pages for AD FS for the en-us locale.
#>

Configuration AdfsGlobalWebContent_SigninPage_Config
{
    param()

    Import-DscResource -ModuleName AdfsDsc

    Node localhost
    {
        AdfsGlobalWebContent ContosoGlobalWebContent
        {
            FederationServiceName             = 'sts.contoso.com'
            Locale                            = 'en-US'
            CompanyName                       = 'Contoso'
            HelpDeskLink                      = 'http://helpdesklink'
            HelpDeskLinkText                  = 'Help desk'
            HomeLink                          = 'http://homelink'
            HomeLinkText                      = 'Home'
            PrivacyLink                       = 'http://privacylink'
            PrivacyLinkText                   = 'Privacy statement'
            SignInPageDescriptionText         = 'Sign in here'
            SignOutPageDescriptionText        = 'Sign out here'
            ErrorPageGenericErrorMessage      = 'An error occurred.'
            ErrorPageSupportEmail             = 'support@contoso.com'
            UpdatePasswordPageDescriptionText = 'Update password here'
        }
    }
}
