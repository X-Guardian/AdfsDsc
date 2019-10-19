<#PSScriptInfo
.VERSION 1.0.0
.GUID 75cfe6d4-e319-4b61-a701-09d608c467c4
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
        This configuration will set the text and links to display when an application prompts a user prompted for a
        certificate for the en-us locale.
#>

Configuration AdfsGlobalWebContent_CertificatePage_Config
{
    param()

    Import-DscResource -ModuleName AdfsDsc

    Node localhost
    {
        AdfsGlobalWebContent ContosoGlobalWebContent
        {
            FederationServiceName             = 'sts.contoso.com'
            Locale                            = 'en-us'
            CompanyName                       = 'Contoso'
            HomeLink                          = 'http://homelink'
            HomeLinkText                      = 'Home'
            PrivacyLink                       = 'http://privaylink'
            PrivacyLinkText                   = 'Privacy statement'
            SignInPageDescriptionText         = '<p>Sign-in to Contoso requires device registration. Click <A href=''http://fs1.contoso.com/deviceregistration/''>here</A> for more information.</p>'
            SignOutPageDescriptionText        = 'Sign out here'
            ErrorPageGenericErrorMessage      = 'An error occurred.'
            ErrorPageSupportEmail             = 'support@contoso.com'
            UpdatePasswordPageDescriptionText = 'Update password here'
            CertificatePageDescriptionText    = 'Sign in with your Smartcard'
        }
    }
}
