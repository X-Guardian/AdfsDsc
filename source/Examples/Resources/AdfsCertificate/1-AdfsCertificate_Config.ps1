<#PSScriptInfo
.VERSION 1.0.0
.GUID 3523a799-0ce0-46b2-a670-bfcbdd9fab0a
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
        This configuration will set the primary token-signing certificate in Active Directory Federation Services (AD FS)
        to the certificate with the specified thumbprint.
#>

Configuration AdfsCertificate_Config
{
    Import-DscResource -ModuleName AdfsDsc

    Node localhost
    {
        AdfsCertificate Certificates
        {
            CertificateType = 'Token-Signing'
            Thumbprint      = 'fedd995b45e633d4ef30fcbc8f3a48b627e9a28b'
        }
    }
}
