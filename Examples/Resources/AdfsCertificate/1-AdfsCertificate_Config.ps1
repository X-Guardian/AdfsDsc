<#PSScriptInfo
.VERSION 1.0.0
.GUID 3523a799-0ce0-46b2-a670-bfcbdd9fab0a
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
