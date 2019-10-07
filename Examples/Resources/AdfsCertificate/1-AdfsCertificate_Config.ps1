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
        This configuration will ...
#>

Configuration AdfsCertificate_Config
{
    Import-DscResource -ModuleName AdfsDsc

    Node localhost
    {
        AdfsCertificate Certificates
        {
            CertificateType = 'Token-Signing'
            Thumbprint      = 'cb779e674ae6921682d01d055a4315c786160a7b'
        }
    }
}
