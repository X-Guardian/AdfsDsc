<#PSScriptInfo
.VERSION 1.0.0
.GUID 1ba41585-6c2e-47df-a9a5-b9af7db7122f
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

Configuration AdfsSslCertificate_Config
{
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCredential]
        $Credential
    )

    Import-DscResource -ModuleName AdfsDsc

    Node localhost
    {
        AdfsSslCertificate SslCertificate
        {
            CertificateType  = 'Https-Binding'
            Thumbprint       = 'cb779e674ae6921682d01d055a4315c786160a7b'
            RemoteCredential = $Credential
        }
    }
}
