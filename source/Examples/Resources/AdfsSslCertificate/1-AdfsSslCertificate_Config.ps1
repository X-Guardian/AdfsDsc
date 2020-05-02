<#PSScriptInfo
.VERSION 1.0.0
.GUID 1ba41585-6c2e-47df-a9a5-b9af7db7122f
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
        This configuration will set the specified certificate for HTTPS bindings for AD FS using the remote credential
        to connect to all the federation servers in the farm.
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
            Thumbprint       = 'FC85DDB0FC58E63D8CB52654F22E4BE7900FE349'
            RemoteCredential = $Credential
        }
    }
}
