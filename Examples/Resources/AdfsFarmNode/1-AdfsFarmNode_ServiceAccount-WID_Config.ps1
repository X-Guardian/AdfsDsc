<#PSScriptInfo
.VERSION 1.0.0
.GUID e8c46129-6a35-4221-9bb5-886b493ad3f0
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
        This configuration will add the computer as a node in an existing Active Directory Federation Services (AD FS)
        server farm using the Windows Internal Database (WID) on the local server computer and whose primary node is
        installed on a computer named PrimaryWIDHost.

        The certificate with the specified thumbprint will be used as the SSL certificate and the service
        communications certificate. Automatically generated, self-signed certificates will be used for the token
        signing and token decryption certificates.

        The standard user account specified in the ServiceAccountCredential parameter will be used for the service
        account.
#>

Configuration AdfsFarmNode_ServiceAccount-WID_Config
{
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCredential]
        $ServiceAccountCredential,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCredential]
        $DomainAdminCredential
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName AdfsDsc

    Node localhost
    {
        WindowsFeature InstallAdfs
        {
            Name   = 'ADFS-Federation'
        }

        AdfsFarmNode SecondWIDHost
        {
            FederationServiceName    = 'fs.corp.contoso.com'
            CertificateThumbprint    = '8169c52b4ec6e77eb2ae17f028fe5da4e35c0bed'
            ServiceAccountCredential = $ServiceAccountCredential
            Credential               = $DomainAdminCredential
            PrimaryComputerName      = 'PrimaryWIDHost'
        }
    }
}
