<#PSScriptInfo
.VERSION 1.0.0
.GUID 3b6861e5-d3c9-48a7-bebe-88c61442c69c
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
        This configuration will create the first node in an Active Directory Federation Services (AD FS) server farm
        using the Windows Internal Database (WID) on the local server computer.

        The certificate with the specified thumbprint will be used as the SSL certificate and the service
        communications certificate. Automatically generated, self-signed certificates will be used for the token
        signing and token decryption certificates.

        The standard user account specified in the ServiceAccountCredential parameter will be used for the service
        account.
#>

Configuration AdfsFarm_ServiceAccount-WID_Config
{
    Param
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
            Name = 'ADFS-Federation'
        }

        AdfsFarm Contoso
        {
            FederationServiceName        = 'fs.corp.contoso.com'
            FederationServiceDisplayName = 'Contoso ADFS Service'
            CertificateThumbprint        = '8169c52b4ec6e77eb2ae17f028fe5da4e35c0bed'
            ServiceAccountCredential     = $ServiceAccountCredential
            Credential                   = $DomainAdminCredential
        }
    }
}
