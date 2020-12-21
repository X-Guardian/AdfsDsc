<#PSScriptInfo
.VERSION 1.0.0
.GUID 46f31899-f32e-4621-87a8-5f7614b3cc07
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
        This configuration will add the computer as a node in an existing Active Directory Federation Services (AD FS)
        server farm using the Windows Internal Database (WID) on the local server computer and whose primary node is
        installed on a computer named PrimaryWIDHost.

        The certificate with the specified thumbprint will be used as the SSL certificate and the service
        communications certificate. Automatically generated, self-signed certificates will be used for the token
        signing and token decryption certificates.

        The group Managed Service Account specified in the GroupServiceAccountIdentifier parameter will be used for the
        service account.
#>

Configuration AdfsFarmNode_gMSA_WID_Config
{
    param
    (
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

        AdfsFarmNode SecondWIDHost
        {
            FederationServiceName         = 'fs.corp.contoso.com'
            CertificateThumbprint         = '8169c52b4ec6e77eb2ae17f028fe5da4e35c0bed'
            GroupServiceAccountIdentifier = 'contoso\adfsgmsa$'
            Credential                    = $DomainAdminCredential
            PrimaryComputerName           = 'PrimaryWIDHost'
        }
    }
}
