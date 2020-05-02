<#PSScriptInfo
.VERSION 1.0.0
.GUID 88fc9bba-34b0-4baa-8c9a-1b0dc09b4cd4
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
        server farm using using a Microsoft SQL Server database on a remote computer named sql01.contoso.com using
        Windows Authentication and whose primary node is installed on a computer named adfs01.contoso.com.

        The certificate with the specified thumbprint will be used as the SSL certificate and the service
        communications certificate. Automatically generated, self-signed certificates will be used for the token
        signing and token decryption certificates.

        The group Managed Service Account specified in the GroupServiceAccountIdentifier parameter will be used for the
        service account.
#>

Configuration AdfsFarmNode_gMSA_SQL_Integrated_Config
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
            FederationServiceName         = 'sts.contoso.com'
            CertificateThumbprint         = '933D8ACDD49CEF529EB159504C4095575E3496BB'
            GroupServiceAccountIdentifier = 'contoso\adfsgmsa$'
            SQLConnectionString           = 'Data Source=sql01.contoso.com;Integrated Security=True'
            Credential                    = $DomainAdminCredential
            PrimaryComputerName           = 'adfs01.contoso.com'
        }
    }
}
