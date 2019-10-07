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
        This configuration will ...
#>

Configuration AdfsFarmNode_gMSA_Config
{
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCredential]
        $DomainAdminCredential
    )

    Import-DscResource -ModuleName AdfsDsc

    Node localhost
    {
        WindowsFeature InstallAdfs
        {
            Name = 'ADFS-Federation'
        }

        AdfsFarmNode ADFS02
        {
            FederationServiceName         = 'sts.contoso.com'
            CertificateThumbprint         = '933D8ACDD49CEF529EB159504C4095575E3496BB'
            GroupServiceAccountIdentifier = 'contoso\adfs-gmsa$'
            SQLConnectionString           = 'Data Source=SQL01;Integrated Security=True'
            Credential                    = $DomainAdminCredential
            PrimaryComputerName           = 'ADFS01'
        }
    }
}
