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
        This configuration will ...
#>

Configuration AdfsFarm_ServiceAccount_Config
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

    Import-DscResource -ModuleName AdfsDsc

    Node localhost
    {
        WindowsFeature InstallAdfs
        {
            Name = 'ADFS-Federation'
        }

        AdfsFarm Fabrikam
        {
            FederationServiceName        = 'sts.fabrikam.com'
            FederationServiceDisplayName = 'Fabrikam ADFS Service'
            CertificateThumbprint        = '933D8ACDD49CEF529EB159504C4095575E3496BB'
            SQLConnectionString          = 'Data Source=SQL01;Integrated Security=True'
            ServiceAccountCredential     = $ServiceAccountCredential
            Credential                   = $DomainAdminCredential
        }
    }
}
