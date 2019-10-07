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

Configuration AdfsFarmNode_Config
{
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCredential]
        $ServiceAccountCredential
    )

    Import-DscResource -ModuleName AdfsDsc

    Node localhost
    {
        WindowsFeature InstallAdfs
        {
            Name   = 'ADFS-Federation'
        }

        AdfsFarmNode ADFS02
        {
            FederationServiceName    = 'sts.contoso.com'
            CertificateThumbprint    = '2C6A6926F05544C68B45EB75CD228D861320B46C'
            ServiceAccountCredential = $ServiceAccountCredential
            PrimaryComputerName      = 'ADFS01'
        }
    }
}
