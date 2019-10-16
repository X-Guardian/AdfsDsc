<#PSScriptInfo
.VERSION 1.0.0
.GUID 25244487-0a86-4e3f-8223-b504b46d6b80
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
        This configuration will set the contact information in Active Directory Federation Services (AD FS).
#>

Configuration AdfsContactPerson_Config
{
    Import-DscResource -ModuleName AdfsDsc

    Node localhost
    {
        AdfsContactPerson ContactPerson
        {
            FederationServiceName = 'sts.contoso.com'
            Company               = 'Contoso'
            EmailAddress          = 'support@contoso.com'
            GivenName             = 'Bob'
            Surname               = 'Smith'
            TelephoneNumber       = '+1 555 12345678'
        }
    }
}
