<#PSScriptInfo
.VERSION 1.0.0
.GUID 06035ace-52fa-4d92-b7f0-8a4780f60fbf
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

Configuration AdfsRelyingPartyTrust_OWA_Config
{

    Import-DscResource -Module AdfsDsc

    Node localhost
    {
        AdfsRelyingPartyTrust OwaInternal
        {
            Name                       = 'Outlook Web App'
            Enabled                    = $true
            Notes                      = 'This is a trust for https://mail.fabrikam.com/owa'
            WSFedEndpoint              = 'https://mail.fabrikam.com/owa'
            Identifier                 = 'https://mail.fabrikam.com/owa'
            IssuanceTransformRules     = $node.IssuanceTransformRules
            IssuanceAuthorizationRules = $node.IssuanceAuthorizationRules
        }
    }
}

$ConfigurationData = @{
    AllNodes = @(
        @{
            NodeName = 'localhost'
            IssuanceAuthorizationRules = @'
@RuleTemplate = "AllowAllAuthzRule"
 => issue(Type = "http://schemas.microsoft.com/authorization/claims/permit", Value = "true");
'@
            IssuanceTransformRules     = @'
@RuleName = "ActiveDirectoryUserSID"
c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname", Issuer == "AD AUTHORITY"]

=> issue(store = "Active Directory", types = ("http://schemas.microsoft.com/ws/2008/06/identity/claims/primarysid"), query = ";objectSID;{0}", param = c.Value);

@RuleName = "ActiveDirectoryGroupSID"
c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname", Issuer == "AD AUTHORITY"]

=> issue(store = "Active Directory", types = ("http://schemas.microsoft.com/ws/2008/06/identity/claims/groupsid"), query = ";tokenGroups(SID);{0}", param = c.Value);

@RuleName = "ActiveDirectoryUPN"
c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname", Issuer == "AD AUTHORITY"]

=> issue(store = "Active Directory", types = ("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn"), query = ";userPrincipalName;{0}", param = c.Value);
'@
        }
    )
}
