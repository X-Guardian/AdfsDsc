<#
    .SYNOPSIS
        AdfsWebApiApplication DSC Resource Integration test Configuration.

    .NOTES
        The AdfsWebApiApplication resource has a dependency on an AdfsApplicationGroup resource
#>

#region HEADER
# Integration Test Config Template Version: 1.2.1
#endregion

$configFile = [System.IO.Path]::ChangeExtension($MyInvocation.MyCommand.Path, 'json')
if (Test-Path -Path $configFile)
{
    $ConfigurationData = Get-Content -Path $configFile | ConvertFrom-Json
}
else
{
    $ConfigurationData = @{
        AllNodes              = @(
            @{
                NodeName        = 'localhost'
                CertificateFile = $env:DscPublicCertificatePath
            }
        )
        AdfsApplicationGroup  = @{
            Name        = 'DscAppGroup1'
            Description = "This is the AppGroup1 Description"
            Ensure      = 'Present'
        }
        AdfsWebApiApplication = @{
            Name                              = 'DscWebApiApplication1'
            Description                       = 'This is the DscWebApiApplication1 Description'
            Identifier                        = 'e7bfb303-c5f6-4028-a360-b6293d41338c'
            AccessControlPolicyName           = 'Permit specific group'
        }
    }
}

Configuration MSFT_AdfsWebApiApplication_Init_Config
{
    <#
        .SYNOPSIS
            Initialises the Integration test resources
    #>

    Import-DscResource -ModuleName 'AdfsDsc'

    node $AllNodes.NodeName
    {
        AdfsApplicationGroup 'Integration_Test'
        {
            Name   = $ConfigurationData.AdfsApplicationGroup.Name
            Ensure = 'Absent'
        }
    }
}

Configuration MSFT_AdfsWebApiApplication_Config
{
    <#
        .SYNOPSIS
            Manages an ADFS Application Group and AdfsWebApiApplication
    #>

    Import-DscResource -ModuleName 'AdfsDsc'

    node $AllNodes.NodeName
    {
        AdfsApplicationGroup 'Integration_Test'
        {
            Name        = $ConfigurationData.AdfsApplicationGroup.Name
            Description = $ConfigurationData.AdfsApplicationGroup.Description
        }

        AdfsWebApiApplication 'Integration_Test'
        {
            Name                          = $ConfigurationData.AdfsWebApiApplication.Name
            Description                   = $ConfigurationData.AdfsWebApiApplication.Description
            ApplicationGroupIdentifier    = $ConfigurationData.AdfsApplicationGroup.Name
            Identifier                    = $ConfigurationData.AdfsWebApiApplication.Identifier
            AccessControlPolicyName       = $ConfigurationData.AdfsWebApiApplication.AccessControlPolicyName
            AccessControlPolicyParameters = MSFT_AdfsAccessControlPolicyParameters
            {
                GroupParameter = 'GTECK\DscWebApiApplication1 Users'
            }
            IssuanceTransformRules        = @(
                MSFT_AdfsIssuanceTransformRule
                {
                    TemplateName   = 'LdapClaims'
                    Name           = 'App1 Ldap Claims'
                    LdapMapping    = @(
                        MSFT_AdfsLdapMapping
                        {
                            LdapAttribute     = 'mail'
                            OutgoingClaimType = 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress'
                        }
                        MSFT_AdfsLdapMapping
                        {
                            LdapAttribute     = 'sn'
                            OutgoingClaimType = 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname'
                        }
                    )
                    AttributeStore = 'Active Directory'
                }
                MSFT_AdfsIssuanceTransformRule
                {
                    TemplateName       = 'EmitGroupClaims'
                    Name               = 'App1 User Role Claim'
                    GroupName          = 'App1 Users'
                    OutgoingClaimType  = 'http://schemas.microsoft.com/ws/2008/06/identity/claims/role'
                    OutgoingClaimValue = 'User'
                }
                MSFT_AdfsIssuanceTransformRule
                {
                    TemplateName = 'CustomClaims'
                    Name         = 'App1 Custom Claim'
                    CustomRule   = 'c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/groupsid", Value == "S-1-5-21-2624039266-918686060-4041204886-1128", Issuer == "AD AUTHORITY"]
 => issue(Type = "http://schemas.microsoft.com/ws/2008/06/identity/claims/role", Value = "IDScan User", Issuer = c.Issuer, OriginalIssuer = c.OriginalIssuer, ValueType = c.ValueType);'
                }
            )
        }
    }
}
