<#
    .SYNOPSIS
        DSC Configuration Template for DSC Resource Integration tests.

    .DESCRIPTION
        To Use:
            1. Copy to \Tests\Integration\ folder and rename <ResourceName>.config.ps1
               (e.g. MSFT_Firewall.config.ps1).
            2. Customize TODO sections.
            3. Remove TODO comments and TODO comment-blocks.
            4. Remove this comment-based help.

    .NOTES
        Comment in HEADER region are standard and should not be altered.
#>

#region HEADER
# Integration Test Config Template Version: 1.2.1
#endregion

$configFile = [System.IO.Path]::ChangeExtension($MyInvocation.MyCommand.Path, 'json')
if (Test-Path -Path $configFile)
{
    <#
        TODO: Allows reading the configuration data from a JSON file,
        e.g. integration_template.config.json for real testing
        scenarios outside of the CI.
    #>
    $ConfigurationData = Get-Content -Path $configFile | ConvertFrom-Json
}
else
{
    <#
        TODO: (Optional) If appropriate, this configuration hash table
        can be moved from here and into the integration test file.
        For example, if there are several configurations which all
        need different configuration properties, it might be easier
        to have one ConfigurationData-block per configuration test
        than one big ConfigurationData-block here.
        It may also be moved if it is easier to read the tests when
        the ConfigurationData-block is in the integration test file.
        The reason for it being here is that it is easier to read
        the configuration when the ConfigurationData-block is in this
        file.
    #>
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
            Name        = 'DscWebApiApplication1'
            Description = 'This is the DscWebApiApplication1 Description'
            Identifier  = 'e7bfb303-c5f6-4028-a360-b6293d41338c'
        }
    }
}

<#
    .SYNOPSIS
        Initialises the Integration test resources
#>
Configuration MSFT_AdfsWebApiApplication_Init_Config
{
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

<#
    .SYNOPSIS
        Manages an ADFS Application Group
#>
Configuration MSFT_AdfsWebApiApplication_Config
{
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
            Name                       = $ConfigurationData.AdfsWebApiApplication.Name
            Description                = $ConfigurationData.AdfsWebApiApplication.Description
            ApplicationGroupIdentifier = $ConfigurationData.AdfsApplicationGroup.Name
            Identifier                 = $ConfigurationData.AdfsWebApiApplication.Identifier
            AccessControlPolicyName    = 'Permit Everyone'
            IssuanceTransformRules     = @(
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

<#

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
                    TemplateName         = 'EmitGroupClaims'
                    Name                 = 'App1 User Role Claim'
                    GroupName            = 'App1 Users'
                    OutgoingClaimType    = 'http://schemas.microsoft.com/ws/2008/06/identity/claims/role'
                    OutgoingClaimValue   = 'User'
                }
#>
