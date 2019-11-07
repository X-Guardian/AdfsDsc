<#
    .SYNOPSIS
        AdfsApplicationPermission DSC Resource Integration Test Configuration

    .NOTES
        The AdfsApplicationPermission resource has a dependency on an AdfsApplicationGroup,
        AdfsNativeClientApplication and AdsWebApiApplication resource.
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
    $applicationIdentifier = 'e7bfb303-c5f6-4028-a360-b6293d41338c'

    $ConfigurationData = @{
        AllNodes                    = @(
            @{
                NodeName        = 'localhost'
                CertificateFile = $env:DscPublicCertificatePath
            }
        )

        AdfsApplicationGroup        = @{
            Name        = 'DscAppGroup1'
            Description = "This is the AppGroup1 Description"
            Ensure      = 'Present'
        }

        AdfsNativeClientApplication = @{
            Name        = 'DscNativeClientApplication1'
            Description = 'This is the DscNativeClientApplication1 Description'
            Identifier  = $applicationIdentifier
            RedirectUri = 'https://nativeapp1.contoso.com'
        }

        AdfsWebApiApplication       = @{
            Name                    = 'DscWebApiApplication1'
            Description             = 'This is the DscWebApiApplication1 Description'
            Identifier              = $applicationIdentifier
            AccessControlPolicyName = 'Permit Everyone'
        }

        AdfsApplicationPermission   = @{
            ClientRoleIdentifier = $applicationIdentifier
            ServerRoleIdentifier = $applicationIdentifier
            Description          = 'This is the DscApplicationPermission Description'
            ScopeNames           = 'openid'
        }
    }
}

Configuration MSFT_AdfsApplicationPermission_Init_Config
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

Configuration MSFT_AdfsApplicationPermission_Config
{
    <#
        .SYNOPSIS
            Manages an ADFS Application Group and AdfsApplicationPermission
    #>

    Import-DscResource -ModuleName 'AdfsDsc'

    node $AllNodes.NodeName
    {
        AdfsApplicationGroup 'Integration_Test'
        {
            Name        = $ConfigurationData.AdfsApplicationGroup.Name
            Description = $ConfigurationData.AdfsApplicationGroup.Description
        }

        AdfsNativeClientApplication 'Integration_Test'
        {
            Name                       = $ConfigurationData.AdfsNativeClientApplication.Name
            Description                = $ConfigurationData.AdfsNativeClientApplication.Description
            ApplicationGroupIdentifier = $ConfigurationData.AdfsApplicationGroup.Name
            Identifier                 = $ConfigurationData.AdfsNativeClientApplication.Identifier
            RedirectUri                = $ConfigurationData.AdfsNativeClientApplication.RedirectUri
        }

        AdfsWebApiApplication 'Integration_Test'
        {
            Name                       = $ConfigurationData.AdfsWebApiApplication.Name
            Description                = $ConfigurationData.AdfsWebApiApplication.Description
            ApplicationGroupIdentifier = $ConfigurationData.AdfsApplicationGroup.Name
            Identifier                 = $ConfigurationData.AdfsWebApiApplication.Identifier
            AccessControlPolicyName    = $ConfigurationData.AdfsWebApiApplication.AccessControlPolicyName
        }

        AdfsApplicationPermission 'Integration_Test'
        {
            ClientRoleIdentifier = $ConfigurationData.AdfsApplicationPermission.ClientRoleIdentifier
            ServerRoleIdentifier = $ConfigurationData.AdfsApplicationPermission.ServerRoleIdentifier
            Description          = $ConfigurationData.AdfsApplicationPermission.Description
            ScopeNames           = $ConfigurationData.AdfsApplicationPermission.ScopeNames
        }
    }
}
