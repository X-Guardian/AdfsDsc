<#
    .SYNOPSIS
        AdfsNativeClientApplication DSC Resource Integration Test Configuration

    .NOTES
        The AdfsNativeClientApplication resource has a dependency on an AdfsApplicationGroup resource
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
            Identifier  = 'e7bfb303-c5f6-4028-a360-b6293d41338c'
            RedirectUri = 'https://nativeapp1.contoso.com'
            LogoutUri   = 'https://nativeapp1.contoso.com/logout'
        }
    }
}

Configuration MSFT_AdfsNativeClientApplication_Init_Config
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

Configuration MSFT_AdfsNativeClientApplication_Config
{
    <#
        .SYNOPSIS
            Manages an ADFS Application Group and AdfsNativeClientApplication
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
            LogoutUri                  = $ConfigurationData.AdfsNativeClientApplication.LogoutUri
        }
    }
}
