<#
    .SYNOPSIS
        AdfsServerApplication DSC Resource Integration Test Configuration

    .NOTES
        The AdfsServerApplication resource has a dependency on an AdfsApplicationGroup resource
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
        AdfsServerApplication = @{
            Name                = 'DscServerApplication1'
            Description         = 'This is the DscServerApplication1 Description'
            Identifier          = '96ec073d-9200-4d74-aeb7-d5028d6efa4b'
            ADUserPrincipalName = 'CONTOSO\Svc.App1'
            RedirectUri         = 'https://serverapp1.contoso.com'
            LogoutUri           = 'https://serverapp1.contoso.com/logout'
        }
    }
}

Configuration MSFT_AdfsServerApplication_Init_Config
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

Configuration MSFT_AdfsServerApplication_Config
{
    <#
        .SYNOPSIS
            Manages an ADFS Application Group and AdfsServerApplication
    #>

    Import-DscResource -ModuleName 'AdfsDsc'

    node $AllNodes.NodeName
    {
        AdfsApplicationGroup 'Integration_Test'
        {
            Name        = $ConfigurationData.AdfsApplicationGroup.Name
            Description = $ConfigurationData.AdfsApplicationGroup.Description
        }

        AdfsServerApplication 'Integration_Test'
        {
            Name                       = $ConfigurationData.AdfsServerApplication.Name
            Description                = $ConfigurationData.AdfsServerApplication.Description
            ApplicationGroupIdentifier = $ConfigurationData.AdfsApplicationGroup.Name
            Identifier                 = $ConfigurationData.AdfsServerApplication.Identifier
            ADUserPrincipalName        = $ConfigurationData.AdfsServerApplication.ADUserPrincipalName
            RedirectUri                = $ConfigurationData.AdfsServerApplication.RedirectUri
            LogoutUri                  = $ConfigurationData.AdfsServerApplication.LogoutUri
        }
    }
}
