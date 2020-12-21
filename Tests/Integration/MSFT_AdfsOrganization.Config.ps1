<#
    .SYNOPSIS
        AdfsOrganization DSC Resource Integration Test Configuration
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
        FederationServiceName = 'sts.contoso.com'
        AdfsOrganizationInit  = @{
            DisplayName     = ''
            Name            = ''
            OrganizationUrl = ''
        }
        AdfsOrganization      = @{
            DisplayName     = 'Contoso Inc.'
            Name            = 'Contoso'
            OrganizationUrl = 'https://www.contoso.com/'
        }
    }
}

Configuration MSFT_AdfsOrganization_Init_Config
{
    <#
        .SYNOPSIS
            Initialises the Integration test resources
    #>

    Import-DscResource -ModuleName 'AdfsDsc'

    node $AllNodes.NodeName
    {
        AdfsOrganization 'Integration_Test'
        {
            FederationServiceName = $ConfigurationData.FederationServiceName
            DisplayName           = $ConfigurationData.AdfsOrganizationInit.DisplayName
            Name                  = $ConfigurationData.AdfsOrganizationInit.Name
            OrganizationUrl       = $ConfigurationData.AdfsOrganizationInit.OrganizationUrl
        }
    }
}

Configuration MSFT_AdfsOrganization_Config
{
    <#
        .SYNOPSIS
            Manages an ADFS Global Authentication Policy
    #>

    Import-DscResource -ModuleName 'AdfsDsc'

    node $AllNodes.NodeName
    {
        AdfsOrganization 'Integration_Test'
        {
            FederationServiceName = $ConfigurationData.FederationServiceName
            DisplayName           = $ConfigurationData.AdfsOrganization.DisplayName
            Name                  = $ConfigurationData.AdfsOrganization.Name
            OrganizationUrl       = $ConfigurationData.AdfsOrganization.OrganizationUrl
        }
    }
}
