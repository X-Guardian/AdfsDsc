<#
    .SYNOPSIS
        AdfsClaimDescription DSC Resource Integration Test Configuration
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
        AllNodes             = @(
            @{
                NodeName        = 'localhost'
                CertificateFile = $env:DscPublicCertificatePath
            }
        )
        AdfsClaimDescription = @{
            Name       = 'Contoso Role'
            ClaimType  = 'https://contoso.com/role'
            IsAccepted = $true
            IsOffered  = $true
            IsRequired = $false
            Notes      = 'The role of the Contoso user'
            ShortName  = 'contosorole'
        }
    }
}

Configuration MSFT_AdfsClaimDescription_Init_Config
{
    <#
        .SYNOPSIS
            Initialises the Integration test resources
    #>

    Import-DscResource -ModuleName 'AdfsDsc'

    node $AllNodes.NodeName
    {
        AdfsClaimDescription 'Integration_Test'
        {
            Name      = $ConfigurationData.AdfsClaimDescription.Name
            ClaimType = $ConfigurationData.AdfsClaimDescription.ClaimType
            Ensure    = 'Absent'
        }
    }
}

Configuration MSFT_AdfsClaimDescription_Config
{
    <#
        .SYNOPSIS
            Manages an ADFS Claim Description
    #>

    Import-DscResource -ModuleName 'AdfsDsc'

    node $AllNodes.NodeName
    {
        AdfsClaimDescription 'Integration_Test'
        {
            Name       = $ConfigurationData.AdfsClaimDescription.Name
            ClaimType  = $ConfigurationData.AdfsClaimDescription.ClaimType
            IsAccepted = $ConfigurationData.AdfsClaimDescription.IsAccepted
            IsOffered  = $ConfigurationData.AdfsClaimDescription.IsOffered
            IsRequired = $ConfigurationData.AdfsClaimDescription.IsRequired
            Notes      = $ConfigurationData.AdfsClaimDescription.Notes
            ShortName  = $ConfigurationData.AdfsClaimDescription.ShortName
        }
    }
}
