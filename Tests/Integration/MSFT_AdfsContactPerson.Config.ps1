<#
    .SYNOPSIS
        AdfsContactPerson DSC Resource Integration Test Configuration
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
        AdfsContactPerson     = @{
            Company         = 'Contoso'
            EmailAddress    = 'support@contoso.com'
            GivenName       = 'Bob'
            Surname         = 'Smith'
            TelephoneNumber = '+1 555 12345678'
        }
    }
}

Configuration MSFT_AdfsContactPerson_Init_Config
{
    <#
        .SYNOPSIS
            Initialises the Integration test resources
    #>

    Import-DscResource -ModuleName 'AdfsDsc'

    node $AllNodes.NodeName
    {
        AdfsContactPerson 'Integration_Test'
        {
            FederationServiceName = $ConfigurationData.FederationServiceName
            Company               = ''
            EmailAddress          = ''
            GivenName             = ''
            Surname               = ''
            TelephoneNumber       = ''
        }
    }
}

Configuration MSFT_AdfsContactPerson_Config
{
    <#
        .SYNOPSIS
            Manages an ADFS Application Group
    #>

    Import-DscResource -ModuleName 'AdfsDsc'

    node $AllNodes.NodeName
    {
        AdfsContactPerson 'Integration_Test'
        {
            FederationServiceName = $ConfigurationData.FederationServiceName
            Company               = $ConfigurationData.AdfsContactPerson.Company
            EmailAddress          = $ConfigurationData.AdfsContactPerson.EmailAddress
            GivenName             = $ConfigurationData.AdfsContactPerson.GivenName
            Surname               = $ConfigurationData.AdfsContactPerson.Surname
            TelephoneNumber       = $ConfigurationData.AdfsContactPerson.TelephoneNumber
        }
    }
}
