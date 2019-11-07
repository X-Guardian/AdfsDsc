#region HEADER
# Integration Test Config Template Version: 1.2.0
#endregion

$configFile = [System.IO.Path]::ChangeExtension($MyInvocation.MyCommand.Path, 'json')
if (Test-Path -Path $configFile)
{
    <#
        Allows reading the configuration data from a JSON file, for real testing
        scenarios outside of the CI.
    #>
    $ConfigurationData = Get-Content -Path $configFile | ConvertFrom-Json
}
else
{
    $FederationServiceName = 'sts.contoso.com'
    $AdfsCertificate = New-SelfSignedCertificate -DnsName $FederationServiceName

    $ConfigurationData = @{
        AllNodes = @(
            @{
                NodeName                      = 'localhost'
                CertificateFile               = $env:DscPublicCertificatePath
                FederationServiceName         = $FederationServiceName
                FederationServiceDisplayName  = 'Contoso ADFS Service'
                GroupServiceAccountIdentifier = 'contoso\adfsgmsa$'
                AdfsCertificateThumbprint     = $AdfsCertificate.Thumbprint
            }
        )
    }
}

Configuration MSFT_AdfsFarm_Config
{
    <#
        .SYNOPSIS
            Sets the supported property values.
    #>

    Import-DscResource -ModuleName 'AdfsDsc'

    node $AllNodes.NodeName
    {
        ADFSFarm 'Integration_Test'
        {
            FederationServiceName         = $ConfigurationData.AllNodes.FederationServiceName
            FederationServiceDisplayName  = $ConfigurationData.AllNodes.FederationServiceDisplayName
            CertificateThumbprint         = $ConfigurationData.AllNodes.AdfsCertificateThumbprint
            GroupServiceAccountIdentifier = $ConfigurationData.AllNodes.GroupServiceAccountIdentifier
            Credential                    = $DomainAdminCredential
        }
    }
}
