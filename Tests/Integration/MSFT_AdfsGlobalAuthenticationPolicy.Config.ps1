<#
    .SYNOPSIS
        AdfsGlobalAuthenticationPolicy DSC Resource Integration Test Configuration
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
        AdfsGlobalAuthenticationPolicyInit     = @{
            AdditionalAuthenticationProvider       = @()
            AllowAdditionalAuthenticationAsPrimary = $false
            ClientAuthenticationMethods            = @(
                'ClientSecretPostAuthentication'
                'ClientSecretBasicAuthentication'
                'PrivateKeyJWTBearerAuthentication'
                'WindowsIntegratedAuthentication'
            )
            EnablePaginatedAuthenticationPages     = $false
            DeviceAuthenticationEnabled            = $false
            DeviceAuthenticationMethod             = 'SignedToken'
            PrimaryExtranetAuthenticationProvider  = @(
                'FormsAuthentication'
                'MicrosoftPassportAuthentication'
            )
            PrimaryIntranetAuthenticationProvider  = @(
                'WindowsAuthentication'
                'FormsAuthentication'
                'MicrosoftPassportAuthentication'
            )
            WindowsIntegratedFallbackEnabled       = $true
        }
        AdfsGlobalAuthenticationPolicy     = @{
            AdditionalAuthenticationProvider       = @()
            AllowAdditionalAuthenticationAsPrimary = $true
            ClientAuthenticationMethods            = @(
                'ClientSecretPostAuthentication'
                'ClientSecretBasicAuthentication'
                'PrivateKeyJWTBearerAuthentication'
            )
            EnablePaginatedAuthenticationPages     = $true
            DeviceAuthenticationEnabled            = $true
            DeviceAuthenticationMethod             = 'All'
            PrimaryExtranetAuthenticationProvider  = @(
                'FormsAuthentication'
            )
            PrimaryIntranetAuthenticationProvider  = @(
                'WindowsAuthentication'
                'FormsAuthentication'
            )
            WindowsIntegratedFallbackEnabled       = $false
        }
    }
}

Configuration MSFT_AdfsGlobalAuthenticationPolicy_Init_Config
{
    <#
        .SYNOPSIS
            Initialises the Integration test resources
    #>

    Import-DscResource -ModuleName 'AdfsDsc'

    node $AllNodes.NodeName
    {
        AdfsGlobalAuthenticationPolicy 'Integration_Test'
        {
            FederationServiceName                  = $ConfigurationData.FederationServiceName
            AdditionalAuthenticationProvider       = $ConfigurationData.AdfsGlobalAuthenticationPolicyInit.AdditionalAuthenticationProvider
            AllowAdditionalAuthenticationAsPrimary = $ConfigurationData.AdfsGlobalAuthenticationPolicyInit.AllowAdditionalAuthenticationAsPrimary
            ClientAuthenticationMethods            = $ConfigurationData.AdfsGlobalAuthenticationPolicyInit.ClientAuthenticationMethods
            EnablePaginatedAuthenticationPages     = $ConfigurationData.AdfsGlobalAuthenticationPolicyInit.EnablePaginatedAuthenticationPages
            DeviceAuthenticationEnabled            = $ConfigurationData.AdfsGlobalAuthenticationPolicyInit.DeviceAuthenticationEnabled
            DeviceAuthenticationMethod             = $ConfigurationData.AdfsGlobalAuthenticationPolicyInit.DeviceAuthenticationMethod
            PrimaryExtranetAuthenticationProvider  = $ConfigurationData.AdfsGlobalAuthenticationPolicyInit.PrimaryExtranetAuthenticationProvider
            PrimaryIntranetAuthenticationProvider  = $ConfigurationData.AdfsGlobalAuthenticationPolicyInit.PrimaryIntranetAuthenticationProvider
            WindowsIntegratedFallbackEnabled       = $ConfigurationData.AdfsGlobalAuthenticationPolicyInit.WindowsIntegratedFallbackEnabled
        }
    }
}

Configuration MSFT_AdfsGlobalAuthenticationPolicy_Config
{
    <#
        .SYNOPSIS
            Manages an ADFS Global Authentication Policy
    #>

    Import-DscResource -ModuleName 'AdfsDsc'

    node $AllNodes.NodeName
    {
        AdfsGlobalAuthenticationPolicy 'Integration_Test'
        {
            FederationServiceName                  = $ConfigurationData.FederationServiceName
            AdditionalAuthenticationProvider       = $ConfigurationData.AdfsGlobalAuthenticationPolicy.AdditionalAuthenticationProvider
            AllowAdditionalAuthenticationAsPrimary = $ConfigurationData.AdfsGlobalAuthenticationPolicy.AllowAdditionalAuthenticationAsPrimary
            ClientAuthenticationMethods            = $ConfigurationData.AdfsGlobalAuthenticationPolicy.ClientAuthenticationMethods
            EnablePaginatedAuthenticationPages     = $ConfigurationData.AdfsGlobalAuthenticationPolicy.EnablePaginatedAuthenticationPages
            DeviceAuthenticationEnabled            = $ConfigurationData.AdfsGlobalAuthenticationPolicy.DeviceAuthenticationEnabled
            DeviceAuthenticationMethod             = $ConfigurationData.AdfsGlobalAuthenticationPolicy.DeviceAuthenticationMethod
            PrimaryExtranetAuthenticationProvider  = $ConfigurationData.AdfsGlobalAuthenticationPolicy.PrimaryExtranetAuthenticationProvider
            PrimaryIntranetAuthenticationProvider  = $ConfigurationData.AdfsGlobalAuthenticationPolicy.PrimaryIntranetAuthenticationProvider
            WindowsIntegratedFallbackEnabled       = $ConfigurationData.AdfsGlobalAuthenticationPolicy.WindowsIntegratedFallbackEnabled
        }
    }
}
