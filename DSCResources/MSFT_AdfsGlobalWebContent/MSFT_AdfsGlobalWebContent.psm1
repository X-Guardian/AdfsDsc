<#
    .SYNOPSIS
        DSC module for the ADFS Global Web Content resource

    .DESCRIPTION
        The AdfsGlobalWebContent DSC resource manages the global web content objects or the global web content object
        that corresponds to the locale that you specify.

    .PARAMETER FederationServiceName
        Key - String
        Specifies the DNS name of the federation service.

    .PARAMETER Locale
        Key - String
        Specifies a locale. The cmdlet sets global web content for the locale that you specify.

    .PARAMETER CompanyName
        Write - String
        Specifies the company name. AD FS displays the company name in the sign-in pages when you have not set a logo
        on the active web theme.

    .PARAMETER HelpDeskLink
        Write - String
        Specifies the help desk link that is shown on the logon pages for AD FS.

    .PARAMETER HelpDeskLinkText
        Write - String
        Specifies the help desk link text that is shown on the logon pages for AD FS.

    .PARAMETER HomeLink
        Write - String
        Specifies the Home link that is shown on the logon pages for AD FS.

    .PARAMETER HomeLinkText
        Write - String
        Specifies the Home link text that is shown on the logon pages for AD FS.

    .PARAMETER HomeRealmDiscoveryOtherOrganizationDescriptionText
        Write - String
        Specifies the text for the home realm discovery description for other organization.

    .PARAMETER HomeRealmDiscoveryPageDescriptionText
        Write - String
        Specifies the text for the home realm discovery page description.

    .PARAMETER OrganizationalNameDescriptionText
        Write - String
        Specifies text for the organizational name description.

    .PARAMETER PrivacyLink
        Write - String
        Specifies the Privacy policy link that is shown on the logon pages for AD FS.

    .PARAMETER PrivacyLinkText
        Write - String
        Specifies the Privacy policy link text that is shown on the logon pages for AD FS.

    .PARAMETER CertificatePageDescriptionText
        Write - String
        Specifies the text on the certificate page. Active Directory Federation Services (AD FS) displays the text that
        you specify when it prompts the user for a certificate.

    .PARAMETER SignInPageDescriptionText
        Write - String
        Specifies the description to display when a user signs in to applications by using AD FS. When you use
        Integrated Windows Authentication in the intranet, users do not see this page.

    .PARAMETER SignOutPageDescriptionText
        Write - String
        Specifies the description to display when a user signs out of applications.

    .PARAMETER ErrorPageDescriptionText
        Write - String
        Specifies an error message to display when a user encounters any generic errors that occur for a token request.
        This string can be an HTML fragment.

    .PARAMETER ErrorPageGenericErrorMessage
        Write - String
        Specifies an error message to display for any generic errors that occur for a token request. This string can be
        an HTML fragment.

    .PARAMETER ErrorPageAuthorizationErrorMessage
        Write - String
        Specifies an error message to display when a user encounters any authorization errors that occur for a token
        request. This string can be an HTML fragment.

    .PARAMETER ErrorPageDeviceAuthenticationErrorMessage
        Write - String
        Specifies an error message to display for any device authentication errors that occur for a token request.
        Device authentication errors occur when the user presents an expired user@device certificate to AD FS, a
        certificate is not found in AD DS, or a certificate is disabled in AD DS. This string can be an HTML fragment.

    .PARAMETER ErrorPageSupportEmail
        Write - String
        Specifies the support email address on the error page.

    .PARAMETER UpdatePasswordPageDescriptionText
        Write - String
        Specifies the description to display in the update password page when users change their passwords.

    .PARAMETER SignInPageAdditionalAuthenticationDescriptionText
        Write - String
        Specifies the description to display when an application prompts a user for additional authentication. The
        sign-in page can also display a description that is provided by the additional authentication provider.
#>

Set-StrictMode -Version 2.0

$script:dscModuleName = 'AdfsDsc'
$script:psModuleName = 'ADFS'
$script:dscResourceName = [System.IO.Path]::GetFileNameWithoutExtension($MyInvocation.MyCommand.Name)

$script:resourceModulePath = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent
$script:modulesFolderPath = Join-Path -Path $script:resourceModulePath -ChildPath 'Modules'

$script:localizationModulePath = Join-Path -Path $script:modulesFolderPath -ChildPath "$($script:DSCModuleName).Common"
Import-Module -Name (Join-Path -Path $script:localizationModulePath -ChildPath "$($script:dscModuleName).Common.psm1")

$script:localizedData = Get-LocalizedData -ResourceName $script:dscResourceName

function Get-TargetResource
{
    <#
    .SYNOPSIS
        Get-TargetResource

    .NOTES
        Used Cmdlets/Functions:

        Name                     | Module
        -------------------------|----------------
        Get-AdfsGlobalWebContent | Adfs
        Assert-Module            | AdfsDsc.Common
        Assert-AdfsService       | AdfsDsc.Common
    #>

    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $FederationServiceName,

        [Parameter(Mandatory = $true)]
        [System.String]
        $Locale
    )

    # Set Verbose and Debug parameters
    $commonParms = @{
        Verbose = $VerbosePreference
        Debug   = $DebugPreference
    }

    Write-Verbose -Message ($script:localizedData.GettingResourceMessage -f $FederationServiceName, $Locale)

    # Check of the Resource PowerShell module is installed
    Assert-Module -ModuleName $script:psModuleName

    # Check if the ADFS Service is present and running
    Assert-AdfsService @commonParms

    try
    {
        $targetResource = Get-AdfsGlobalWebContent -Locale $Locale
    }
    catch
    {
        $errorMessage = $script:localizedData.GettingResourceErrorMessage -f $FederationServiceName, $Locale
        New-InvalidOperationException -Message $errorMessage -Error $_
    }

    $returnValue = @{
        FederationServiceName                              = $FederationServiceName
        Locale                                             = $Locale
        CompanyName                                        = $targetResource.CompanyName
        HelpDeskLink                                       = $targetResource.HelpDeskLink
        HelpDeskLinkText                                   = $targetResource.HelpDeskLinkText
        HomeLink                                           = $targetResource.HomeLink
        HomeLinkText                                       = $targetResource.HomeLinkText
        HomeRealmDiscoveryOtherOrganizationDescriptionText = $targetResource.HomeRealmDiscoveryOtherOrganizationDescriptionText
        HomeRealmDiscoveryPageDescriptionText              = $targetResource.HomeRealmDiscoveryPageDescriptionText
        OrganizationalNameDescriptionText                  = $targetResource.OrganizationalNameDescriptionText
        PrivacyLink                                        = $targetResource.PrivacyLink
        PrivacyLinkText                                    = $targetResource.PrivacyLinkText
        CertificatePageDescriptionText                     = $targetResource.CertificatePageDescriptionText
        SignInPageDescriptionText                          = $targetResource.SignInPageDescriptionText
        SignOutPageDescriptionText                         = $targetResource.SignOutPageDescriptionText
        ErrorPageDescriptionText                           = $targetResource.ErrorPageDescriptionText
        ErrorPageGenericErrorMessage                       = $targetResource.ErrorPageGenericErrorMessage
        ErrorPageAuthorizationErrorMessage                 = $targetResource.ErrorPageAuthorizationErrorMessage
        ErrorPageDeviceAuthenticationErrorMessage          = $targetResource.ErrorPageDeviceAuthenticationErrorMessage
        ErrorPageSupportEmail                              = $targetResource.ErrorPageSupportEmail
        UpdatePasswordPageDescriptionText                  = $targetResource.UpdatePasswordPageDescriptionText
        SignInPageAdditionalAuthenticationDescriptionText  = $targetResource.SignInPageAdditionalAuthenticationDescriptionText
    }

    $returnValue
}

function Set-TargetResource
{
    <#
    .SYNOPSIS
        Set-TargetResource

    .NOTES
        Used Cmdlets/Functions:

        Name                          | Module
        ------------------------------|----------------
        Set-AdfsGlobalWebContent      | Adfs
        Compare-ResourcePropertyState | AdfsDsc.Common
    #>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', "",
        Justification = 'False positive on UpdatePasswordPageDescriptionText')]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $FederationServiceName,

        [Parameter(Mandatory = $true)]
        [System.String]
        $Locale,

        [Parameter()]
        [System.String]
        $CompanyName,

        [Parameter()]
        [System.String]
        $HelpDeskLink,

        [Parameter()]
        [System.String]
        $HelpDeskLinkText,

        [Parameter()]
        [System.String]
        $HomeLink,

        [Parameter()]
        [System.String]
        $HomeLinkText,

        [Parameter()]
        [System.String]
        $HomeRealmDiscoveryOtherOrganizationDescriptionText,

        [Parameter()]
        [System.String]
        $HomeRealmDiscoveryPageDescriptionText,

        [Parameter()]
        [System.String]
        $OrganizationalNameDescriptionText,

        [Parameter()]
        [System.String]
        $PrivacyLink,

        [Parameter()]
        [System.String]
        $PrivacyLinkText,

        [Parameter()]
        [System.String]
        $CertificatePageDescriptionText,

        [Parameter()]
        [System.String]
        $SignInPageDescriptionText,

        [Parameter()]
        [System.String]
        $SignOutPageDescriptionText,

        [Parameter()]
        [System.String]
        $ErrorPageDescriptionText,

        [Parameter()]
        [System.String]
        $ErrorPageGenericErrorMessage,

        [Parameter()]
        [System.String]
        $ErrorPageAuthorizationErrorMessage,

        [Parameter()]
        [System.String]
        $ErrorPageDeviceAuthenticationErrorMessage,

        [Parameter()]
        [System.String]
        $ErrorPageSupportEmail,

        [Parameter()]
        [System.String]
        $UpdatePasswordPageDescriptionText,

        [Parameter()]
        [System.String]
        $SignInPageAdditionalAuthenticationDescriptionText
    )

    # Set Verbose and Debug parameters
    $commonParms = @{
        Verbose = $VerbosePreference
        Debug   = $DebugPreference
    }

    # Remove any parameters not used in Splats
    [HashTable]$parameters = $PSBoundParameters
    $parameters.Remove('FederationServiceName')
    $parameters.Remove('Locale')
    $parameters.Remove('Verbose')

    $getTargetResourceParms = @{
        FederationServiceName = $FederationServiceName
        Locale                = $Locale
    }
    $targetResource = Get-TargetResource @getTargetResourceParms

    $propertiesNotInDesiredState = (
        Compare-ResourcePropertyState -CurrentValues $targetResource -DesiredValues $parameters `
            @commonParms | Where-Object -Property InDesiredState -eq $false)

    $SetParameters = @{ }
    foreach ($property in $propertiesNotInDesiredState)
    {
        Write-Verbose -Message ($script:localizedData.SettingResourceMessage -f
            $FederationServiceName, $Locale, $property.ParameterName, ($property.Expected -join ', '))

        $setParameters.add($property.ParameterName, $property.Expected)
    }

    if ($setParameters.Count -gt 0)
    {
        try
        {
            Set-AdfsGlobalWebContent -Locale $Locale @setParameters
        }
        catch
        {
            $errorMessage = $script:localizedData.SettingResourceErrorMessage -f $FederationServiceName, $Locale
            New-InvalidOperationException -Message $errorMessage -Error $_
        }
    }
}

function Test-TargetResource
{
    <#
    .SYNOPSIS
        Test-TargetResource

    .NOTES
        Used Cmdlets/Functions:

        Name                          | Module
        ------------------------------|------------------
        Compare-ResourcePropertyState | AdfsDsc.Common
    #>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', "",
        Justification = 'False positive on UpdatePasswordPageDescriptionText')]
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $FederationServiceName,

        [Parameter(Mandatory = $true)]
        [System.String]
        $Locale,

        [Parameter()]
        [System.String]
        $CompanyName,

        [Parameter()]
        [System.String]
        $HelpDeskLink,

        [Parameter()]
        [System.String]
        $HelpDeskLinkText,

        [Parameter()]
        [System.String]
        $HomeLink,

        [Parameter()]
        [System.String]
        $HomeLinkText,

        [Parameter()]
        [System.String]
        $HomeRealmDiscoveryOtherOrganizationDescriptionText,

        [Parameter()]
        [System.String]
        $HomeRealmDiscoveryPageDescriptionText,

        [Parameter()]
        [System.String]
        $OrganizationalNameDescriptionText,

        [Parameter()]
        [System.String]
        $PrivacyLink,

        [Parameter()]
        [System.String]
        $PrivacyLinkText,

        [Parameter()]
        [System.String]
        $CertificatePageDescriptionText,

        [Parameter()]
        [System.String]
        $SignInPageDescriptionText,

        [Parameter()]
        [System.String]
        $SignOutPageDescriptionText,

        [Parameter()]
        [System.String]
        $ErrorPageDescriptionText,

        [Parameter()]
        [System.String]
        $ErrorPageGenericErrorMessage,

        [Parameter()]
        [System.String]
        $ErrorPageAuthorizationErrorMessage,

        [Parameter()]
        [System.String]
        $ErrorPageDeviceAuthenticationErrorMessage,

        [Parameter()]
        [System.String]
        $ErrorPageSupportEmail,

        [Parameter()]
        [System.String]
        $UpdatePasswordPageDescriptionText,

        [Parameter()]
        [System.String]
        $SignInPageAdditionalAuthenticationDescriptionText
    )

    # Set Verbose and Debug parameters
    $commonParms = @{
        Verbose = $VerbosePreference
        Debug   = $DebugPreference
    }

    Write-Verbose -Message ($script:localizedData.TestingResourceMessage -f $FederationServiceName, $Locale)

    $getTargetResourceParms = @{
        FederationServiceName = $FederationServiceName
        Locale                = $Locale
    }
    $targetResource = Get-TargetResource @getTargetResourceParms

    $propertiesNotInDesiredState = (
        Compare-ResourcePropertyState -CurrentValues $targetResource -DesiredValues $PSBoundParameters `
            @commonParms | Where-Object -Property InDesiredState -eq $false)

    if ($propertiesNotInDesiredState)
    {
        # Resource is not in desired state
        Write-Verbose -Message ($script:localizedData.ResourceNotInDesiredStateMessage -f
            $FederationServiceName, $Locale)

        $inDesiredState = $false
    }
    else
    {
        # Resource is in desired state
        Write-Verbose -Message ($script:localizedData.ResourceInDesiredStateMessage -f $FederationServiceName, $Locale)

        $inDesiredState = $true
    }

    $inDesiredState
}

Export-ModuleMember -Function *-TargetResource
