$Global:DSCModuleName = 'AdfsDsc'
$Global:PSModuleName = 'ADFS'
$Global:DSCResourceName = 'MSFT_AdfsGlobalWebContent'

$moduleRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $Script:MyInvocation.MyCommand.Path))
if ( (-not (Test-Path -Path (Join-Path -Path $moduleRoot -ChildPath 'DSCResource.Tests'))) -or `
    (-not (Test-Path -Path (Join-Path -Path $moduleRoot -ChildPath 'DSCResource.Tests\TestHelper.psm1'))) )
{
    & git @('clone', 'https://github.com/PowerShell/DscResource.Tests.git',
        (Join-Path -Path $moduleRoot -ChildPath '\DSCResource.Tests\'))
}

Import-Module (Join-Path -Path $moduleRoot -ChildPath 'DSCResource.Tests\TestHelper.psm1') -Force

$TestEnvironment = Initialize-TestEnvironment `
    -DSCModuleName $Global:DSCModuleName `
    -DSCResourceName $Global:DSCResourceName `
    -TestType Unit

try
{
    InModuleScope $Global:DSCResourceName {
        # Import Stub Module
        Import-Module (Join-Path -Path $PSScriptRoot -ChildPath "Stubs\$($Global:PSModuleName)Stub.psm1") -Force

        # Define Resource Commands
        $ResourceCommand = @{
            Get = 'Get-AdfsGlobalWebContent'
            Set = 'Set-AdfsGlobalWebContent'
        }

        $mockResource = @{
            FederationServiceName                              = 'sts.contoso.com'
            Locale                                             = 'en-US'
            CompanyName                                        = 'Contoso'
            HelpDeskLink                                       = 'https://www.contoso.com/helpdesk'
            HelpDeskLinkText                                   = 'Contoso Helpdesk'
            HomeLink                                           = 'https://www.contoso.com'
            HomeLinkText                                       = 'Contoso home'
            HomeRealmDiscoveryOtherOrganizationDescriptionText = 'Contoso Home Realm Other Organization'
            HomeRealmDiscoveryPageDescriptionText              = 'Contoso Home Realm'
            OrganizationalNameDescriptionText                  = 'Contoso Company'
            PrivacyLink                                        = 'https://www.contoso.com/privacy'
            PrivacyLinkText                                    = 'Contoso Privacy Policy'
            CertificatePageDescriptionText                     = 'Contoso Certificate'
            SignInPageDescriptionText                          = 'Contoso Signin'
            SignOutPageDescriptionText                         = 'Contoso Signout'
            ErrorPageDescriptionText                           = 'Contoso Error'
            ErrorPageGenericErrorMessage                       = 'Contoso Generic Error'
            ErrorPageAuthorizationErrorMessage                 = 'Contoso Authorization Error'
            ErrorPageDeviceAuthenticationErrorMessage          = 'Contoso Device Authentication Error'
            ErrorPageSupportEmail                              = 'support@contoso.com'
            UpdatePasswordPageDescriptionText                  = 'Contoso Update Password'
            SignInPageAdditionalAuthenticationDescriptionText  = 'Contoso Additional Sign In'
        }

        $mockChangedResource = @{
            CompanyName                                        = 'Fabrikam'
            HelpDeskLink                                       = 'https://www.fabrikam.com/helpdesk'
            HelpDeskLinkText                                   = 'Fabrikam Helpdesk'
            HomeLink                                           = 'https://www.fabrikam.com'
            HomeLinkText                                       = 'Fabrikam home'
            HomeRealmDiscoveryOtherOrganizationDescriptionText = 'Fabrikam Home Realm Other Organization'
            HomeRealmDiscoveryPageDescriptionText              = 'Fabrikam Home Realm'
            OrganizationalNameDescriptionText                  = 'Fabrikam Company'
            PrivacyLink                                        = 'https://www.fabrikam.com/privacy'
            PrivacyLinkText                                    = 'Fabrikam Privacy Policy'
            CertificatePageDescriptionText                     = 'Fabrikam Certificate'
            SignInPageDescriptionText                          = 'Fabrikam Signin'
            SignOutPageDescriptionText                         = 'Fabrikam Signout'
            ErrorPageDescriptionText                           = 'Fabrikam Error'
            ErrorPageGenericErrorMessage                       = 'Fabrikam Generic Error'
            ErrorPageAuthorizationErrorMessage                 = 'Fabrikam Authorization Error'
            ErrorPageDeviceAuthenticationErrorMessage          = 'Fabrikam Device Authentication Error'
            ErrorPageSupportEmail                              = 'support@fabrikam.com'
            UpdatePasswordPageDescriptionText                  = 'Fabrikam Update Password'
            SignInPageAdditionalAuthenticationDescriptionText  = 'Fabrikam Additional Sign In'
        }

        $mockGetTargetResourceResult = @{
            FederationServiceName                              = $mockResource.FederationServiceName
            Locale                                             = $mockResource.Locale
            CompanyName                                        = $mockResource.CompanyName
            HelpDeskLink                                       = $mockResource.HelpDeskLink
            HelpDeskLinkText                                   = $mockResource.HelpDeskLinkText
            HomeLink                                           = $mockResource.HomeLink
            HomeLinkText                                       = $mockResource.HomeLinkText
            HomeRealmDiscoveryOtherOrganizationDescriptionText = $mockResource.HomeRealmDiscoveryOtherOrganizationDescriptionText
            HomeRealmDiscoveryPageDescriptionText              = $mockResource.HomeRealmDiscoveryPageDescriptionText
            OrganizationalNameDescriptionText                  = $mockResource.OrganizationalNameDescriptionText
            PrivacyLink                                        = $mockResource.PrivacyLink
            PrivacyLinkText                                    = $mockResource.PrivacyLinkText
            CertificatePageDescriptionText                     = $mockResource.CertificatePageDescriptionText
            SignInPageDescriptionText                          = $mockResource.SignInPageDescriptionText
            SignOutPageDescriptionText                         = $mockResource.SignOutPageDescriptionText
            ErrorPageDescriptionText                           = $mockResource.ErrorPageDescriptionText
            ErrorPageGenericErrorMessage                       = $mockResource.ErrorPageGenericErrorMessage
            ErrorPageAuthorizationErrorMessage                 = $mockResource.ErrorPageAuthorizationErrorMessage
            ErrorPageDeviceAuthenticationErrorMessage          = $mockResource.ErrorPageDeviceAuthenticationErrorMessage
            ErrorPageSupportEmail                              = $mockResource.ErrorPageSupportEmail
            UpdatePasswordPageDescriptionText                  = $mockResource.UpdatePasswordPageDescriptionText
            SignInPageAdditionalAuthenticationDescriptionText  = $mockResource.SignInPageAdditionalAuthenticationDescriptionText
        }

        Describe 'MSFT_AdfsGlobalWebContent\Get-TargetResource' -Tag 'Get' {
            BeforeAll {
                $getTargetResourceParameters = @{
                    FederationServiceName = $mockResource.FederationServiceName
                    Locale                = $mockResource.Locale
                }

                $mockGetResourceCommandResult = @{
                    CompanyName                                        = $mockResource.CompanyName
                    HelpDeskLink                                       = $mockResource.HelpDeskLink
                    HelpDeskLinkText                                   = $mockResource.HelpDeskLinkText
                    HomeLink                                           = $mockResource.HomeLink
                    HomeLinkText                                       = $mockResource.HomeLinkText
                    HomeRealmDiscoveryOtherOrganizationDescriptionText = $mockResource.HomeRealmDiscoveryOtherOrganizationDescriptionText
                    HomeRealmDiscoveryPageDescriptionText              = $mockResource.HomeRealmDiscoveryPageDescriptionText
                    OrganizationalNameDescriptionText                  = $mockResource.OrganizationalNameDescriptionText
                    PrivacyLink                                        = $mockResource.PrivacyLink
                    PrivacyLinkText                                    = $mockResource.PrivacyLinkText
                    CertificatePageDescriptionText                     = $mockResource.CertificatePageDescriptionText
                    SignInPageDescriptionText                          = $mockResource.SignInPageDescriptionText
                    SignOutPageDescriptionText                         = $mockResource.SignOutPageDescriptionText
                    ErrorPageDescriptionText                           = $mockResource.ErrorPageDescriptionText
                    ErrorPageGenericErrorMessage                       = $mockResource.ErrorPageGenericErrorMessage
                    ErrorPageAuthorizationErrorMessage                 = $mockResource.ErrorPageAuthorizationErrorMessage
                    ErrorPageDeviceAuthenticationErrorMessage          = $mockResource.ErrorPageDeviceAuthenticationErrorMessage
                    ErrorPageSupportEmail                              = $mockResource.ErrorPageSupportEmail
                    UpdatePasswordPageDescriptionText                  = $mockResource.UpdatePasswordPageDescriptionText
                    SignInPageAdditionalAuthenticationDescriptionText  = $mockResource.SignInPageAdditionalAuthenticationDescriptionText
                }

                Mock -CommandName Assert-Module
                Mock -CommandName "Assert-$($Global:PSModuleName)Service"
                Mock -CommandName $ResourceCommand.Get -MockWith { $mockGetResourceCommandResult }

                $result = Get-TargetResource @getTargetResourceParameters
            }

            foreach ($property in $mockResource.Keys)
            {
                It "Should return the correct $property property" {
                    $result.$property | Should -Be $mockResource.$property
                }
            }

            It 'Should call the expected mocks' {
                Assert-MockCalled -CommandName Assert-Module `
                    -ParameterFilter { $ModuleName -eq $Global:PSModuleName } `
                    -Exactly -Times 1
                Assert-MockCalled -CommandName "Assert-$($Global:PSModuleName)Service" -Exactly -Times 1
                Assert-MockCalled -CommandName $ResourceCommand.Get -Exactly -Times 1
            }

            Context "When $($ResourceCommand.Get) throws an exception" {
                BeforeAll {
                    Mock -CommandName $ResourceCommand.Get -MockWith { Throw 'Error' }
                }

                It 'Should throw the correct exception' {
                    { Get-TargetResource @getTargetResourceParameters } | Should -Throw (
                        $script:localizedData.GettingResourceErrorMessage -f
                        $getTargetResourceParameters.FederationServiceName, $getTargetResourceParameters.Locale )
                }
            }
        }

        Describe 'MSFT_AdfsGlobalWebContent\Set-TargetResource' -Tag 'Set' {
            BeforeAll {
                $setTargetResourceParameters = @{
                    FederationServiceName                              = $mockResource.FederationServiceName
                    Locale                                             = $mockResource.Locale
                    CompanyName                                        = $mockChangedResource.CompanyName
                    HelpDeskLink                                       = $mockChangedResource.HelpDeskLink
                    HelpDeskLinkText                                   = $mockChangedResource.HelpDeskLinkText
                    HomeLink                                           = $mockChangedResource.HomeLink
                    HomeLinkText                                       = $mockChangedResource.HomeLinkText
                    HomeRealmDiscoveryOtherOrganizationDescriptionText = $mockChangedResource.HomeRealmDiscoveryOtherOrganizationDescriptionText
                    HomeRealmDiscoveryPageDescriptionText              = $mockChangedResource.HomeRealmDiscoveryPageDescriptionText
                    OrganizationalNameDescriptionText                  = $mockChangedResource.OrganizationalNameDescriptionText
                    PrivacyLink                                        = $mockChangedResource.PrivacyLink
                    PrivacyLinkText                                    = $mockChangedResource.PrivacyLinkText
                    CertificatePageDescriptionText                     = $mockChangedResource.CertificatePageDescriptionText
                    SignInPageDescriptionText                          = $mockChangedResource.SignInPageDescriptionText
                    SignOutPageDescriptionText                         = $mockChangedResource.SignOutPageDescriptionText
                    ErrorPageDescriptionText                           = $mockChangedResource.ErrorPageDescriptionText
                    ErrorPageGenericErrorMessage                       = $mockChangedResource.ErrorPageGenericErrorMessage
                    ErrorPageAuthorizationErrorMessage                 = $mockChangedResource.ErrorPageAuthorizationErrorMessage
                    ErrorPageDeviceAuthenticationErrorMessage          = $mockChangedResource.ErrorPageDeviceAuthenticationErrorMessage
                    ErrorPageSupportEmail                              = $mockChangedResource.ErrorPageSupportEmail
                    UpdatePasswordPageDescriptionText                  = $mockChangedResource.UpdatePasswordPageDescriptionText
                    SignInPageAdditionalAuthenticationDescriptionText  = $mockChangedResource.SignInPageAdditionalAuthenticationDescriptionText
                }

                Mock -CommandName $ResourceCommand.Set
                Mock -CommandName Get-TargetResource -MockWith { $mockGetTargetResourceResult }
            }

            foreach ($property in $mockChangedResource.Keys)
            {
                Context "When $property has changed" {
                    BeforeAll {
                        $setTargetResourceParametersChangedProperty = $setTargetResourceParameters.Clone()
                        $setTargetResourceParametersChangedProperty.$property = $mockChangedResource.$property
                    }

                    It 'Should not throw' {
                        { Set-TargetResource @setTargetResourceParametersChangedProperty } | Should -Not -Throw
                    }

                    It 'Should call the correct mocks' {
                        Assert-MockCalled -CommandName Get-TargetResource `
                            -ParameterFilter { `
                                $FederationServiceName -eq $setTargetResourceParametersChangedProperty.FederationServiceName } `
                            -Exactly -Times 1
                        Assert-MockCalled -CommandName $ResourceCommand.Set -Exactly -Times 1
                    }
                }
            }

            Context "When $($ResourceCommand.Set) throws an exception" {
                BeforeAll {
                    Mock -CommandName $ResourceCommand.Set -MockWith { Throw 'Error' }
                }

                It 'Should throw the correct exception' {
                    { Set-TargetResource @setTargetResourceParameters } | Should -Throw (
                        $script:localizedData.SettingResourceErrorMessage -f
                        $setTargetResourceParameters.FederationServiceName, $setTargetResourceParameters.Locale )
                }
            }
        }

        Describe 'MSFT_AdfsGlobalWebContent\Test-TargetResource' -Tag 'Test' {
            BeforeAll {
                $testTargetResourceParameters = @{
                    FederationServiceName                              = $mockResource.FederationServiceName
                    Locale                                             = $mockResource.Locale
                    CompanyName                                        = $mockResource.CompanyName
                    HelpDeskLink                                       = $mockResource.HelpDeskLink
                    HelpDeskLinkText                                   = $mockResource.HelpDeskLinkText
                    HomeLink                                           = $mockResource.HomeLink
                    HomeLinkText                                       = $mockResource.HomeLinkText
                    HomeRealmDiscoveryOtherOrganizationDescriptionText = $mockResource.HomeRealmDiscoveryOtherOrganizationDescriptionText
                    HomeRealmDiscoveryPageDescriptionText              = $mockResource.HomeRealmDiscoveryPageDescriptionText
                    OrganizationalNameDescriptionText                  = $mockResource.OrganizationalNameDescriptionText
                    PrivacyLink                                        = $mockResource.PrivacyLink
                    PrivacyLinkText                                    = $mockResource.PrivacyLinkText
                    CertificatePageDescriptionText                     = $mockResource.CertificatePageDescriptionText
                    SignInPageDescriptionText                          = $mockResource.SignInPageDescriptionText
                    SignOutPageDescriptionText                         = $mockResource.SignOutPageDescriptionText
                    ErrorPageDescriptionText                           = $mockResource.ErrorPageDescriptionText
                    ErrorPageGenericErrorMessage                       = $mockResource.ErrorPageGenericErrorMessage
                    ErrorPageAuthorizationErrorMessage                 = $mockResource.ErrorPageAuthorizationErrorMessage
                    ErrorPageDeviceAuthenticationErrorMessage          = $mockResource.ErrorPageDeviceAuthenticationErrorMessage
                    ErrorPageSupportEmail                              = $mockResource.ErrorPageSupportEmail
                    UpdatePasswordPageDescriptionText                  = $mockResource.UpdatePasswordPageDescriptionText
                    SignInPageAdditionalAuthenticationDescriptionText  = $mockResource.SignInPageAdditionalAuthenticationDescriptionText
                }

                Mock -CommandName Get-TargetResource -MockWith { $mockGetTargetResourceResult }
            }

            It 'Should not throw' {
                { Test-TargetResource @testTargetResourceParameters } | Should -Not -Throw
            }

            It 'Should call the expected mocks' {
                Assert-MockCalled -CommandName Get-TargetResource `
                    -ParameterFilter { $FederationServiceName -eq $testTargetResourceParameters.FederationServiceName } `
                    -Exactly -Times 1
            }

            Context 'When all the resource properties are in the desired state' {
                It 'Should return $true' {
                    Test-TargetResource @testTargetResourceParameters | Should -Be $true
                }
            }

            foreach ($property in $mockChangedResource.Keys)
            {
                Context "When the $property resource property is not in the desired state" {
                    BeforeAll {
                        $testTargetResourceNotInDesiredStateParameters = $testTargetResourceParameters.Clone()
                        $testTargetResourceNotInDesiredStateParameters.$property = $mockChangedResource.$property
                    }

                    It 'Should return $false' {
                        Test-TargetResource @testTargetResourceNotInDesiredStateParameters | Should -Be $false
                    }
                }
            }
        }
    }
}
finally
{
    Restore-TestEnvironment -TestEnvironment $TestEnvironment
}
