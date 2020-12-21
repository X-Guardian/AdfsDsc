$script:dscModuleName = 'AdfsDsc'
$global:psModuleName = 'ADFS'
$script:dscResourceName = 'MSFT_AdfsGlobalAuthenticationPolicy'

function Invoke-TestSetup
{
    try
    {
        Import-Module -Name DscResource.Test -Force -ErrorAction 'Stop'
    }
    catch [System.IO.FileNotFoundException]
    {
        throw 'DscResource.Test module dependency not found. Please run ".\build.ps1 -Tasks build" first.'
    }

    $script:testEnvironment = Initialize-TestEnvironment `
        -DSCModuleName $script:dscModuleName `
        -DSCResourceName $script:dscResourceName `
        -ResourceType 'Mof' `
        -TestType 'Unit'
}

function Invoke-TestCleanup
{
    Restore-TestEnvironment -TestEnvironment $script:testEnvironment
}

# Begin Testing

Invoke-TestSetup

try
{
    InModuleScope $script:dscResourceName {
        Set-StrictMode -Version 2.0

        # Import Stub Module
        Import-Module (Join-Path -Path $PSScriptRoot -ChildPath "Stubs\$($global:psModuleName)Stub.psm1") -Force

        # Define Resource Commands
        $ResourceCommand = @{
            Get = 'Get-AdfsGlobalAuthenticationPolicy'
            Set = 'Set-AdfsGlobalAuthenticationPolicy'
        }

        $mockResource = @{
            FederationServiceName                  = 'sts.contoso.com'
            AdditionalAuthenticationProvider       = 'AdditionalAuthentication'
            AllowAdditionalAuthenticationAsPrimary = $true
            ClientAuthenticationMethods            = 'ClientSecretPostAuthentication'
            EnablePaginatedAuthenticationPages     = $true
            DeviceAuthenticationEnabled            = $true
            DeviceAuthenticationMethod             = 'All'
            PrimaryExtranetAuthenticationProvider  = 'FormsAuthentication'
            PrimaryIntranetAuthenticationProvider  = 'WindowsAuthentication', 'FormsAuthentication', 'MicrosoftPassportAuthentication'
            WindowsIntegratedFallbackEnabled       = $true
        }

        $mockChangedResource = @{
            AdditionalAuthenticationProvider       = 'AnotherAdditionalAuthentication'
            AllowAdditionalAuthenticationAsPrimary = $false
            ClientAuthenticationMethods            = 'ClientSecretBasicAuthentication'
            EnablePaginatedAuthenticationPages     = $false
            DeviceAuthenticationEnabled            = $false
            DeviceAuthenticationMethod             = 'ClientTLS'
            PrimaryExtranetAuthenticationProvider  = 'WindowsAuthentication'
            PrimaryIntranetAuthenticationProvider  = 'FormsAuthentication'
            WindowsIntegratedFallbackEnabled       = $false
        }

        $mockGetTargetResourceResult = @{
            FederationServiceName                  = $mockResource.FederationServiceName
            AdditionalAuthenticationProvider       = $mockResource.AdditionalAuthenticationProvider
            AllowAdditionalAuthenticationAsPrimary = $mockResource.AllowAdditionalAuthenticationAsPrimary
            ClientAuthenticationMethods            = $mockResource.ClientAuthenticationMethods
            EnablePaginatedAuthenticationPages     = $mockResource.EnablePaginatedAuthenticationPages
            DeviceAuthenticationEnabled            = $mockResource.DeviceAuthenticationEnabled
            DeviceAuthenticationMethod             = $mockResource.DeviceAuthenticationMethod
            PrimaryExtranetAuthenticationProvider  = $mockResource.PrimaryExtranetAuthenticationProvider
            PrimaryIntranetAuthenticationProvider  = $mockResource.PrimaryIntranetAuthenticationProvider
            WindowsIntegratedFallbackEnabled       = $mockResource.WindowsIntegratedFallbackEnabled
        }

        Describe 'MSFT_AdfsGlobalAuthenticationPolicy\Get-TargetResource' -Tag 'Get' {
            BeforeAll {
                $getTargetResourceParameters = @{
                    FederationServiceName = $mockResource.FederationServiceName
                }

                $mockGetResourceCommandResult = @{
                    AdditionalAuthenticationProvider       = $mockResource.AdditionalAuthenticationProvider
                    AllowAdditionalAuthenticationAsPrimary = $mockResource.AllowAdditionalAuthenticationAsPrimary
                    ClientAuthenticationMethods            = $mockResource.ClientAuthenticationMethods
                    EnablePaginatedAuthenticationPages     = $mockResource.EnablePaginatedAuthenticationPages
                    DeviceAuthenticationEnabled            = $mockResource.DeviceAuthenticationEnabled
                    DeviceAuthenticationMethod             = $mockResource.DeviceAuthenticationMethod
                    PrimaryExtranetAuthenticationProvider  = $mockResource.PrimaryExtranetAuthenticationProvider
                    PrimaryIntranetAuthenticationProvider  = $mockResource.PrimaryIntranetAuthenticationProvider
                    WindowsIntegratedFallbackEnabled       = $mockResource.WindowsIntegratedFallbackEnabled
                }

                Mock -CommandName Assert-Module
                Mock -CommandName "Assert-$($global:psModuleName)Service"
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
                    -ParameterFilter { $ModuleName -eq $global:psModuleName } `
                    -Exactly -Times 1
                Assert-MockCalled -CommandName "Assert-$($global:psModuleName)Service" -Exactly -Times 1
                Assert-MockCalled -CommandName $ResourceCommand.Get -Exactly -Times 1
            }

            Context "When $($ResourceCommand.Get) throws an exception" {
                BeforeAll {
                    Mock -CommandName $ResourceCommand.Get -MockWith { Throw 'Error' }
                }

                It 'Should throw the correct exception' {
                    { Get-TargetResource @getTargetResourceParameters } | Should -Throw (
                        $script:localizedData.GettingResourceErrorMessage -f $getTargetResourceParameters.FederationServiceName )
                }
            }
        }

        Describe 'MSFT_AdfsGlobalAuthenticationPolicy\Set-TargetResource' -Tag 'Set' {
            BeforeAll {
                $setTargetResourceParameters = @{
                    FederationServiceName                  = $mockResource.FederationServiceName
                    AdditionalAuthenticationProvider       = $mockResource.AdditionalAuthenticationProvider
                    AllowAdditionalAuthenticationAsPrimary = $mockResource.AllowAdditionalAuthenticationAsPrimary
                    ClientAuthenticationMethods            = $mockResource.ClientAuthenticationMethods
                    EnablePaginatedAuthenticationPages     = $mockResource.EnablePaginatedAuthenticationPages
                    DeviceAuthenticationEnabled            = $mockResource.DeviceAuthenticationEnabled
                    DeviceAuthenticationMethod             = $mockResource.DeviceAuthenticationMethod
                    PrimaryExtranetAuthenticationProvider  = $mockResource.PrimaryExtranetAuthenticationProvider
                    PrimaryIntranetAuthenticationProvider  = $mockResource.PrimaryIntranetAuthenticationProvider
                    WindowsIntegratedFallbackEnabled       = $mockResource.WindowsIntegratedFallbackEnabled
                }

                Mock -CommandName $ResourceCommand.Set
                Mock -CommandName Get-TargetResource -MockWith { $mockGetTargetResourceResult }
            }

            foreach ($property in $mockChangedResource.Keys)
            {
                Context "When $property has changed" {
                    BeforeAll {
                        $setChangedTargetResourceParametersProperty = $setTargetResourceParameters.Clone()
                        $setChangedTargetResourceParametersProperty.$property = $mockChangedResource.$property
                    }

                    It 'Should not throw' {
                        { Set-TargetResource @setChangedTargetResourceParametersProperty } | Should -Not -Throw
                    }

                    It 'Should call the correct mocks' {
                        Assert-MockCalled -CommandName Get-TargetResource `
                            -ParameterFilter { `
                                $FederationServiceName -eq $setChangedTargetResourceParametersProperty.FederationServiceName } `
                            -Exactly -Times 1
                        Assert-MockCalled -CommandName $ResourceCommand.Set -Exactly -Times 1
                    }
                }
            }

            Context "When $($ResourceCommand.Set) throws an exception" {
                BeforeAll {
                    Mock -CommandName $ResourceCommand.Set -MockWith { Throw 'Error' }

                    $setChangedTargetResourceParametersProperty = $setTargetResourceParameters.Clone()
                    $setChangedTargetResourceParametersProperty.AdditionalAuthenticationProvider = $mockChangedResource.AdditionalAuthenticationProvider
                }

                It 'Should throw the correct exception' {
                    { Set-TargetResource @setChangedTargetResourceParametersProperty } | Should -Throw (
                        $script:localizedData.SettingResourceErrorMessage -f
                        $setTargetResourceParameters.FederationServiceName )
                }
            }
        }

        Describe 'MSFT_AdfsGlobalAuthenticationPolicy\Test-TargetResource' -Tag 'Test' {
            BeforeAll {
                $testTargetResourceParameters = @{
                    FederationServiceName                  = $mockResource.FederationServiceName
                    AdditionalAuthenticationProvider       = $mockResource.AdditionalAuthenticationProvider
                    AllowAdditionalAuthenticationAsPrimary = $mockResource.AllowAdditionalAuthenticationAsPrimary
                    ClientAuthenticationMethods            = $mockResource.ClientAuthenticationMethods
                    EnablePaginatedAuthenticationPages     = $mockResource.EnablePaginatedAuthenticationPages
                    DeviceAuthenticationEnabled            = $mockResource.DeviceAuthenticationEnabled
                    DeviceAuthenticationMethod             = $mockResource.DeviceAuthenticationMethod
                    PrimaryExtranetAuthenticationProvider  = $mockResource.PrimaryExtranetAuthenticationProvider
                    PrimaryIntranetAuthenticationProvider  = $mockResource.PrimaryIntranetAuthenticationProvider
                    WindowsIntegratedFallbackEnabled       = $mockResource.WindowsIntegratedFallbackEnabled
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
    Invoke-TestCleanup
}
