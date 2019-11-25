$Global:DSCModuleName = 'AdfsDsc'
$Global:PSModuleName = 'ADFS'
$Global:DSCResourceName = 'MSFT_AdfsOrganization'

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
            Get = 'Get-AdfsProperties'
            Set = 'Set-AdfsProperties'
        }

        $mockResource = @{
            FederationServiceName = 'sts.contoso.com'
            DisplayName           = 'Contoso Inc.'
            Name                  = 'Contoso'
            OrganizationUrl       = 'https://www.contoso.com'
        }

        $mockChangedResource = @{
            DisplayName     = 'Fabrikam Inc.'
            Name            = 'Fabrikam'
            OrganizationUrl = 'https://www.fabrikam.com'
        }

        $mockGetTargetResourceResult = @{
            FederationServiceName = $mockResource.FederationServiceName
            DisplayName           = $mockResource.DisplayName
            Name                  = $mockResource.Name
            OrganizationUrl       = $mockResource.OrganizationUrl
        }

        Describe 'MSFT_AdfsOrganization\Get-TargetResource' -Tag 'Get' {
            BeforeAll {
                $getTargetResourceParameters = @{
                    FederationServiceName = $mockResource.FederationServiceName
                    DisplayName           = $mockResource.DisplayName
                    Name                  = $mockResource.Name
                    OrganizationUrl       = $mockResource.OrganizationUrl
                }

                $mockGetResourceCommandResult = @{
                    OrganizationInfo = @{
                        DisplayName     = $mockResource.DisplayName
                        Name            = $mockResource.Name
                        OrganizationUrl = $mockResource.OrganizationUrl
                    }
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
                        $script:localizedData.GettingResourceErrorMessage -f $getTargetResourceParameters.FederationServiceName )
                }
            }
        }

        Describe 'MSFT_AdfsOrganization\Set-TargetResource' -Tag 'Set' {
            BeforeAll {
                $setTargetResourceParameters = @{
                    FederationServiceName = $mockResource.FederationServiceName
                    DisplayName           = $mockResource.DisplayName
                    Name                  = $mockResource.Name
                    OrganizationUrl       = $mockResource.OrganizationUrl
                }

                Mock -CommandName $ResourceCommand.Set
                Mock -CommandName New-AdfsOrganization -MockWith { New-MockObject -Type Microsoft.IdentityServer.Management.Resources.Organization }
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
                        Assert-MockCalled -CommandName New-AdfsOrganization -Exactly -Times 1
                    }
                }
            }

            Context 'When New-AdfsOrganization throws an exception' {
                BeforeAll {
                    Mock -CommandName New-AdfsOrganization -MockWith { Throw 'Error' }
                }

                It 'Should throw the correct exception' {
                    { Set-TargetResource @setTargetResourceParameters } | Should -Throw (
                        $script:localizedData.NewAdfsOrganizationErrorMessage -f $setTargetResourceParameters.FederationServiceName )
                }
            }

            Context "When $($ResourceCommand.Set) throws an exception" {
                BeforeAll {
                    Mock -CommandName $ResourceCommand.Set -MockWith { Throw 'Error' }
                }

                It 'Should throw the correct exception' {
                    { Set-TargetResource @setTargetResourceParameters } | Should -Throw (
                        $script:localizedData.SettingResourceErrorMessage -f $setTargetResourceParameters.FederationServiceName )
                }
            }
        }

        Describe 'MSFT_AdfsOrganization\Test-TargetResource' -Tag 'Test' {
            BeforeAll {
                $testTargetResourceParameters = @{
                    FederationServiceName = $mockResource.FederationServiceName
                    DisplayName           = $mockResource.DisplayName
                    Name                  = $mockResource.Name
                    OrganizationUrl       = $mockResource.OrganizationUrl
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
