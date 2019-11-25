$Global:DSCModuleName = 'AdfsDsc'
$Global:PSModuleName = 'ADFS'
$Global:DSCResourceName = 'MSFT_AdfsClaimDescription'

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
            Get    = 'Get-AdfsClaimDescription'
            Set    = 'Set-AdfsClaimDescription'
            Add    = 'Add-AdfsClaimDescription'
            Remove = 'Remove-AdfsClaimDescription'
        }

        $mockError = 'Error'

        $mockResource = @{
            Name       = 'Role'
            ClaimType  = "https://contoso.com/role"
            IsAccepted = $true
            IsOffered  = $true
            IsRequired = $false
            Notes      = 'The role of the Contoso user'
            ShortName  = 'contosorole'
            Ensure     = 'Present'
        }

        $mockAbsentResource = @{
            Name       = $mockResource.Name
            ClaimType  = $mockResource.ClaimType
            IsAccepted = $false
            IsOffered  = $false
            IsRequired = $false
            Notes      = $null
            ShortName  = $null
            Ensure     = 'Absent'
        }

        $mockChangedResource = @{
            ClaimType  = "https://fabrikam.com/role"
            IsAccepted = $false
            IsOffered  = $false
            IsRequired = $true
            Notes      = 'The role of the Fabrikam user'
            ShortName  = 'fabrikamrole'
        }

        $mockGetTargetResourceResult = @{
            Name       = $mockResource.Name
            ClaimType  = $mockResource.ClaimType
            IsAccepted = $mockResource.IsAccepted
            IsOffered  = $mockResource.IsOffered
            IsRequired = $mockResource.IsRequired
            Notes      = $mockResource.Notes
            ShortName  = $mockResource.ShortName
        }

        $mockGetTargetResourcePresentResult = $mockGetTargetResourceResult.Clone()
        $mockGetTargetResourcePresentResult.Ensure = 'Present'

        $mockGetTargetResourceAbsentResult = $mockGetTargetResourceResult.Clone()
        $mockGetTargetResourceAbsentResult.Ensure = 'Absent'

        Describe 'MSFT_AdfsClaimDescription\Get-TargetResource' -Tag 'Get' {
            BeforeAll {
                $getTargetResourceParameters = @{
                    Name      = $mockResource.Name
                    ClaimType = $mockResource.ClaimType
                }

                $mockGetResourceCommandResult = @{
                    Name       = $mockResource.Name
                    ClaimType  = $mockResource.ClaimType
                    IsAccepted = $mockResource.IsAccepted
                    IsOffered  = $mockResource.IsOffered
                    IsRequired = $mockResource.IsRequired
                    Notes      = $mockResource.Notes
                    ShortName  = $mockResource.ShortName
                }

                Mock -CommandName Assert-Module
                Mock -CommandName "Assert-$($Global:PSModuleName)Service"
            }

            Context 'When the Resource is Present' {
                BeforeAll {
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
                    Assert-MockCalled -CommandName $ResourceCommand.Get `
                        -ParameterFilter { $Name -eq $getTargetResourceParameters.Name } `
                        -Exactly -Times 1
                }
            }

            Context 'When the Resource is Absent' {
                BeforeAll {
                    Mock -CommandName $ResourceCommand.Get

                    $result = Get-TargetResource @getTargetResourceParameters
                }

                foreach ($property in $mockAbsentResource.Keys)
                {
                    It "Should return the correct $property property" {
                        $result.$property | Should -Be $mockAbsentResource.$property
                    }
                }

                It 'Should call the expected mocks' {
                    Assert-MockCalled -CommandName Assert-Module `
                        -ParameterFilter { $ModuleName -eq $Global:PSModuleName } `
                        -Exactly -Times 1
                    Assert-MockCalled -CommandName "Assert-$($Global:PSModuleName)Service" -Exactly -Times 1
                    Assert-MockCalled -CommandName $ResourceCommand.Get `
                        -ParameterFilter { $Name -eq $getTargetResourceParameters.Name } `
                        -Exactly -Times 1
                }
            }

            Context "When $($ResourceCommand.Get) throws an exception" {
                BeforeAll {
                    Mock -CommandName $ResourceCommand.Get -MockWith { throw $mockError }
                }

                It 'Should throw the correct exception' {
                    { Get-TargetResource @getTargetResourceParameters } | `
                        Should -Throw ($script:localizedData.GettingResourceErrorMessage -f
                        $getTargetResourceParameters.Name)
                }
            }
        }

        Describe 'MSFT_AdfsClaimDescription\Set-TargetResource' -Tag 'Set' {
            BeforeAll {
                $setTargetResourceParameters = @{
                    Name       = $mockResource.Name
                    ClaimType  = $mockResource.ClaimType
                    IsAccepted = $mockResource.IsAccepted
                    IsOffered  = $mockResource.IsOffered
                    IsRequired = $mockResource.IsRequired
                    Notes      = $mockResource.Notes
                    ShortName  = $mockResource.ShortName
                }

                $setTargetResourcePresentParameters = $setTargetResourceParameters.Clone()
                $setTargetResourcePresentParameters.Ensure = 'Present'

                $setTargetResourceAbsentParameters = $setTargetResourceParameters.Clone()
                $setTargetResourceAbsentParameters.Ensure = 'Absent'

                Mock -CommandName $ResourceCommand.Set
                Mock -CommandName $ResourceCommand.Add
                Mock -CommandName $ResourceCommand.Remove
            }

            Context 'When the Resource is Present' {
                BeforeAll {
                    Mock -CommandName Get-TargetResource -MockWith { $mockGetTargetResourcePresentResult }
                }

                Context 'When the Resource should be Present' {
                    foreach ($property in $mockChangedResource.Keys)
                    {
                        Context "When $property has changed" {
                            BeforeAll {
                                $setTargetResourceParametersChangedProperty = $setTargetResourcePresentParameters.Clone()
                                $setTargetResourceParametersChangedProperty.$property = $mockChangedResource.$property
                            }

                            It 'Should not throw' {
                                { Set-TargetResource @setTargetResourceParametersChangedProperty } | Should -Not -Throw
                            }

                            It 'Should call the correct mocks' {
                                Assert-MockCalled -CommandName Get-TargetResource `
                                    -ParameterFilter { `
                                        $Name -eq $setTargetResourceParametersChangedProperty.Name -and `
                                        $ClaimType -eq $setTargetResourceParametersChangedProperty.ClaimType } `
                                    -Exactly -Times 1
                                Assert-MockCalled -CommandName $ResourceCommand.Set `
                                    -ParameterFilter { $TargetName -eq $setTargetResourceParametersChangedProperty.Name } `
                                    -Exactly -Times 1
                                Assert-MockCalled -CommandName $ResourceCommand.Add -Exactly -Times 0
                                Assert-MockCalled -CommandName $ResourceCommand.Remove -Exactly -Times 0
                            }
                        }
                    }

                    Context "When $($ResourceCommand.Set) throws an exception" {
                        BeforeAll {
                            $setTargetResourceParametersChangedProperty = $setTargetResourcePresentParameters.Clone()
                            $setTargetResourceParametersChangedProperty.ClaimType = $mockChangedResource.ClaimType

                            Mock -CommandName $ResourceCommand.Set -MockWith { throw $mockError }
                        }

                        It 'Should throw the correct exception' {
                            { Set-TargetResource @setTargetResourceParametersChangedProperty } | `
                                Should -Throw ($script:localizedData.SettingResourceErrorMessage -f
                                $setTargetResourceParametersChangedProperty.Name)
                        }
                    }
                }

                Context 'When the Resource should be Absent' {
                    It 'Should not throw' {
                        { Set-TargetResource @setTargetResourceAbsentParameters } | Should -Not -Throw
                    }

                    It 'Should call the expected mocks' {
                        Assert-MockCalled -CommandName Get-TargetResource `
                            -ParameterFilter { `
                                $Name -eq $setTargetResourceAbsentParameters.Name -and `
                                $ClaimType -eq $setTargetResourceAbsentParameters.ClaimType } `
                            -Exactly -Times 1
                        Assert-MockCalled -CommandName $ResourceCommand.Remove `
                            -ParameterFilter { $TargetName -eq $setTargetResourceAbsentParameters.Name } `
                            -Exactly -Times 1
                        Assert-MockCalled -CommandName $ResourceCommand.Set -Exactly -Times 0
                        Assert-MockCalled -CommandName $ResourceCommand.Add -Exactly -Times 0
                    }

                    Context "When $($ResourceCommand.Remove) throws an exception" {
                        BeforeAll {
                            Mock -CommandName $ResourceCommand.Remove -MockWith { throw $mockError }
                        }

                        It 'Should throw the correct exception' {
                            { Set-TargetResource @setTargetResourceAbsentParameters } | `
                                Should -Throw ($script:localizedData.RemovingResourceErrorMessage -f
                                $setTargetResourceAbsentParameters.Name)
                        }
                    }
                }
            }

            Context 'When the Resource is Absent' {
                BeforeAll {
                    Mock -CommandName Get-TargetResource -MockWith { $mockGetTargetResourceAbsentResult }
                }

                Context 'When the Resource should be Present' {
                    It 'Should not throw' {
                        { Set-TargetResource @setTargetResourcePresentParameters } | Should -Not -Throw
                    }

                    It 'Should call the expected mocks' {
                        Assert-MockCalled -CommandName Get-TargetResource `
                            -ParameterFilter { `
                                $Name -eq $setTargetResourcePresentParameters.Name -and `
                                $ClaimType -eq $setTargetResourcePresentParameters.ClaimType } `
                            -Exactly -Times 1
                        Assert-MockCalled -CommandName $ResourceCommand.Add `
                            -ParameterFilter { `
                                $Name -eq $setTargetResourcePresentParameters.Name -and `
                                $ClaimType -eq $setTargetResourcePresentParameters.ClaimType } `
                            -Exactly -Times 1
                        Assert-MockCalled -CommandName $ResourceCommand.Set -Exactly -Times 0
                        Assert-MockCalled -CommandName $ResourceCommand.Remove -Exactly -Times 0
                    }

                    Context "When $($ResourceCommand.Add) throws an exception" {
                        BeforeAll {
                            Mock -CommandName $ResourceCommand.Add -MockWith { throw $mockError }
                        }

                        It 'Should throw the correct exception' {
                            { Set-TargetResource @setTargetResourcePresentParameters } | `
                                Should -Throw ($script:localizedData.AddingResourceErrorMessage -f
                                $setTargetResourcePresentParameters.Name)
                        }
                    }
                }

                Context 'When the Resource should be Absent' {
                    It 'Should not throw' {
                        { Set-TargetResource @setTargetResourceAbsentParameters } | Should -Not -Throw
                    }

                    It 'Should call the expected mocks' {
                        Assert-MockCalled -CommandName Get-TargetResource `
                            -ParameterFilter { `
                                $Name -eq $setTargetResourceAbsentParameters.Name -and `
                                $ClaimType -eq $setTargetResourceAbsentParameters.ClaimType } `
                            -Exactly -Times 1
                        Assert-MockCalled -CommandName $ResourceCommand.Remove -Exactly -Times 0
                        Assert-MockCalled -CommandName $ResourceCommand.Add -Exactly -Times 0
                        Assert-MockCalled -CommandName $ResourceCommand.Set -Exactly -Times 0
                    }
                }
            }
        }

        Describe 'MSFT_AdfsClaimDescription\Test-TargetResource' -Tag 'Test' {
            BeforeAll {
                $testTargetResourceParameters = @{
                    Name       = $mockResource.Name
                    ClaimType  = $mockResource.ClaimType
                    IsAccepted = $mockResource.IsAccepted
                    IsOffered  = $mockResource.IsOffered
                    IsRequired = $mockResource.IsRequired
                    Notes      = $mockResource.Notes
                    ShortName  = $mockResource.ShortName
                }

                $testTargetResourcePresentParameters = $testTargetResourceParameters.Clone()
                $testTargetResourcePresentParameters.Ensure = 'Present'

                $testTargetResourceAbsentParameters = $testTargetResourceParameters.Clone()
                $testTargetResourceAbsentParameters.Ensure = 'Absent'
            }

            Context 'When the Resource is Present' {
                BeforeAll {
                    Mock -CommandName Get-TargetResource -MockWith { $mockGetTargetResourcePresentResult }
                }

                Context 'When the Resource should be Present' {
                    It 'Should not throw' {
                        { Test-TargetResource @testTargetResourcePresentParameters } | Should -Not -Throw
                    }

                    It 'Should call the expected mocks' {
                        Assert-MockCalled -CommandName Get-TargetResource `
                            -ParameterFilter { `
                                $Name -eq $testTargetResourcePresentParameters.Name -and `
                                $ClaimType -eq $testTargetResourcePresentParameters.ClaimType } `
                            -Exactly -Times 1
                    }

                    Context 'When all the resource properties are in the desired state' {
                        It 'Should return $true' {
                            Test-TargetResource @testTargetResourcePresentParameters | Should -Be $true
                        }
                    }

                    foreach ($property in $mockChangedResource.Keys)
                    {
                        Context "When the $property resource property is not in the desired state" {
                            BeforeAll {
                                $testTargetResourceNotInDesiredStateParameters = $testTargetResourcePresentParameters.Clone()
                                $testTargetResourceNotInDesiredStateParameters.$property = $mockChangedResource.$property
                            }

                            It 'Should return $false' {
                                Test-TargetResource @testTargetResourceNotInDesiredStateParameters | Should -Be $false
                            }
                        }
                    }
                }

                Context 'When the Resource should be Absent' {
                    It 'Should not throw' {
                        { Test-TargetResource @testTargetResourceAbsentParameters } | Should -Not -Throw
                    }

                    It 'Should call the expected mocks' {
                        Assert-MockCalled -CommandName Get-TargetResource `
                            -ParameterFilter { `
                                $Name -eq $testTargetResourceAbsentParameters.Name -and `
                                $ClaimType -eq $testTargetResourceAbsentParameters.ClaimType } `
                            -Exactly -Times 1
                    }

                    It 'Should return $false' {
                        Test-TargetResource @testTargetResourceAbsentParameters | Should -Be $false
                    }
                }
            }

            Context 'When the Resource is Absent' {
                BeforeAll {
                    Mock -CommandName Get-TargetResource -MockWith { $mockGetTargetResourceAbsentResult }
                }

                Context 'When the Resource should be Present' {
                    It 'Should not throw' {
                        { Test-TargetResource @testTargetResourcePresentParameters } | Should -Not -Throw
                    }

                    It 'Should call the expected mocks' {
                        Assert-MockCalled -CommandName Get-TargetResource `
                            -ParameterFilter { `
                                $Name -eq $testTargetResourcePresentParameters.Name -and `
                                $ClaimType -eq $testTargetResourcePresentParameters.ClaimType } `
                            -Exactly -Times 1
                    }

                    It 'Should return $false' {
                        Test-TargetResource @testTargetResourcePresentParameters | Should -Be $false
                    }
                }

                Context 'When the Resource should be Absent' {
                    It 'Should not throw' {
                        { Test-TargetResource @testTargetResourceAbsentParameters } | Should -Not -Throw
                    }

                    It 'Should call the expected mocks' {
                        Assert-MockCalled -CommandName Get-TargetResource `
                            -ParameterFilter { `
                                $Name -eq $testTargetResourceAbsentParameters.Name -and `
                                $ClaimType -eq $testTargetResourceAbsentParameters.ClaimType } `
                            -Exactly -Times 1
                    }

                    It 'Should return $true' {
                        Test-TargetResource @testTargetResourceAbsentParameters | Should -Be $true
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
