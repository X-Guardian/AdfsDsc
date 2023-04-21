$script:dscModuleName = 'AdfsDsc'
$global:psModuleName = 'ADFS'
$script:dscResourceName = 'MSFT_AdfsApplicationPermission'

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
            Get    = 'Get-AdfsApplicationPermission'
            Set    = 'Set-AdfsApplicationPermission'
            Add    = 'Grant-AdfsApplicationPermission'
            Remove = 'Revoke-AdfsApplicationPermission'
        }

        $mockError = 'Error'

        $mockResource = @{
            ClientRoleIdentifier = 'NativeApp1'
            ServerRoleIdentifier = 'https://nativeapp1.contoso.com'
            Description          = "This is the AppPermission1 Description"
            ScopeNames           = 'openid', 'profile'
            Ensure               = 'Present'
        }

        $mockAbsentResource = @{
            ClientRoleIdentifier = $mockResource.ClientRoleIdentifier
            ServerRoleIdentifier = $mockResource.ServerRoleIdentifier
            Description          = $null
            ScopeNames           = @()
            Ensure               = 'Absent'
        }

        $mockChangedResource = @{
            Description = "This is the new AppPermission1 Description"
            ScopeNames  = 'openid'
        }

        $mockGetTargetResourceResult = @{
            ClientRoleIdentifier = $mockResource.ClientRoleIdentifier
            ServerRoleIdentifier = $mockResource.ServerRoleIdentifier
            Description          = $mockResource.Description
            ScopeNames           = $mockResource.ScopeNames
        }

        $mockGetTargetResourcePresentResult = $mockGetTargetResourceResult.Clone()
        $mockGetTargetResourcePresentResult.Ensure = 'Present'

        $mockGetTargetResourceAbsentResult = $mockGetTargetResourceResult.Clone()
        $mockGetTargetResourceAbsentResult.Ensure = 'Absent'

        Describe 'MSFT_AdfsApplicationPermission\Get-TargetResource' -Tag 'Get' {
            BeforeAll {
                $getTargetResourceParameters = @{
                    ClientRoleIdentifier = $mockResource.ClientRoleIdentifier
                    ServerRoleIdentifier = $mockResource.ServerRoleIdentifier
                }

                $mockGetResourceCommandResult = @{
                    ClientRoleIdentifier = $mockResource.ClientRoleIdentifier
                    ServerRoleIdentifier = $mockResource.ServerRoleIdentifier
                    Description          = $mockResource.Description
                    ScopeNames           = $mockResource.ScopeNames
                }

                Mock -CommandName Assert-Module
                Mock -CommandName Assert-Command
                Mock -CommandName "Assert-$($global:psModuleName)Service"
            }

            Context 'When the Resource is Present' {
                BeforeAll {
                    Mock -CommandName $ResourceCommand.Get -MockWith { $mockGetResourceCommandResult }
                }

                $result = Get-TargetResource @getTargetResourceParameters

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
                    Assert-MockCalled -CommandName Assert-Command `
                        -ParameterFilter { $Module -eq $global:psModuleName -and $Command -eq $ResourceCommand.Get } `
                        -Exactly -Times 1
                    Assert-MockCalled -CommandName "Assert-$($global:psModuleName)Service" -Exactly -Times 1
                    Assert-MockCalled -CommandName $ResourceCommand.Get `
                        -ParameterFilter { `
                            $ClientRoleIdentifiers -eq $getTargetResourceParameters.ClientRoleIdentifier } `
                        -Exactly -Times 1
                }
            }

            Context 'When the Resource is Absent' {
                BeforeAll {
                    Mock -CommandName $ResourceCommand.Get

                    $result = Get-TargetResource @GetTargetResourceParameters
                }

                foreach ($property in $mockResource.Keys)
                {
                    It "Should return the correct $property property" {
                        $result.$property | Should -Be $mockAbsentResource.$property
                    }
                }

                It 'Should call the expected mocks' {
                    Assert-MockCalled -CommandName Assert-Module `
                        -ParameterFilter { $ModuleName -eq $global:psModuleName } `
                        -Exactly -Times 1
                    Assert-MockCalled -CommandName Assert-Command `
                        -ParameterFilter { $Module -eq $global:psModuleName -and $Command -eq $ResourceCommand.Get } `
                        -Exactly -Times 1
                    Assert-MockCalled -CommandName "Assert-$($global:psModuleName)Service" -Exactly -Times 1
                    Assert-MockCalled -CommandName $ResourceCommand.Get `
                        -ParameterFilter { `
                            $ClientRoleIdentifiers -eq $getTargetResourceParameters.ClientRoleIdentifier } `
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
                        $getTargetResourceParameters.ClientRoleIdentifier,
                        $getTargetResourceParameters.ServerRoleIdentifier)
                }
            }
        }

        Describe 'MSFT_AdfsApplicationPermission\Set-TargetResource' -Tag 'Set' {
            BeforeAll {
                $setTargetResourceParameters = @{
                    ClientRoleIdentifier = $mockResource.ClientRoleIdentifier
                    ServerRoleIdentifier = $mockResource.ServerRoleIdentifier
                    Description          = $mockResource.Description
                    ScopeNames           = $mockResource.ScopeNames
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
                                        $ClientRoleIdentifier -eq $setTargetResourcePresentParameters.ClientRoleIdentifier -and `
                                        $ServerRoleIdentifier -eq $setTargetResourcePresentParameters.ServerRoleIdentifier } `
                                    -Exactly -Times 1
                                Assert-MockCalled -CommandName $ResourceCommand.Set `
                                    -ParameterFilter { `
                                        $TargetClientRoleIdentifier -eq $setTargetResourcePresentParameters.ClientRoleIdentifier -and `
                                        $TargetServerRoleIdentifier -eq $setTargetResourcePresentParameters.ServerRoleIdentifier } `
                                    -Exactly -Times 1
                                Assert-MockCalled -CommandName $ResourceCommand.Add -Exactly -Times 0
                                Assert-MockCalled -CommandName $ResourceCommand.Remove -Exactly -Times 0
                            }
                        }
                    }

                    Context "When $($ResourceCommand.Set) throws an exception" {
                        BeforeAll {
                            $setTargetResourceParametersChangedProperty = $setTargetResourcePresentParameters.Clone()
                            $setTargetResourceParametersChangedProperty.Description = $mockChangedResource.Description

                            Mock -CommandName $ResourceCommand.Set -MockWith { throw $mockError }
                        }

                        It 'Should throw the correct exception' {
                            { Set-TargetResource @setTargetResourceParametersChangedProperty } | `
                                Should -Throw ($script:localizedData.SettingResourceErrorMessage -f
                                $setTargetResourceParametersChangedProperty.ClientRoleIdentifier,
                                $setTargetResourceParametersChangedProperty.ServerRoleIdentifier)
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
                                $ClientRoleIdentifier -eq $setTargetResourceAbsentParameters.ClientRoleIdentifier -and `
                                $ServerRoleIdentifier -eq $setTargetResourceAbsentParameters.ServerRoleIdentifier } `
                            -Exactly -Times 1
                        Assert-MockCalled -CommandName $ResourceCommand.Remove `
                            -ParameterFilter {
                            $TargetClientRoleIdentifier -eq $setTargetResourceAbsentParameters.ClientRoleIdentifier -and `
                                $TargetServerRoleIdentifier -eq $setTargetResourceAbsentParameters.ServerRoleIdentifier } `
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
                                $setTargetResourceAbsentParameters.ClientRoleIdentifier,
                                $setTargetResourceAbsentParameters.ServerRoleIdentifier)
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
                                $ClientRoleIdentifier -eq $setTargetResourcePresentParameters.ClientRoleIdentifier -and `
                                $ServerRoleIdentifier -eq $setTargetResourcePresentParameters.ServerRoleIdentifier } `
                            -Exactly -Times 1
                        Assert-MockCalled -CommandName $ResourceCommand.Add `
                            -ParameterFilter { `
                                $ClientRoleIdentifier -eq $setTargetResourcePresentParameters.ClientRoleIdentifier -and `
                                $ServerRoleIdentifier -eq $setTargetResourcePresentParameters.ServerRoleIdentifier } `
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
                                $setTargetResourcePresentParameters.ClientRoleIdentifier,
                                $setTargetResourcePresentParameters.ServerRoleIdentifier)
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
                                $ClientRoleIdentifier -eq $setTargetResourceAbsentParameters.ClientRoleIdentifier -and `
                                $ServerRoleIdentifier -eq $setTargetResourceAbsentParameters.ServerRoleIdentifier } `
                            -Exactly -Times 1
                        Assert-MockCalled -CommandName $ResourceCommand.Remove -Exactly -Times 0
                        Assert-MockCalled -CommandName $ResourceCommand.Add -Exactly -Times 0
                        Assert-MockCalled -CommandName $ResourceCommand.Set -Exactly -Times 0
                    }
                }
            }
        }

        Describe 'MSFT_AdfsApplicationPermission\Test-TargetResource' -Tag 'Test' {
            BeforeAll {
                $testTargetResourceParameters = @{
                    ClientRoleIdentifier = $mockResource.ClientRoleIdentifier
                    ServerRoleIdentifier = $mockResource.ServerRoleIdentifier
                    Description          = $mockResource.Description
                    ScopeNames           = $mockResource.ScopeNames | Sort-Object -Descending
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
                                $ClientRoleIdentifier -eq $testTargetResourcePresentParameters.ClientRoleIdentifier -and `
                                $ServerRoleIdentifier -eq $testTargetResourcePresentParameters.ServerRoleIdentifier } `
                            -Exactly -Times 1
                    }

                    foreach ($property in $mockChangedResource.Keys)
                    {
                        Context "When the $property resource property is not in the desired state" {
                            BeforeAll {
                                $testTargetResourceNotInDesiredStateParameters = $testTargetResourcePresentParameters.Clone()
                                $testTargetResourceNotInDesiredStateParameters.$property = $mockChangedResource.$property
                            }

                            It 'Should return the desired result' {
                                Test-TargetResource @testTargetResourceNotInDesiredStateParameters | Should -Be $false
                            }
                        }
                    }

                    Context 'When all the resource properties are in the desired state' {
                        It 'Should return the desired result' {
                            Test-TargetResource @testTargetResourcePresentParameters | Should -Be $true
                        }
                    }
                }

                Context 'When the Resource should be Absent' {
                    It 'Should return the desired result' {
                        Test-TargetResource @testTargetResourceAbsentParameters | Should -Be $false
                    }

                    It 'Should call the expected mocks' {
                        Assert-MockCalled -CommandName Get-TargetResource `
                            -ParameterFilter { `
                                $ClientRoleIdentifier -eq $testTargetResourceAbsentParameters.ClientRoleIdentifier -and `
                                $ServerRoleIdentifier -eq $testTargetResourceAbsentParameters.ServerRoleIdentifier } `
                            -Exactly -Times 1
                    }
                }
            }

            Context 'When the Resource is Absent' {
                BeforeAll {
                    Mock -CommandName Get-TargetResource -MockWith { $mockGetTargetResourceAbsentResult }
                }

                Context 'When the Resource should be Present' {
                    It 'Should return return the desired result' {
                        Test-TargetResource @testTargetResourcePresentParameters | Should -Be $false
                    }

                    It 'Should call the expected mocks' {
                        Assert-MockCalled -CommandName Get-TargetResource `
                            -ParameterFilter { `
                                $ClientRoleIdentifier -eq $testTargetResourcePresentParameters.ClientRoleIdentifier -and `
                                $ServerRoleIdentifier -eq $testTargetResourcePresentParameters.ServerRoleIdentifier } `
                            -Exactly -Times 1
                    }
                }

                Context 'When the Resource should be Absent' {
                    It 'Should return return the desired result' {
                        Test-TargetResource @testTargetResourceAbsentParameters | Should -Be $true
                    }

                    It 'Should call the expected mocks' {
                        Assert-MockCalled -CommandName Get-TargetResource `
                            -ParameterFilter { `
                                $ClientRoleIdentifier -eq $testTargetResourceAbsentParameters.ClientRoleIdentifier -and `
                                $ServerRoleIdentifier -eq $testTargetResourceAbsentParameters.ServerRoleIdentifier } `
                            -Exactly -Times 1
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
