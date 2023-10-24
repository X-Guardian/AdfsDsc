$script:dscModuleName = 'AdfsDsc'
$global:psModuleName = 'ADFS'
$script:dscResourceName = 'MSFT_AdfsServerApplication'

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
            Get    = 'Get-AdfsServerApplication'
            Set    = 'Set-AdfsServerApplication'
            Add    = 'Add-AdfsServerApplication'
            Remove = 'Remove-AdfsServerApplication'
        }

        $mockError = 'Error'

        $mockResource = @{
            ApplicationGroupIdentifier = 'AppGroup1'
            Name                       = 'ServerApp1'
            Identifier                 = 'ServerApp1'
            RedirectUri                = @('https://serverapp1.contoso.com')
            Description                = 'App1 Server App'
            ADUserPrincipalName        = 'CONTOSO\Svc.App1'
            LogoutUri                  = 'https://serverapp1.contoso.com/logout'
            Ensure                     = 'Present'
        }

        $mockAbsentResource = @{
            ApplicationGroupIdentifier = 'AppGroup1'
            Name                       = 'ServerApp1'
            Identifier                 = 'ServerApp1'
            RedirectUri                = @()
            Description                = $null
            ADUserPrincipalName        = $null
            LogoutUri                  = $null
            Ensure                     = 'Absent'
        }

        $mockChangedResource = @{
            Identifier          = 'Updated ServerApp1'
            RedirectUri         = @('https://serverapp1.fabrikam.com')
            Description         = 'App1 Updated Server App'
            ADUserPrincipalName = 'FABRIKAM\Svc.App1'
            LogoutUri           = 'https://serverapp1.fabrikam.com/logout'
        }

        $mockChangedApplicationGroupIdentifier = 'AppGroup2'

        $mockGetTargetResourceResult = @{
            Name                       = $mockResource.Name
            ApplicationGroupIdentifier = $mockResource.ApplicationGroupIdentifier
            Identifier                 = $mockResource.Identifier
            RedirectUri                = $mockResource.RedirectUri
            Description                = $mockResource.Description
            ADUserPrincipalName        = $mockResource.ADUserPrincipalName
            LogoutUri                  = $mockResource.LogoutUri
        }

        $mockGetTargetResourcePresentResult = $mockGetTargetResourceResult.Clone()
        $mockGetTargetResourcePresentResult.Ensure = 'Present'

        $mockGetTargetResourceAbsentResult = $mockGetTargetResourceResult.Clone()
        $mockGetTargetResourceAbsentResult.Ensure = 'Absent'

        Describe 'MSFT_AdfsServerApplication\Get-TargetResource' -Tag 'Get' {
            BeforeAll {
                $getTargetResourceParameters = @{
                    Name                       = $mockResource.Name
                    ApplicationGroupIdentifier = $mockResource.ApplicationGroupIdentifier
                    Identifier                 = $mockResource.Identifier
                }

                $mockGetResourceCommandResult = @{
                    Name                       = $mockResource.Name
                    ApplicationGroupIdentifier = $mockResource.ApplicationGroupIdentifier
                    Identifier                 = $mockResource.Identifier
                    RedirectUri                = $mockResource.RedirectUri
                    Description                = $mockResource.Description
                    ADUserPrincipalName        = $mockResource.ADUserPrincipalName
                    LogoutUri                  = $mockResource.LogoutUri
                }

                Mock -CommandName Assert-Module
                Mock -CommandName Assert-Command
                Mock -CommandName "Assert-$($global:psModuleName)Service"
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
                        -ParameterFilter { $ModuleName -eq $global:psModuleName } `
                        -Exactly -Times 1
                    Assert-MockCalled -CommandName Assert-Command `
                        -ParameterFilter { $Module -eq $global:psModuleName -and $Command -eq $ResourceCommand.Get } `
                        -Exactly -Times 1
                    Assert-MockCalled -CommandName "Assert-$($global:psModuleName)Service" -Exactly -Times 1
                    Assert-MockCalled -CommandName $ResourceCommand.Get `
                        -ParameterFilter { $name -eq $getTargetResourceParameters.Name } `
                        -Exactly -Times 1
                }
            }

            Context 'When the Resource is Absent' {
                BeforeAll {
                    Mock -CommandName $ResourceCommand.Get

                    $result = Get-TargetResource @getTargetResourceParameters
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
                        -ParameterFilter { $name -eq $getTargetResourceParameters.Name } `
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

        Describe 'MSFT_AdfsServerApplication\Set-TargetResource' -Tag 'Set' {
            BeforeAll {
                $setTargetResourceParameters = @{
                    Name                       = $mockResource.Name
                    ApplicationGroupIdentifier = $mockResource.ApplicationGroupIdentifier
                    Identifier                 = $mockResource.Identifier
                    RedirectUri                = $mockResource.RedirectUri
                    Description                = $mockResource.Description
                    ADUserPrincipalName        = $mockResource.ADUserPrincipalName
                    LogoutUri                  = $mockResource.LogoutUri
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

                    Context 'When the Application Group Identifier has changed' {
                        BeforeAll {
                            $setTargetResourcePresentAGIChangedParameters = $setTargetResourcePresentParameters.Clone()
                            $setTargetResourcePresentAgiChangedParameters.ApplicationGroupIdentifier = $mockChangedApplicationGroupIdentifier
                        }

                        It 'Should not throw' {
                            { Set-TargetResource @setTargetResourcePresentAGIChangedParameters } | Should -Not -Throw
                        }

                        It 'Should call the expected mocks' {
                            Assert-MockCalled -CommandName Get-TargetResource `
                                -ParameterFilter { `
                                    $Name -eq $setTargetResourcePresentAGIChangedParameters.Name } `
                                -Exactly -Times 1
                            Assert-MockCalled -CommandName $ResourceCommand.Set -Exactly -Times 0
                            Assert-MockCalled -CommandName $ResourceCommand.Remove `
                                -ParameterFilter { $TargetName -eq $setTargetResourcePresentParameters.Name } `
                                -Exactly -Times 1
                            Assert-MockCalled -CommandName $ResourceCommand.Add `
                                -ParameterFilter { $Name -eq $setTargetResourcePresentAGIChangedParameters.Name } `
                                -Exactly -Times 1
                        }

                        Context "When $($ResourceCommand.Remove) throws an exception" {
                            BeforeAll {
                                Mock -CommandName $ResourceCommand.Remove -MockWith { throw $mockError }
                            }

                            It 'Should throw the correct exception' {
                                { Set-TargetResource @setTargetResourcePresentAGIChangedParameters } | `
                                        Should -Throw ($script:localizedData.RemovingResourceErrorMessage -f
                                        $setTargetResourcePresentAGIChangedParameters.Name)
                            }
                        }

                        Context "When $($ResourceCommand.Add) throws an exception" {
                            BeforeAll {
                                Mock -CommandName $ResourceCommand.Add -MockWith { throw $mockError }
                            }

                            It 'Should throw the correct exception' {
                                { Set-TargetResource @setTargetResourcePresentAGIChangedParameters } | `
                                        Should -Throw ($script:localizedData.AddingResourceErrorMessage -f
                                        $setTargetResourcePresentAGIChangedParameters.Name)
                            }
                        }
                    }

                    Context 'When the Application Group Identifier has not changed' {
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
                                            $Name -eq $setTargetResourceParametersChangedProperty.Name } `
                                        -Exactly -Times 1
                                    Assert-MockCalled -CommandName $ResourceCommand.Set `
                                        -ParameterFilter { $TargetName -eq $setTargetResourcePresentParameters.Name } `
                                        -Exactly -Times 1
                                    Assert-MockCalled -CommandName $ResourceCommand.Remove -Exactly -Times 0
                                    Assert-MockCalled -CommandName $ResourceCommand.Add -Exactly -Times 0
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
                                        $setTargetResourceParametersChangedProperty.Name)
                            }
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
                                $Name -eq $setTargetResourceAbsentParameters.Name } `
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
                            -ParameterFilter { $Name -eq $setTargetResourcePresentParameters.Name } `
                            -Exactly -Times 1
                        Assert-MockCalled -CommandName $ResourceCommand.Add `
                            -ParameterFilter { $name -eq $setTargetResourcePresentParameters.Name } `
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
                            -ParameterFilter { $Name -eq $setTargetResourceAbsentParameters.Name } `
                            -Exactly -Times 1
                        Assert-MockCalled -CommandName $ResourceCommand.Remove -Exactly -Times 0
                        Assert-MockCalled -CommandName $ResourceCommand.Add -Exactly -Times 0
                        Assert-MockCalled -CommandName $ResourceCommand.Set -Exactly -Times 0
                    }
                }
            }
        }

        Describe 'MSFT_AdfsServerApplication\Test-TargetResource' -Tag 'Test' {
            $testTargetResourceParameters = @{
                Name                       = $mockResource.Name
                ApplicationGroupIdentifier = $mockResource.ApplicationGroupIdentifier
                Identifier                 = $mockResource.Identifier
                RedirectUri                = $mockResource.RedirectUri
                Description                = $mockResource.Description
                ADUserPrincipalName        = $mockResource.ADUserPrincipalName
                LogoutUri                  = $mockResource.LogoutUri
            }

            $testTargetResourcePresentParameters = $testTargetResourceParameters.Clone()
            $testTargetResourcePresentParameters.Ensure = 'Present'

            $testTargetResourceAbsentParameters = $testTargetResourceParameters.Clone()
            $testTargetResourceAbsentParameters.Ensure = 'Absent'

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
                            -ParameterFilter { $Name -eq $testTargetResourcePresentParameters.Name } `
                            -Exactly -Times 1
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
                            -ParameterFilter { $Name -eq $testTargetResourceAbsentParameters.Name } `
                            -Exactly -Times 1
                    }
                }
            }

            Context 'When the Resource is Absent' {
                BeforeAll {
                    Mock -CommandName Get-TargetResource -MockWith { $mockGetTargetResourceAbsentResult }
                }

                Context 'When the Resource should be Present' {
                    It 'Should return the desired result' {
                        Test-TargetResource @testTargetResourcePresentParameters | Should -Be $false
                    }

                    It 'Should call the expected mocks' {
                        Assert-MockCalled -CommandName Get-TargetResource `
                            -ParameterFilter { $Name -eq $testTargetResourcePresentParameters.Name } `
                            -Exactly -Times 1
                    }
                }

                Context 'When the Resource should be Absent' {
                    It 'Should return the desired result' {
                        Test-TargetResource @testTargetResourceAbsentParameters | Should -Be $true
                    }

                    It 'Should call the expected mocks' {
                        Assert-MockCalled -CommandName Get-TargetResource `
                            -ParameterFilter { $Name -eq $testTargetResourceAbsentParameters.Name } `
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
