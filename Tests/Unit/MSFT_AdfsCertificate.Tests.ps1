$script:dscModuleName = 'AdfsDsc'
$global:psModuleName = 'ADFS'
$script:dscResourceName = 'MSFT_AdfsCertificate'

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
            Get = 'Get-AdfsCertificate'
            Set = 'Set-AdfsCertificate'
        }

        $mockResource = @{
            CertificateType = 'Service-Communications'
            Thumbprint      = 'c3994f6e0b79eb4aa293621e683a752a3b4005d6'
        }

        $mockChangedResource = @{
            Thumbprint = 'c3994f6e0b79eb4aa293621e683a752a3b4005d7'
        }

        $mockGetTargetResourceResult = @{
            CertificateType = $mockResource.CertificateType
            Thumbprint      = $mockResource.Thumbprint
        }

        Describe 'MSFT_AdfsCertificate\Get-TargetResource' -Tag 'Get' {
            BeforeAll {
                $getTargetResourceParameters = @{
                    CertificateType = $mockResource.CertificateType
                    Thumbprint      = $mockResource.Thumbprint
                }

                $mockGetResourceCommandResult = @{
                    CertificateType = $mockResource.CertificateType
                    Thumbprint      = $mockResource.Thumbprint
                    IsPrimary       = $true
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
                        $script:localizedData.GettingResourceErrorMessage -f $getTargetResourceParameters.CertificateType )
                }
            }
        }

        Describe 'MSFT_AdfsCertificate\Set-TargetResource' -Tag 'Set' {
            BeforeAll {
                $setTargetResourceParameters = @{
                    CertificateType = $mockResource.CertificateType
                    Thumbprint      = $mockResource.Thumbprint
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
                                $CertificateType -eq $setTargetResourceParametersChangedProperty.CertificateType } `
                            -Exactly -Times 1
                        Assert-MockCalled -CommandName $ResourceCommand.Set `
                            -ParameterFilter { `
                                $CertificateType -eq $setTargetResourceParametersChangedProperty.CertificateType } `
                            -Exactly -Times 1
                    }
                }
            }

            Context "When $($ResourceCommand.Set) throws an exception" {
                BeforeAll {
                    $setTargetResourceParametersChangedProperty = $setTargetResourceParameters.Clone()
                    $setTargetResourceParametersChangedProperty.Thumbprint = $mockChangedResource.Thumbprint

                    Mock -CommandName $ResourceCommand.Set -MockWith { Throw 'Error' }
                }

                It 'Should throw the correct exception' {
                    { Set-TargetResource @setTargetResourceParametersChangedProperty } | Should -Throw (
                        $script:localizedData.SettingResourceErrorMessage -f
                        $setTargetResourceParametersChangedProperty.CertificateType )
                }
            }
        }

        Describe 'MSFT_AdfsCertificate\Test-TargetResource' -Tag 'Test' {
            BeforeAll {
                $testTargetResourceParameters = @{
                    CertificateType = $mockResource.CertificateType
                    Thumbprint      = $mockResource.Thumbprint
                }

                Mock -CommandName Get-TargetResource -MockWith { $mockGetTargetResourceResult }
            }

            It 'Should not throw' {
                { Test-TargetResource @testTargetResourceParameters } | Should -Not -Throw
            }

            It 'Should call the expected mocks' {
                Assert-MockCalled -CommandName Get-TargetResource `
                    -ParameterFilter { `
                        $CertificateType -eq $testTargetResourceParameters.CertificateType -and `
                        $Thumbprint -eq $testTargetResourceParameters.Thumbprint } `
                    -Exactly -times 1
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
