$Global:DSCModuleName = 'AdfsDsc'
$Global:PSModuleName = 'ADFS'
$Global:DSCResourceName = 'MSFT_AdfsSslCertificate'

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
        # Import ADFS Stub Module
        Import-Module (Join-Path -Path $PSScriptRoot -ChildPath "Stubs\$($Global:PSModuleName)Stub.psm1") -Force

        $mockUserName = 'DummyUser'

        $mockCredential = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @(
            $mockUserName,
            (ConvertTo-SecureString -String 'DummyPassword' -AsPlainText -Force)
        )

        $mockMSFTCredential = New-CimCredentialInstance -UserName $mockUserName

        # Define Resource Commands
        $ResourceCommand = @{
            Get = 'Get-AdfsSslCertificate'
            Set = 'Set-AdfsSslCertificate'
        }

        $mockResource = @{
            CertificateType = 'Https-Binding'
            Thumbprint      = 'c3994f6e0b79eb4aa293621e683a752a3b4005d6'
        }

        $mockChangedResource = @{
            ThumbPrint = 'c3994f6e0b79eb4aa293621e683a752a3b4005d7'
        }

        $mockGetTargetResourceResult = @{
            CertificateType = $mockResource.CertificateType
            ThumbPrint      = $mockResource.Thumbprint
        }

        Describe "$Global:DSCResourceName\Get-TargetResource" -Tag 'Get' {
            $getTargetResourceParameters = @{
                CertificateType  = $mockResource.CertificateType
                ThumbPrint       = $mockResource.Thumbprint
                RemoteCredential = $mockCredential
            }

            $mockGetResourceCommandResult = @(
                @{
                    CertificateHash = $mockResource.Thumbprint
                }
            )

            Mock -CommandName Assert-Module
            Mock -CommandName Assert-AdfsService

            Mock -CommandName $ResourceCommand.Get -MockWith { $mockGetResourceCommandResult }

            $result = Get-TargetResource @getTargetResourceParameters

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
                Assert-MockCalled -CommandName Assert-AdfsService -Exactly -Times 1
                Assert-MockCalled -CommandName $ResourceCommand.Get
            }

            Context 'When Get-AdfsSslCertificate throws an exception' {
                Mock -CommandName Get-AdfsSslCertificate -MockWith { Throw 'Error' }

                It 'Should throw the correct exception' {
                    { Get-TargetResource @getTargetResourceParameters } | Should -Throw ( `
                            $script:localizedData.GettingResourceError -f $getTargetResourceParameters.CertificateType )
                }
            }
        }

        Describe "$Global:DSCResourceName\Set-TargetResource" -Tag 'Set' {
            $setTargetResourceParameters = @{
                CertificateType  = $mockResource.CertificateType
                Thumbprint       = $mockChangedResource.Thumbprint
                RemoteCredential = $mockCredential
            }

            Mock -CommandName $ResourceCommand.Set

            Mock -CommandName Get-TargetResource -MockWith { $mockGetTargetResourceResult }

            It 'Should not throw' {
                { Set-TargetResource @setTargetResourceParameters } | Should -Not -Throw
            }

            It 'Should call the expected mocks' {
                Assert-MockCalled -CommandName Get-TargetResource `
                    -ParameterFilter { `
                        $CertificateType -eq $setTargetResourceParameters.CertificateType -and `
                        $Thumbprint -eq $setTargetResourceParameters.Thumbprint } `
                    -Exactly -Times 1
                Assert-MockCalled -CommandName $ResourceCommand.Set -Exactly -Times 1
            }

            Context 'When Set-AdfsSslCertificate throws an exception' {
                Mock -CommandName Set-AdfsSslCertificate -MockWith { Throw 'Error' }

                It 'Should throw the correct exception' {
                    { Set-TargetResource @setTargetResourceParameters } | Should -Throw ( `
                            $script:localizedData.SettingResourceError -f $setTargetResourceParameters.CertificateType )
                }
            }
        }

        Describe "$Global:DSCResourceName\Test-TargetResource" -Tag 'Test' {
            $testTargetResourceParameters = @{
                CertificateType  = $mockResource.CertificateType
                ThumbPrint       = $mockResource.Thumbprint
                RemoteCredential = $mockCredential
            }

            Mock -CommandName Get-TargetResource -MockWith { $mockGetTargetResourceResult }

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
                    $testTargetResourceNotInDesiredStateParameters = $testTargetResourceParameters.Clone()
                    $testTargetResourceNotInDesiredStateParameters.$property = $mockChangedResource.$property

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
