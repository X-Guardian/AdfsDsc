
$Global:DSCModuleName = 'AdfsDsc'
$Global:PSModuleName = 'ADFS'
$Global:DSCResourceName = 'MSFT_AdfsFarmNode'

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

        $sqlConnectionString = 'TBC'

        $mockGsaResource = @{
            FederationServiceName         = 'sts.contoso.com'
            CertificateThumbprint         = '6F7E9F5543505B943FEEA49E651EDDD8D9D45011'
            GroupServiceAccountIdentifier = 'CONTOSO\AdfsGmsa'
            ServiceAccountCredential      = $null
            PrimaryComputerName           = 'adfs01'
            PrimaryComputerPort           = 80
            SQLConnectionString           = $SQLConnectionString
            Ensure                        = 'Present'
        }

        $mockSaResource = @{
            FederationServiceName         = 'sts.contoso.com'
            CertificateThumbprint         = '6F7E9F5543505B943FEEA49E651EDDD8D9D45011'
            GroupServiceAccountIdentifier = $null
            ServiceAccountCredential      = $mockMSFTCredential
            PrimaryComputerName           = 'adfs01'
            PrimaryComputerPort           = 80
            SQLConnectionString           = $SQLConnectionString
            Ensure                        = 'Present'
        }

        $mockAbsentResource = @{
            FederationServiceName         = 'sts.contoso.com'
            CertificateThumbprint         = $null
            GroupServiceAccountIdentifier = $null
            ServiceAccountCredential      = $null
            PrimaryComputerName           = $null
            PrimaryComputerPort           = $null
            SQLConnectionString           = $null
            Ensure                        = 'Absent'
        }

        $mockGetTargetResourceResult = @{
            FederationServiceName         = $mockGsaResource.FederationServiceName
            CertificateThumbprint         = $mockGsaResource.CertificateThumbprint
            GroupServiceAccountIdentifier = $mockGsaResource.GroupServiceAccountIdentifier
            ServiceAccountCredential      = $mockGsaResource.ServiceAccountCredential
            PrimaryComputerName           = $mockGsaResource.PrimaryComputerName
            PrimaryComputerPort           = $mockGsaResource.PrimaryComputerPort
            SQLConnectionString           = $mockGsaResource.SQLConnectionString
        }

        $mockGetTargetResourcePresentResult = $mockGetTargetResourceResult.Clone()
        $mockGetTargetResourcePresentResult.Ensure = 'Present'

        $mockGetTargetResourceAbsentResult = $MockGetTargetResourceResult.Clone()
        $mockGetTargetResourceAbsentResult.Ensure = 'Absent'

        $getTargetResourceParameters = @{
            FederationServiceName = $mockGsaResource.FederationServiceName
            Credential            = $mockCredential
        }

        Describe '$Global:DSCResourceName\Get-TargetResource' -Tag 'Get' {
            $mockGetAdfsSslCertificateResult = @(
                @{
                    Hostname        = 'sts.contoso.com'
                    PortNumber      = 443
                    CertificateHash = $mockGsaResource.CertificateThumbprint
                }
            )

            $mockGetAdfsSyncProperties = @{
                PrimaryComputerName = $mockGsaResource.PrimaryComputerName
                PrimaryComputerPort = $mockGsaResource.PrimaryComputerPort
            }

            $mockGetCimInstanceServiceRunningResult = @{
                StartName = $mockGsaResource.GroupServiceAccountIdentifier
                State     = 'Running'
            }

            $mockGetCimInstanceSecurityTokenServiceResult = @{
                ConfigurationDatabaseConnectionString = $sqlConnectionString
            }

            Mock -CommandName Assert-Module
            Mock -CommandName Assert-DomainMember
            Mock -CommandName Assert-AdfsService
            Mock -CommandName Get-CimInstance `
                -ParameterFilter { $ClassName -eq 'Win32_Service' } `
                -MockWith { $mockGetCimInstanceServiceRunningResult }
            Mock -CommandName Get-CimInstance `
                -ParameterFilter { `
                    $Namespace -eq 'root/ADFS' -and `
                    $ClassName -eq 'SecurityTokenService' } `
                -MockWith { $mockGetCimInstanceSecurityTokenServiceResult }
            Mock -CommandName Get-AdfsSslCertificate -MockWith { $mockGetAdfsSslCertificateResult }
            Mock -CommandName Get-AdfsSyncProperties -MockWith { $mockGetAdfsSyncProperties }
            Mock -CommandName Assert-GroupServiceAccount -MockWith { $true }

            Context 'When the ADFS service is configured' {
                BeforeAll {
                    Mock -CommandName Get-AdfsConfigurationStatus -MockWith { 'Configured' }

                    $result = Get-TargetResource @getTargetResourceParameters
                }

                foreach ($property in $mockGsaResource.Keys)
                {
                    It "Should return the correct $property property" {
                        $result.$property | Should -Be $mockGsaResource.$property
                    }
                }

                It 'Should call the expected mocks' {
                    Assert-MockCalled -CommandName Assert-Module `
                        -ParameterFilter { $ModuleName -eq $Global:PSModuleName } `
                        -Exactly -Times 1
                    Assert-MockCalled -CommandName Assert-DomainMember -Exactly -Times 1
                    Assert-MockCalled -CommandName Assert-AdfsService -Exactly -Times 1
                    Assert-MockCalled -CommandName Get-CimInstance `
                        -ParameterFilter {
                        $ClassName -eq 'Win32_Service' -and `
                            $Filter -eq "Name='$script:AdfsServiceName'" } `
                        -Exactly -Times 1
                    Assert-MockCalled -CommandName Get-CimInstance `
                        -ParameterFilter {
                        $Namespace -eq 'root/ADFS' -and `
                            $ClassName -eq 'SecurityTokenService' } `
                        -Exactly -Times 1
                    Assert-MockCalled -CommandName Get-AdfsSslCertificate -Exactly -Times 1
                    Assert-MockCalled -CommandName Get-AdfsSyncProperties -Exactly -Times 1
                    Assert-MockCalled -CommandName Assert-GroupServiceAccount -Exactly -Times 1
                }

                Context 'When Get-AdfsSslCertificate throws an exception' {
                    BeforeAll {
                        Mock Get-AdfsSslCertificate -MockWith { throw $mockExceptionErrorMessage }
                    }

                    It 'Should throw the correct exception' {
                        { Get-TargetResource @getTargetResourceParameters } | Should -Throw (
                            $script:localizedData.GettingAdfsSslCertificateError -f
                            $mockGsaResource.FederationServiceName)
                    }
                }

                Context 'When Get-AdfsSslCertificate returns an empty result' {
                    BeforeAll {
                        Mock Get-AdfsSslCertificate
                    }

                    It 'Should throw the correct exception' {
                        { Get-TargetResource @getTargetResourceParameters } | Should -Throw (
                            $script:localizedData.GettingAdfsSslCertificateError -f
                            $mockGsaResource.FederationServiceName)
                    }
                }

                Context 'When Get-CimInstance -ClassName Win32_Service returns an empty result' {
                    BeforeAll {
                        Mock -CommandName Get-CimInstance `
                            -ParameterFilter { $ClassName -eq 'Win32_Service' }
                    }

                    It 'Should throw the correct exception' {
                        { Get-TargetResource @getTargetResourceParameters } | Should -Throw (
                            $script:localizedData.GettingAdfsServiceError -f
                            $mockGsaResource.FederationServiceName)
                    }
                }

                Context 'When the Service Account is not a group managed service account' {
                    BeforeAll {
                        Mock -CommandName Assert-GroupServiceAccount -MockWith { $false }

                        $result = Get-TargetResource @getTargetResourceParameters
                    }

                    foreach ($property in $mockSaResource.Keys)
                    {
                        It "Should return the correct $property property" {
                            $result.$property | Should -Be $mockSaResource.$property
                        }
                    }
                }

                Context 'When Get-CimInstance -ClassName SecurityTokenService throws an exception' {
                    BeforeAll {
                        Mock -CommandName Get-CimInstance `
                            -ParameterFilter { `
                                $Namespace -eq 'root/ADFS' -and `
                                $ClassName -eq 'SecurityTokenService' } `
                            -MockWith { throw $mockExceptionErrorMessage }
                    }

                    It 'Should throw the correct exception' {
                        { Get-TargetResource @getTargetResourceParameters } | Should -Throw (
                            $script:localizedData.GettingAdfsSecurityTokenServiceError -f
                            $mockGsaResource.FederationServiceName)
                    }
                }

                Context 'When Get-AdfsSyncProperties throws an exception' {
                    BeforeAll {
                        Mock Get-AdfsSyncProperties -MockWith { throw $mockExceptionErrorMessage }
                    }

                    It 'Should throw the correct exception' {
                        { Get-TargetResource @getTargetResourceParameters } | Should -Throw (
                            $script:localizedData.GettingAdfsSyncPropertiesError -f
                            $mockGsaResource.FederationServiceName)
                    }
                }
            }

            Context 'When the ADFS service is not configured' {
                BeforeAll {
                    Mock -CommandName Get-AdfsConfigurationStatus -MockWith { 'NotConfigured' }

                    $result = Get-TargetResource @getTargetResourceParameters
                }

                foreach ($property in $mockGsaResource.Keys)
                {
                    It "Should return the correct $property property" {
                        $result.$property | Should -Be $mockAbsentResource.$property
                    }
                }

                It 'Should call the expected mocks' {
                    Assert-MockCalled -CommandName Assert-Module `
                        -ParameterFilter { $ModuleName -eq $Global:PSModuleName } `
                        -Exactly -Times 1
                    Assert-MockCalled -CommandName Assert-DomainMember -Exactly -Times 1
                    Assert-MockCalled -CommandName Assert-AdfsService -Exactly -Times 0
                    Assert-MockCalled -CommandName Get-CimInstance `
                        -ParameterFilter { $Filter -eq "Name='$script:AdfsServiceName'" } `
                        -Exactly -Times 0
                    Assert-MockCalled -CommandName Get-AdfsSslCertificate -Exactly -Times 0
                    Assert-MockCalled -CommandName Get-AdfsSyncProperties -Exactly -Times 0
                    Assert-MockCalled -CommandName Assert-GroupServiceAccount -Exactly -Times 0
                }
            }
        }

        Describe '$Global:DSCResourceName\Set-TargetResource' -Tag 'Set' {
            BeforeAll {
                $setTargetResourceParameters = @{
                    FederationServiceName         = $mockGsaResource.FederationServiceName
                    Credential                    = $mockCredential
                    CertificateThumbprint         = $mockGsaResource.CertificateThumbprint
                    GroupServiceAccountIdentifier = $mockGsaResource.GroupServiceAccountIdentifier
                    PrimaryComputerName           = 'ADFS01'
                    PrimaryComputerPort           = 443
                }

                $setTargetResourcePresentParameters = $setTargetResourceParameters.Clone()
                $setTargetResourcePresentParameters.Ensure = 'Present'

                $setTargetResourceAbsentParameters = $setTargetResourceParameters.Clone()
                $setTargetResourceAbsentParameters.Ensure = 'Absent'

                $mockAddAdfsFarmNodeSuccessResult = @{
                    Message = 'The configuration completed successfully.'
                    Context = 'DeploymentSucceeded'
                    Status  = 'Success'
                }

                $mockAddAdfsFarmNodeErrorResult = @{
                    Message = 'The configuration did not complete successfully.'
                    Context = 'DeploymentTask'
                    Status  = 'Error'
                }

                Mock -CommandName Add-AdfsFarmNode -MockWith { $mockAddAdfsFarmNodeSuccessResult }
                Mock -CommandName Remove-AdfsFarmNode
            }

            Context 'When both credential parameters have been specified' {
                BeforeAll {
                    $setTargetResourceBothCredentialParameters = $setTargetResourceParameters.Clone()
                    $setTargetResourceBothCredentialParameters.Add('ServiceAccountCredential', $mockCredential)
                }

                It 'Should throw the correct error' {
                    { Set-TargetResource @setTargetResourceBothCredentialParameters } |
                        Should -Throw ($script:localizedData.ResourceDuplicateCredentialError -f
                            $setTargetResourceBothCredentialParameters.FederationServiceName)
                }
            }

            Context 'When neither credential parameters have been specified' {
                BeforeAll {
                    $setTargetResourceBothCredentialParameters = $setTargetResourceParameters.Clone()
                    $setTargetResourceBothCredentialParameters.Remove('GroupServiceAccountIdentifier')
                }

                It 'Should throw the correct error' {
                    { Set-TargetResource @setTargetResourceBothCredentialParameters } |
                        Should -Throw ($script:localizedData.ResourceMissingCredentialError -f
                            $setTargetResourceBothCredentialParameters.FederationServiceName)
                }
            }

            Context 'When the ADFS Service should be installed' {

                Context 'When the ADFS Service is not installed' {
                    BeforeAll {
                        $mockGetTargetResourceAbsentResult = @{
                            Ensure = 'Absent'
                        }

                        Mock -CommandName Get-TargetResource -MockWith { $mockGetTargetResourceAbsentResult }
                    }

                    It 'Should not throw' {
                        { Set-TargetResource @setTargetResourcePresentParameters } | Should -Not -Throw
                    }

                    It 'Should call the expected mocks' {
                        Assert-MockCalled -CommandName Add-AdfsFarmNode `
                            -ParameterFilter { `
                                $CertificateThumbprint -eq $setTargetResourcePresentParameters.CertificateThumbprint } `
                            -Exactly -Times 1
                        Assert-MockCalled -CommandName Remove-AdfsFarmNode -Exactly -Times 0
                    }

                    Context 'When Add-AdfsFarmNode throws System.IO.FileNotFoundException' {
                        BeforeAll {
                            Mock Add-AdfsFarmNode -MockWith { throw New-Object System.IO.FileNotFoundException }
                        }

                        It 'Should not throw' {
                            { Set-TargetResource @setTargetResourceParameters } | Should -Not -Throw
                        }

                        It 'Should call the expected mocks' {
                            Assert-MockCalled -CommandName Add-AdfsFarmNode `
                                -ParameterFilter { `
                                    $CertificateThumbprint -eq $setTargetResourcePresentParameters.CertificateThumbprint } `
                                -Exactly -Times 1
                        }
                    }

                    Context 'When Add-AdfsFarmNode throws an exception' {
                        BeforeAll {
                            Mock Add-AdfsFarmNode -MockWith { throw $mockExceptionErrorMessage }
                        }

                        It 'Should throw the correct error' {
                            { Set-TargetResource @setTargetResourcePresentParameters } | Should -Throw (
                                $script:localizedData.InstallationError -f
                                $setTargetResourcePresentParameters.FederationServiceName)
                        }
                    }

                    Context 'When Add-AdfsFarmNode returns a result with a status of "Error"' {
                        BeforeAll {
                            Mock Add-AdfsFarmNode -MockWith { $mockAddAdfsFarmNodeErrorResult }
                        }

                        It 'Should throw the correct error' {
                            { Set-TargetResource @setTargetResourceParameters } | Should -Throw (
                                $mockAddAdfsFarmNodeErrorResult.Message)
                        }
                    }
                }

                Context 'When the ADFS Service is installed' {
                    BeforeAll {
                        Mock -CommandName Get-TargetResource -MockWith { $mockGetTargetResourcePresentResult }
                    }

                    It 'Should not throw' {
                        { Set-TargetResource @setTargetResourcePresentParameters } | Should -Not -Throw
                    }
                }
            }

            Context 'When the ADFS Service should not be installed' {

                Context 'When the ADFS Service is installed' {
                    BeforeAll {
                        Mock -CommandName Get-TargetResource -MockWith { $mockGetTargetResourcePresentResult }
                    }

                    It 'Should not throw' {
                        { Set-TargetResource @setTargetResourceAbsentParameters } | Should -Not -Throw
                    }

                    It 'Should call the expected mocks' {
                        Assert-MockCalled -CommandName Remove-AdfsFarmNode -Exactly -Times 1
                        Assert-MockCalled -CommandName Add-AdfsFarmNode -Exactly -Times 0
                    }

                    Context 'When Remove-AdfsFarmNode throws an exception' {
                        BeforeAll {
                            Mock Remove-AdfsFarmNode -MockWith { throw $mockExceptionErrorMessage }
                        }

                        It 'Should throw the correct error' {
                            { Set-TargetResource @setTargetResourceAbsentParameters } | Should -Throw (
                                $script:localizedData.RemovalError -f
                                $setTargetResourceAbsentParameters.FederationServiceName)
                        }
                    }
                }

                Context 'When the ADFS Service is not installed' {
                    BeforeAll {
                        Mock -CommandName Get-TargetResource -MockWith { $mockGetTargetResourceAbsentResult }
                    }

                    It 'Should not throw' {
                        { Set-TargetResource @setTargetResourceAbsentParameters } | Should -Not -Throw
                    }

                    It 'Should call the expected mocks' {
                        Assert-MockCalled -CommandName Remove-AdfsFarmNode -Exactly -Times 0
                        Assert-MockCalled -CommandName Add-AdfsFarmNode -Exactly -Times 0
                    }
                }
            }
        }

        Describe '$Global:DSCResourceName\Test-TargetResource' -Tag 'Test' {
            BeforeAll {
                $testTargetResourceParameters = @{
                    FederationServiceName         = $mockGsaResource.FederationServiceName
                    Credential                    = $mockCredential
                    CertificateThumbprint         = $mockGsaResource.CertificateThumbprint
                    GroupServiceAccountIdentifier = $mockGsaResource.GroupServiceAccountIdentifier
                    PrimaryComputerName           = $mockGsaResource.PrimaryComputerName
                    PrimaryComputerPort           = $mockGsaResource.PrimaryComputerPort
                }

                $testTargetResourcePresentParameters = $testTargetResourceParameters.Clone()
                $testTargetResourcePresentParameters.Ensure = 'Present'

                $testTargetResourceAbsentParameters = $testTargetResourceParameters.Clone()
                $testTargetResourceAbsentParameters.Ensure = 'Absent'
            }

            Context 'When the ADFS Farm Node is installed' {
                BeforeAll {
                    Mock Get-TargetResource -MockWith { $mockGetTargetResourcePresentResult }
                }

                Context 'When the ADFS Farm Node should be installed' {
                    It 'Should return true' {
                        Test-TargetResource @testTargetResourcePresentParameters | Should -BeTrue
                    }

                    It 'Should call the expected mocks' {
                        Assert-MockCalled -CommandName Get-TargetResource `
                            -ParameterFilter { $FederationServiceName -eq `
                                $TestTargetResourcePresentParameters.FederationServiceName } `
                            -Exactly -Times 1

                    }
                }

                Context 'When the ADFS Farm Node should not be installed' {
                    It 'Should return false' {
                        Test-TargetResource @testTargetResourceAbsentParameters | Should -BeFalse
                    }

                    It 'Should call the expected mocks' {
                        Assert-MockCalled -CommandName Get-TargetResource `
                            -ParameterFilter { $FederationServiceName -eq `
                                $TestTargetResourceAbsentParameters.FederationServiceName } `
                            -Exactly -Times 1
                    }
                }
            }

            Context 'When the ADFS Farm Node is not installed' {
                BeforeAll {
                    Mock Get-TargetResource -MockWith { $mockGetTargetResourceAbsentResult }
                }

                Context 'When the ADFS Farm Node should not be installed' {
                    It 'Should return $false' {
                        Test-TargetResource @testTargetResourceAbsentParameters | Should -Be $true
                    }

                    It 'Should call the expected mocks' {
                        Assert-MockCalled -CommandName Get-TargetResource `
                            -ParameterFilter { $FederationServiceName -eq `
                                $testTargetResourceAbsentParameters.FederationServiceName } `
                            -Exactly -Times 1
                    }
                }

                Context 'When the ADFS Farm Node should be installed' {
                    It 'Should return $false' {
                        Test-TargetResource @testTargetResourcePresentParameters | Should -Be $false
                    }

                    It 'Should call the expected mocks' {
                        Assert-MockCalled -CommandName Get-TargetResource `
                            -ParameterFilter { $FederationServiceName -eq `
                                $testTargetResourcePresentParameters.FederationServiceName } `
                            -Exactly -Times 1
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
