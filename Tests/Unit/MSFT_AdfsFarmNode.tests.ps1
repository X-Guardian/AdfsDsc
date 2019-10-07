
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
                Mock -CommandName Get-AdfsConfigurationStatus -MockWith { 'Configured' }

                $result = Get-TargetResource @getTargetResourceParameters

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
                    Mock Get-AdfsSslCertificate -MockWith { throw $mockExceptionErrorMessage }

                    It 'Should throw the correct exception' {
                        { Get-TargetResource @getTargetResourceParameters } | Should -Throw ( `
                                $script:localizedData.GettingAdfsSslCertificateError -f `
                                $mockGsaResource.FederationServiceName)
                    }
                }

                Context 'When Get-AdfsSslCertificate returns an empty result' {
                    Mock Get-AdfsSslCertificate

                    It 'Should throw the correct exception' {
                        { Get-TargetResource @getTargetResourceParameters } | Should -Throw ( `
                                $script:localizedData.GettingAdfsSslCertificateError -f `
                                $mockGsaResource.FederationServiceName)
                    }
                }

                Context 'When Get-CimInstance -ClassName Win32_Service returns an empty result' {
                    Mock -CommandName Get-CimInstance `
                        -ParameterFilter { $ClassName -eq 'Win32_Service' }

                    It 'Should throw the correct exception' {
                        { Get-TargetResource @getTargetResourceParameters } | Should -Throw ( `
                                $script:localizedData.GettingAdfsServiceError -f `
                                $mockGsaResource.FederationServiceName)
                    }
                }

                Context 'When the Service Account is not a group managed service account' {
                    Mock -CommandName 'Assert-GroupServiceAccount' -MockWith { $false }

                    $result = Get-TargetResource @getTargetResourceParameters

                    foreach ($property in $mockSaResource.Keys)
                    {
                        It "Should return the correct $property property" {
                            $result.$property | Should -Be $mockSaResource.$property
                        }
                    }
                }

                Context 'When Get-CimInstance -ClassName SecurityTokenService throws an exception' {
                    Mock -CommandName Get-CimInstance `
                        -ParameterFilter { `
                            $Namespace -eq 'root/ADFS' -and `
                            $ClassName -eq 'SecurityTokenService' } `
                        -MockWith { throw $mockExceptionErrorMessage }

                    It 'Should throw the correct exception' {
                        { Get-TargetResource @getTargetResourceParameters } | Should -Throw ( `
                                $script:localizedData.GettingAdfsSecurityTokenServiceError -f `
                                $mockGsaResource.FederationServiceName)
                    }
                }

                Context 'When Get-AdfsSyncProperties throws an exception' {
                    Mock Get-AdfsSyncProperties -MockWith { throw $mockExceptionErrorMessage }

                    It 'Should throw the correct exception' {
                        { Get-TargetResource @getTargetResourceParameters } | Should -Throw ( `
                                $script:localizedData.GettingAdfsSyncPropertiesError -f `
                                $mockGsaResource.FederationServiceName)
                    }
                }
            }

            Context 'When the ADFS service is not configured' {
                Mock -CommandName Get-AdfsConfigurationStatus -MockWith { 'NotConfigured' }

                $result = Get-TargetResource @getTargetResourceParameters

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

            $mockInstallAdfsFarmNodeResult = @{
                Message = 'The configuration completed successfully.'
                Context = 'DeploymentSucceeded'
                Status  = 'Success'
            }

            Mock -CommandName Add-AdfsFarmNode -MockWith { $mockInstallAdfsFarmNodeResult }
            Mock -CommandName Remove-AdfsFarmNode

            Context 'When both credential parameters have been specified' {
                $setTargetResourceBothCredentialParameters = $setTargetResourceParameters.Clone()
                $setTargetResourceBothCredentialParameters.Add('ServiceAccountCredential', $mockCredential)

                It 'Should throw the correct error' {
                    { Set-TargetResource @setTargetResourceBothCredentialParameters } | `
                            Should -Throw ($script:localizedData.ResourceDuplicateCredentialError -f `
                                $setTargetResourceBothCredentialParameters.FederationServiceName)
                }
            }

            Context 'When neither credential parameters have been specified' {
                $setTargetResourceBothCredentialParameters = $setTargetResourceParameters.Clone()
                $setTargetResourceBothCredentialParameters.Remove('GroupServiceAccountIdentifier')

                It 'Should throw the correct error' {
                    { Set-TargetResource @setTargetResourceBothCredentialParameters } | `
                            Should -Throw ($script:localizedData.ResourceMissingCredentialError -f `
                                $setTargetResourceBothCredentialParameters.FederationServiceName)
                }
            }

            Context 'When the ADFS Service should be installed' {

                Context 'When the ADFS Service is not installed' {
                    $mockGetTargetResourceAbsentResult = @{
                        Ensure = 'Absent'
                    }

                    Mock -CommandName Get-TargetResource -MockWith { $mockGetTargetResourceAbsentResult }

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

                    Context 'When Install-AdfsFarm throws an exception' {
                        Mock Add-AdfsFarmNode -MockWith { throw $mockExceptionErrorMessage }

                        It 'Should throw the correct error' {
                            { Set-TargetResource @setTargetResourcePresentParameters } | Should -Throw `
                            ($script:localizedData.InstallationError -f `
                                    $setTargetResourcePresentParameters.FederationServiceName)
                        }
                    }
                }

                Context 'When the ADFS Service is installed' {
                    Mock -CommandName Get-TargetResource -MockWith { $mockGetTargetResourcePresentResult }

                    It 'Should not throw' {
                        { Set-TargetResource @setTargetResourcePresentParameters } | Should -Not -Throw
                    }
                }
            }

            Context 'When the ADFS Service should not be installed' {

                Context 'When the ADFS Service is installed' {
                    Mock -CommandName Get-TargetResource -MockWith { $mockGetTargetResourcePresentResult }

                    It 'Should not throw' {
                        { Set-TargetResource @setTargetResourceAbsentParameters } | Should -Not -Throw
                    }

                    It 'Should call the expected mocks' {
                        Assert-MockCalled -CommandName Remove-AdfsFarmNode -Exactly -Times 1
                        Assert-MockCalled -CommandName Add-AdfsFarmNode -Exactly -Times 0

                    }
                }

                Context 'When the ADFS Service is not installed' {

                }
            }
        }

        Describe '$Global:DSCResourceName\Test-TargetResource' -Tag 'Test' {
            $testTargetResourceParameters = @{
                FederationServiceName         = $mockGsaResource.FederationServiceName
                Credential                    = $mockCredential
                CertificateThumbprint         = $mockGsaResource.CertificateThumbprint
                GroupServiceAccountIdentifier = $mockGsaResource.GroupServiceAccountIdentifier
                PrimaryComputerName           = $mockGsaResource.PrimaryComputerName
                PrimaryComputerPort           = $mockGsaResource.PrimaryComputerPort
            }

            Context 'When the ADFS role is installed' {
                Mock Get-TargetResource -MockWith { $mockGetTargetResourcePresentResult }

                It 'Should not throw' {
                    { Test-TargetResource @testTargetResourceParameters } | Should -Not -Throw
                }

                It 'Should call the expected mocks' {
                    Assert-MockCalled -CommandName Get-TargetResource `
                        -ParameterFilter { $FederationServiceName -eq $mockGsaResource.FederationServiceName } `
                        -Exactly -Times 1

                }

                Context 'When all the resource properties are in the desired state' {
                    It 'Should return $true' {
                        Test-TargetResource @testTargetResourceParameters | Should -Be $true
                    }
                }
            }

            Context 'When the ADFS role is not configured' {
                Mock Get-TargetResource -MockWith { $mockGetTargetResourceAbsentResult }

                It 'Should return $false' {
                    Test-TargetResource @testTargetResourceParameters | Should -Be $false
                }

                It 'Should call the expected mocks' {
                    Assert-MockCalled -CommandName Get-TargetResource `
                        -ParameterFilter { $FederationServiceName -eq $mockGsaResource.FederationServiceName } `
                        -Exactly -Times 1
                }
            }
        }
    }
}
finally
{
    Restore-TestEnvironment -TestEnvironment $TestEnvironment
}
