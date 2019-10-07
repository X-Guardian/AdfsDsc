$Global:DSCModuleName = 'AdfsDsc'
$Global:PSModuleName = 'ADFS'
$Global:DSCResourceName = 'MSFT_AdfsFarm'

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
            FederationServiceDisplayName  = 'Contoso ADFS Service'
            CertificateThumbprint         = '6F7E9F5543505B943FEEA49E651EDDD8D9D45011'
            GroupServiceAccountIdentifier = 'CONTOSO\AdfsGmsa'
            ServiceAccountCredential      = $null
            SQLConnectionString           = $sqlConnectionString
            Ensure                        = 'Present'
        }

        $mockSaResource = @{
            FederationServiceName         = 'sts.contoso.com'
            FederationServiceDisplayName  = 'Contoso ADFS Service'
            CertificateThumbprint         = '6F7E9F5543505B943FEEA49E651EDDD8D9D45011'
            GroupServiceAccountIdentifier = $null
            ServiceAccountCredential      = $mockMSFTCredential
            SQLConnectionString           = $sqlConnectionString
            Ensure                        = 'Present'
        }

        $mockAbsentResource = @{
            FederationServiceName         = 'sts.contoso.com'
            FederationServiceDisplayName  = $null
            CertificateThumbprint         = $null
            GroupServiceAccountIdentifier = $null
            ServiceAccountCredential      = $null
            SQLConnectionString           = $null
            Ensure                        = 'Absent'
        }

        $mockGetTargetResourceResult = @{
            FederationServiceName         = $mockGsaResource.FederationServiceName
            FederationServiceDisplayName  = $mockGsaResource.FederationServiceDisplayName
            CertificateThumbprint         = $mockGsaResource.CertificateThumbprint
            ServiceAccountCredential      = $mockGsaResource.ServiceAccountCredential
            GroupServiceAccountIdentifier = $mockGsaResource.GroupServiceAccountIdentifier
            SQLConnectionString           = $mockGsaResource.SQLConnectionString
            Ensure                        = $mockGsaResource.Ensure
        }

        Describe '$Global:DSCResourceName\Get-TargetResource' -Tag 'Get' {
            $getTargetResourceParameters = @{
                FederationServiceName = $mockGsaResource.FederationServiceName
                CertificateThumbprint = $mockGsaResource.CertificateThumbprint
                Credential            = $mockCredential
            }

            $mockGetAdfsSslCertificateResult = @(
                @{
                    Hostname        = 'sts.contoso.com'
                    PortNumber      = 443
                    CertificateHash = $mockGsaResource.CertificateThumbprint
                }
            )

            $mockGetAdfsPropertiesResult = @{
                HostName    = $mockGsaResource.FederationServiceName
                DisplayName = $mockGsaResource.FederationServiceDisplayName
            }

            $mockGetCimInstanceServiceRunningResult = @{
                State     = 'Running'
                StartName = $mockGsaResource.GroupServiceAccountIdentifier
            }

            $mockGetCimInstanceSecurityTokenServiceResult = @{
                ConfigurationDatabaseConnectionString = $sqlConnectionString
            }

            $mockExceptionErrorMessage = 'UnknownException'
            $mockException = New-Object -TypeName 'System.Exception' -ArgumentList $mockExceptionErrorMessage
            $mockErrorRecord = New-Object -TypeName 'System.Management.Automation.ErrorRecord' `
                -ArgumentList @($mockException, $null, 'InvalidOperation', $null)

            Mock -CommandName Assert-Module
            Mock -CommandName Assert-DomainMember
            Mock -CommandName "Assert-$($Global:PSModuleName)Service"

            Mock -CommandName Get-CimInstance `
                -ParameterFilter { $ClassName -eq 'Win32_Service' } `
                -MockWith { $mockGetCimInstanceServiceRunningResult }
            Mock -CommandName Get-CimInstance `
                -ParameterFilter { `
                    $Namespace -eq 'root/ADFS' -and `
                    $ClassName -eq 'SecurityTokenService' } `
                -MockWith { $mockGetCimInstanceSecurityTokenServiceResult }
            Mock -CommandName Get-AdfsSslCertificate -MockWith { $mockGetAdfsSslCertificateResult }
            Mock -CommandName Get-AdfsProperties -MockWith { $mockGetAdfsPropertiesResult }
            Mock -CommandName Assert-GroupServiceAccount -MockWith { $true }

            Context 'When the ADFS Farm is Present' {
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
                    Assert-MockCalled -CommandName "Assert-$($Global:PSModuleName)Service" -Exactly -Times 1
                    Assert-MockCalled -CommandName Get-AdfsConfigurationStatus -Exactly -Times 1
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
                    Assert-MockCalled -CommandName Get-CimInstance `
                        -ParameterFilter { $Filter -eq "Name='$script:AdfsServiceName'" } `
                        -Exactly -Times 1
                    Assert-MockCalled -CommandName Get-AdfsSslCertificate -Exactly -Times 1
                    Assert-MockCalled -CommandName Get-AdfsProperties -Exactly -Times 1
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

                Context 'When Get-AdfsProperties throws an exception' {
                    Mock Get-AdfsProperties -MockWith { throw $mockExceptionErrorMessage }

                    It 'Should throw the correct exception' {
                        { Get-TargetResource @getTargetResourceParameters } | Should -Throw ( `
                                $script:localizedData.GettingAdfsPropertiesError -f `
                                $mockGsaResource.FederationServiceName)
                    }
                }
            }

            Context 'When the ADFS Farm is Absent' {
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
                    Assert-MockCalled -CommandName "Assert-$($Global:PSModuleName)Service" -Exactly -Times 0
                    Assert-MockCalled -CommandName Get-CimInstance `
                        -ParameterFilter { $Filter -eq "Name='$script:AdfsServiceName'" } `
                        -Exactly -Times 0
                    Assert-MockCalled -CommandName Get-AdfsSslCertificate -Exactly -Times 0
                    Assert-MockCalled -CommandName Get-AdfsProperties -Exactly -Times 0
                    Assert-MockCalled -CommandName Assert-GroupServiceAccount -Exactly -Times 0
                }
            }
        }

        Describe '$Global:DSCResourceName\Set-TargetResource' -Tag 'Set' {
            $setTargetResourceParameters = @{
                FederationServiceName         = $mockGsaResource.FederationServiceName
                CertificateThumbprint         = $mockGsaResource.CertificateThumbprint
                Credential                    = $mockCredential
                GroupServiceAccountIdentifier = $mockGsaResource.GroupServiceAccountIdentifier
            }

            $mockInstallAdfsFarmResult = @{
                Message = 'The configuration completed successfully.'
                Context = 'DeploymentSucceeded'
                Status  = 'Success'
            }

            $mockNewCertificateThumbprint = '6F7E9F5543505B943FEEA49E651EDDD8D9D45014'
            $mockNewFederationServiceDisplayName = 'Fabrikam ADFS Service'

            Mock -CommandName Install-AdfsFarm -MockWith { $mockInstallAdfsFarmResult }

            Context 'When both credential parameters have been specified' {
                $setTargetResourceBothCredentialParameters = $setTargetResourceParameters.Clone()
                $setTargetResourceBothCredentialParameters.Add('ServiceAccountCredential', $mockCredential)

                It 'Should throw the correct error' {
                    { Set-TargetResource @setTargetResourceBothCredentialParameters } | `
                            Should -Throw ($script:localizedData.ResourceDuplicateCredentialError -f `
                                $mockGsaResource.FederationServiceName)
                }
            }

            Context 'When neither credential parameters have been specified' {
                $setTargetResourceBothCredentialParameters = $setTargetResourceParameters.Clone()
                $setTargetResourceBothCredentialParameters.Remove('GroupServiceAccountIdentifier')

                It 'Should throw the correct error' {
                    { Set-TargetResource @setTargetResourceBothCredentialParameters } | `
                            Should -Throw ($script:localizedData.ResourceMissingCredentialError -f `
                                $mockGsaResource.FederationServiceName)
                }
            }

            Context 'When the ADFS Service is not installed' {
                $mockGetTargetResourceAbsentResult = @{
                    Ensure = 'Absent'
                }

                Mock -CommandName Get-TargetResource -MockWith { $mockGetTargetResourceAbsentResult }

                It 'Should not throw' {
                    { Set-TargetResource @setTargetResourceParameters } | Should -Not -Throw
                }

                It 'Should call the expected mocks' {
                    Assert-MockCalled -CommandName Install-AdfsFarm `
                        -ParameterFilter { $FederationServiceName -eq $mockGsaResource.FederationServiceName } `
                        -Exactly -Times 1
                }

                Context 'When Install-AdfsFarm throws an exception' {
                    Mock Install-AdfsFarm -MockWith { throw $mockExceptionErrorMessage }

                    It 'Should throw the correct error' {
                        { Set-TargetResource @setTargetResourceParameters } | Should -Throw `
                        ($script:localizedData.InstallationError -f $mockGsaResource.FederationServiceName)
                    }
                }
            }

            Context 'When the ADFS Service is installed' {
                Mock -CommandName Get-TargetResource -MockWith { $mockGetTargetResourceResult }

                It 'Should not throw' {
                    { Set-TargetResource @setTargetResourceParameters } | Should -Not -Throw
                }
            }
        }

        Describe '$Global:DSCResourceName\Test-TargetResource' -Tag 'Test' {
            $testTargetResourceParameters = @{
                FederationServiceName = $mockGsaResource.FederationServiceName
                CertificateThumbprint = $mockGsaResource.CertificateThumbprint
                Credential            = $mockCredential
            }

            Context 'When the ADFS role is configured' {
                Mock Get-TargetResource -MockWith { $mockGetTargetResourceResult }

                It 'Should return $true' {
                    Test-TargetResource @testTargetResourceParameters | Should -BeTrue
                }

                It 'Should call the expected mocks' {
                    Assert-MockCalled -CommandName Get-TargetResource `
                        -ParameterFilter { `
                            $FederationServiceName -eq $testTargetResourceParameters.FederationServiceName } `
                        -Exactly -Times 1

                }
            }

            Context 'When the ADFS role is not configured' {
                $mockGetTargetResourceAbsentResult = $mockGetTargetResourceResult.Clone()
                $mockGetTargetResourceAbsentResult.Ensure = 'Absent'

                Mock Get-TargetResource -MockWith { $mockGetTargetResourceAbsentResult }

                It 'Should return $false' {
                    Test-TargetResource @testTargetResourceParameters | Should -BeFalse
                }

                It 'Should call the expected mocks' {
                    Assert-MockCalled -CommandName Get-TargetResource `
                        -ParameterFilter { `
                            $FederationServiceName -eq $testTargetResourceParameters.FederationServiceName } `
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
