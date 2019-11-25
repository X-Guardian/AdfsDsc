$Global:DSCModuleName = 'AdfsDsc'
$Global:PSModuleName = 'ADFS'
$Global:DscResourceFriendlyName = 'AdfsFarm'
$Global:DSCResourceName = "MSFT_$Global:DscResourceFriendlyName"

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
            Get       = 'Get-AdfsConfigurationStatus'
            Install   = 'Install-AdfsFarm'
        }

        $mockUserName = 'CONTOSO\SvcAccount'
        $mockPassword = 'DummyPassword'

        $mockCredential = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @(
            $mockUserName,
            (ConvertTo-SecureString -String $mockPassword -AsPlainText -Force)
        )

        $mockMSFTCredential = New-CimCredentialInstance -UserName $mockUserName

        $sqlConnectionString = 'TBC'

        $mockResource = @{
            FederationServiceName         = 'sts.contoso.com'
            FederationServiceDisplayName  = 'Contoso ADFS Service'
            CertificateThumbprint         = '6F7E9F5543505B943FEEA49E651EDDD8D9D45011'
            SQLConnectionString           = $SQLConnectionString
            Ensure                        = 'Present'
        }

        $mockGsaResource = $mockResource.Clone()
        $mockGsaResource += @{
            GroupServiceAccountIdentifier = 'CONTOSO\AdfsGmsa'
            ServiceAccountCredential      = $null
        }

        $mockSaResource = $mockResource.Clone()
        $mockSaResource += @{
            GroupServiceAccountIdentifier = $null
            ServiceAccountCredential      = $mockMSFTCredential
        }

        $mockAbsentResource = @{
            FederationServiceName         = $mockResource.FederationServiceName
            CertificateThumbprint         = $mockResource.CertificateThumbprint
            FederationServiceDisplayName  = $null
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
        }

        $mockGetTargetResourcePresentResult = $mockGetTargetResourceResult.Clone()
        $mockGetTargetResourcePresentResult.Ensure = 'Present'

        $mockGetTargetResourceAbsentResult = $mockGetTargetResourceResult.Clone()
        $mockGetTargetResourceAbsentResult.Ensure = 'Absent'

        Describe 'MSFT_AdfsFarm\Get-TargetResource' -Tag 'Get' {
            BeforeAll {
                $getTargetResourceParameters = @{
                    FederationServiceName = $mockResource.FederationServiceName
                    CertificateThumbprint = $mockResource.CertificateThumbprint
                    Credential            = $mockCredential
                }

                $mockGetAdfsSslCertificateResult = @(
                    @{
                        Hostname        = 'sts.contoso.com'
                        PortNumber      = 443
                        CertificateHash = $mockResource.CertificateThumbprint
                    }
                )

                $mockGetAdfsPropertiesResult = @{
                    HostName    = $mockResource.FederationServiceName
                    DisplayName = $mockResource.FederationServiceDisplayName
                }

                $mockGetCimInstanceServiceGsaRunningResult = @{
                    State     = 'Running'
                    StartName = $mockGsaResource.GroupServiceAccountIdentifier
                }

                $mockGetCimInstanceServiceSaRunningResult = @{
                    State     = 'Running'
                    StartName = $mockSaResource.ServiceAccountCredential.UserName
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
                    -MockWith { $mockGetCimInstanceServiceGsaRunningResult }
                Mock -CommandName Get-CimInstance `
                    -ParameterFilter { `
                        $Namespace -eq 'root/ADFS' -and `
                        $ClassName -eq 'SecurityTokenService' } `
                    -MockWith { $mockGetCimInstanceSecurityTokenServiceResult }
                Mock -CommandName Get-AdfsSslCertificate -MockWith { $mockGetAdfsSslCertificateResult }
                Mock -CommandName Get-AdfsProperties -MockWith { $mockGetAdfsPropertiesResult }
                Mock -CommandName Assert-GroupServiceAccount -MockWith { $true }
            }

            Context "When the $($Global:DscResourceFriendlyName) Resource is Configured" {
                BeforeAll {
                    Mock -CommandName $ResourceCommand.Get -MockWith { 'Configured' }

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
                    Assert-MockCalled -CommandName "Assert-$($Global:PSModuleName)Service" -Exactly -Times 1
                    Assert-MockCalled -CommandName $ResourceCommand.Get -Exactly -Times 1
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
                    BeforeAll {
                        Mock Get-AdfsSslCertificate -MockWith { throw $mockExceptionErrorMessage }
                    }

                    It 'Should throw the correct exception' {
                        { Get-TargetResource @getTargetResourceParameters } | Should -Throw (
                            $script:localizedData.GettingAdfsSslCertificateErrorMessage -f
                            $mockResource.FederationServiceName)
                    }
                }

                Context 'When Get-AdfsSslCertificate returns an empty result' {
                    BeforeAll {
                        Mock Get-AdfsSslCertificate
                    }

                    It 'Should throw the correct exception' {
                        { Get-TargetResource @getTargetResourceParameters } | Should -Throw (
                            $script:localizedData.GettingAdfsSslCertificateErrorMessage -f
                            $mockResource.FederationServiceName)
                    }
                }

                Context 'When Get-CimInstance -ClassName Win32_Service returns an empty result' {
                    BeforeAll {
                        Mock -CommandName Get-CimInstance `
                            -ParameterFilter { $ClassName -eq 'Win32_Service' }
                    }

                    It 'Should throw the correct exception' {
                        { Get-TargetResource @getTargetResourceParameters } | Should -Throw (
                            $script:localizedData.GettingAdfsServiceErrorMessage -f
                            $mockResource.FederationServiceName)
                    }
                }

                Context 'When the Service Account is not a group managed service account' {
                    BeforeAll {
                        Mock -CommandName Get-CimInstance `
                            -ParameterFilter { $ClassName -eq 'Win32_Service' } `
                            -MockWith { $mockGetCimInstanceServiceSaRunningResult }
                        Mock -CommandName Assert-GroupServiceAccount -MockWith { $false }

                        $result = Get-TargetResource @getTargetResourceParameters
                    }

                    foreach ($property in $mockSaResource.Keys)
                    {
                        if ($property -eq 'ServiceAccountCredential')
                        {
                            It "Should return the correct $property property" {
                                $result.ServiceAccountCredential.UserName | Should -Be $mockSaResource.ServiceAccountCredential.UserName
                            }
                        }
                        else
                        {
                            It "Should return the correct $property property" {
                                $result.$property | Should -Be $mockSaResource.$property
                            }
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
                            $script:localizedData.GettingAdfsSecurityTokenServiceErrorMessage -f
                            $mockResource.FederationServiceName)
                    }
                }

                Context 'When Get-AdfsProperties throws an exception' {
                    BeforeAll {
                        Mock Get-AdfsProperties -MockWith { throw $mockExceptionErrorMessage }
                    }

                    It 'Should throw the correct exception' {
                        { Get-TargetResource @getTargetResourceParameters } | Should -Throw (
                            $script:localizedData.GettingAdfsPropertiesErrorMessage -f
                            $mockResource.FederationServiceName)
                    }
                }
            }

            Context "When the $($Global:DscResourceFriendlyName) Resource is Absent" {
                BeforeAll {
                    Mock -CommandName $ResourceCommand.Get -MockWith { 'NotConfigured' }

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

        Describe 'MSFT_AdfsFarm\Set-TargetResource' -Tag 'Set' {
            BeforeAll {
                $setTargetResourceParameters = @{
                    FederationServiceName         = $mockGsaResource.FederationServiceName
                    CertificateThumbprint         = $mockGsaResource.CertificateThumbprint
                    Credential                    = $mockCredential
                    GroupServiceAccountIdentifier = $mockGsaResource.GroupServiceAccountIdentifier
                }

                $mockInstallResourceSuccessResult = @{
                    Message = 'The configuration completed successfully.'
                    Context = 'DeploymentSucceeded'
                    Status  = 'Success'
                }

                $mockInstallResourceErrorResult = @{
                    Message = 'The configuration did not complete successfully.'
                    Context = 'DeploymentTask'
                    Status  = 'Error'
                }

                $mockNewCertificateThumbprint = '6F7E9F5543505B943FEEA49E651EDDD8D9D45014'
                $mockNewFederationServiceDisplayName = 'Fabrikam ADFS Service'

                Mock -CommandName $ResourceCommand.Install -MockWith { $mockInstallResourceSuccessResult }
            }

            Context 'When both credential parameters have been specified' {
                BeforeAll {
                    $setTargetResourceBothCredentialParameters = $setTargetResourceParameters.Clone()
                    $setTargetResourceBothCredentialParameters.Add('ServiceAccountCredential', $mockCredential)
                }

                It 'Should throw the correct error' {
                    { Set-TargetResource @setTargetResourceBothCredentialParameters } |
                        Should -Throw ($script:localizedData.ResourceDuplicateCredentialErrorMessage -f
                            $mockResource.FederationServiceName)
                }
            }

            Context 'When neither credential parameters have been specified' {
                BeforeAll {
                    $setTargetResourceBothCredentialParameters = $setTargetResourceParameters.Clone()
                    $setTargetResourceBothCredentialParameters.Remove('GroupServiceAccountIdentifier')
                }

                It 'Should throw the correct error' {
                    { Set-TargetResource @setTargetResourceBothCredentialParameters } |
                        Should -Throw ($script:localizedData.ResourceMissingCredentialErrorMessage -f
                            $mockResource.FederationServiceName)
                }
            }

            Context "When the $($Global:DscResourceFriendlyName) Resource is not installed" {
                BeforeAll {
                    $mockGetTargetResourceAbsentResult = @{
                        Ensure = 'Absent'
                    }

                    Mock -CommandName Get-TargetResource -MockWith { $mockGetTargetResourceAbsentResult }
                }

                It 'Should not throw' {
                    { Set-TargetResource @setTargetResourceParameters } | Should -Not -Throw
                }

                It 'Should call the expected mocks' {
                    Assert-MockCalled -CommandName $ResourceCommand.Install `
                        -ParameterFilter { $FederationServiceName -eq $setTargetResourceParameters.FederationServiceName } `
                        -Exactly -Times 1
                }

                Context "When $($ResourceCommand.Install) throws System.IO.FileNotFoundException" {
                    BeforeAll {
                        Mock $ResourceCommand.Install -MockWith { throw New-Object System.IO.FileNotFoundException }
                    }

                    It 'Should not throw' {
                        { Set-TargetResource @setTargetResourceParameters } | Should -Not -Throw
                    }

                    It 'Should call the expected mocks' {
                        Assert-MockCalled -CommandName $ResourceCommand.Install `
                            -ParameterFilter { $FederationServiceName -eq $setTargetResourceParameters.FederationServiceName } `
                            -Exactly -Times 1
                    }
                }

                Context "When $($ResourceCommand.Install) throws an exception" {
                    BeforeAll {
                        Mock $ResourceCommand.Install -MockWith { throw $mockExceptionErrorMessage }
                    }

                    It 'Should throw the correct error' {
                        { Set-TargetResource @setTargetResourceParameters } | Should -Throw (
                            $script:localizedData.InstallationErrorMessage -f $setTargetResourceParameters.FederationServiceName)
                    }
                }

                Context "When $($ResourceCommand.Install) returns a result with a status of 'Error'" {
                    BeforeAll {
                        Mock $ResourceCommand.Install -MockWith { $mockInstallResourceErrorResult }
                    }

                    It 'Should throw the correct error' {
                        { Set-TargetResource @setTargetResourceParameters } | Should -Throw (
                            $mockInstallResourceErrorResult.Message)
                    }
                }
            }

            Context "When the $($Global:DscResourceFriendlyName) Resource is installed" {
                BeforeAll {
                    Mock -CommandName Get-TargetResource -MockWith { $mockGetTargetResourcePresentResult }
                }

                It 'Should not throw' {
                    { Set-TargetResource @setTargetResourceParameters } | Should -Not -Throw
                }
            }
        }

        Describe 'MSFT_AdfsFarm\Test-TargetResource' -Tag 'Test' {
            BeforeAll {
                $testTargetResourceParameters = @{
                    FederationServiceName = $mockResource.FederationServiceName
                    CertificateThumbprint = $mockResource.CertificateThumbprint
                    Credential            = $mockCredential
                }
            }

            Context "When the $($Global:DscResourceFriendlyName) Resource is installed" {
                BeforeAll {
                    Mock Get-TargetResource -MockWith { $mockGetTargetResourcePresentResult }
                }

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

            Context "When the $($Global:DscResourceFriendlyName) Resource is not installed" {
                BeforeAll {
                    Mock Get-TargetResource -MockWith { $mockGetTargetResourceAbsentResult }
                }

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
