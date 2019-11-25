$Global:DSCModuleName = 'AdfsDsc'
$Global:PSModuleName = 'ADFS'
$Global:DscResourceFriendlyName = 'AdfsFarmNode'
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
            Install   = 'Add-AdfsFarmNode'
            Uninstall = 'Remove-AdfsFarmNode'
        }

        $mockUserName = 'CONTOSO\AdfsSmsa'
        $mockPassword = 'DummyPassword'

        $mockCredential = New-Object -TypeName 'System.Management.Automation.PSCredential' -ArgumentList @(
            $mockUserName,
            (ConvertTo-SecureString -String $mockPassword -AsPlainText -Force)
        )

        $mockMSFTCredential = New-CimCredentialInstance -UserName $mockUserName

        $sqlConnectionString = 'TBC'

        $mockWidResource = @{
            FederationServiceName = 'sts.contoso.com'
            CertificateThumbprint = '6F7E9F5543505B943FEEA49E651EDDD8D9D45011'
            PrimaryComputerName   = 'adfs01'
            PrimaryComputerPort   = 80
            SQLConnectionString   = $SQLConnectionString
            Ensure                = 'Present'
        }

        $mockSqlResource = @{
            FederationServiceName = 'sts.contoso.com'
            CertificateThumbprint = '6F7E9F5543505B943FEEA49E651EDDD8D9D45011'
            SQLConnectionString   = $SQLConnectionString
            Ensure                = 'Present'
        }

        $mockGsaWidResource = $mockWidResource.Clone()
        $mockGsaWidResource += @{
            GroupServiceAccountIdentifier = 'CONTOSO\AdfsGmsa'
            ServiceAccountCredential      = $null
        }

        $mockGsaSqlResource = $mockSqlResource.Clone()
        $mockGsaSqlResource += @{
            GroupServiceAccountIdentifier = 'CONTOSO\AdfsGmsa'
            ServiceAccountCredential      = $null
        }

        $mockSaResource = $mockWidResource.Clone()
        $mockSaResource += @{
            GroupServiceAccountIdentifier = $null
            ServiceAccountCredential      = $mockMSFTCredential
        }

        $mockAbsentResource = @{
            FederationServiceName         = $mockWidResource.FederationServiceName
            CertificateThumbprint         = $null
            GroupServiceAccountIdentifier = $null
            ServiceAccountCredential      = $null
            PrimaryComputerName           = $null
            PrimaryComputerPort           = $null
            SQLConnectionString           = $null
            Ensure                        = 'Absent'
        }

        $mockGetTargetGsaWidResourceResult = @{
            FederationServiceName         = $mockGsaWidResource.FederationServiceName
            CertificateThumbprint         = $mockGsaWidResource.CertificateThumbprint
            GroupServiceAccountIdentifier = $mockGsaWidResource.GroupServiceAccountIdentifier
            ServiceAccountCredential      = $mockGsaWidResource.ServiceAccountCredential
            PrimaryComputerName           = $mockGsaWidResource.PrimaryComputerName
            PrimaryComputerPort           = $mockGsaWidResource.PrimaryComputerPort
            SQLConnectionString           = $mockGsaWidResource.SQLConnectionString
        }

        $mockGetTargetGsaWidResourcePresentResult = $mockGetTargetGsaWidResourceResult.Clone()
        $mockGetTargetGsaWidResourcePresentResult.Ensure = 'Present'

        $mockGetTargetResourceAbsentResult = $mockGetTargetGsaWidResourceResult.Clone()
        $mockGetTargetResourceAbsentResult.Ensure = 'Absent'

        $getTargetResourceParameters = @{
            FederationServiceName = $mockWidResource.FederationServiceName
            CertificateThumbprint = $mockWidResource.CertificateThumbprint
            Credential            = $mockCredential
        }

        Describe 'MSFT_AdfsFarmNode\Get-TargetResource' -Tag 'Get' {
            $mockGetAdfsSslCertificateResult = @(
                @{
                    Hostname        = 'sts.contoso.com'
                    PortNumber      = 443
                    CertificateHash = $mockWidResource.CertificateThumbprint
                }
            )

            $mockGetAdfsSyncPropertiesWid = @{
                PrimaryComputerName = $mockWidResource.PrimaryComputerName
                PrimaryComputerPort = $mockWidResource.PrimaryComputerPort
            }

            $mockGetCimInstanceServiceGsaRunningResult = @{
                State     = 'Running'
                StartName = $mockGsaWidResource.GroupServiceAccountIdentifier
            }

            $mockGetCimInstanceServiceSaRunningResult = @{
                State     = 'Running'
                StartName = $mockSaResource.ServiceAccountCredential.UserName
            }

            $mockGetCimInstanceSecurityTokenServiceResult = @{
                ConfigurationDatabaseConnectionString = $sqlConnectionString
            }

            Mock -CommandName Assert-Module
            Mock -CommandName Assert-DomainMember
            Mock -CommandName Assert-AdfsService
            Mock -CommandName Get-CimInstance `
                -ParameterFilter { $ClassName -eq 'Win32_Service' } `
                -MockWith { $mockGetCimInstanceServiceGsaRunningResult }
            Mock -CommandName Get-CimInstance `
                -ParameterFilter { `
                    $Namespace -eq 'root/ADFS' -and `
                    $ClassName -eq 'SecurityTokenService' } `
                -MockWith { $mockGetCimInstanceSecurityTokenServiceResult }
            Mock -CommandName Get-AdfsSslCertificate -MockWith { $mockGetAdfsSslCertificateResult }
            Mock -CommandName Get-AdfsSyncProperties
            Mock -CommandName Assert-GroupServiceAccount -MockWith { $true }
            Mock -CommandName Get-ObjectType -MockWith { $script:syncPropertiesTypeName }

            Context "When the $($Global:DscResourceFriendlyName) Resource is configured" {
                BeforeAll {
                    Mock -CommandName $ResourceCommand.Get -MockWith { 'Configured' }
                }

                Context "When the configured database is WID" {
                    BeforeAll {
                        Mock -CommandName Get-AdfsSyncProperties -MockWith { $mockGetAdfsSyncPropertiesWid }
                        Mock -CommandName Get-ObjectType -MockWith { $script:syncPropertiesTypeName }

                        $result = Get-TargetResource @getTargetResourceParameters
                    }

                    foreach ($property in $mockGsaWidResource.Keys)
                    {
                        It "Should return the correct $property property" {
                            $result.$property | Should -Be $mockGsaWidResource.$property
                        }
                    }

                    It 'Should call the expected mocks' {
                        Assert-MockCalled -CommandName Assert-Module `
                            -ParameterFilter { $ModuleName -eq $Global:PSModuleName } `
                            -Exactly -Times 1
                        Assert-MockCalled -CommandName Assert-DomainMember -Exactly -Times 1
                        Assert-MockCalled -CommandName Assert-AdfsService -Exactly -Times 1
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
                        Assert-MockCalled -CommandName Get-AdfsSslCertificate -Exactly -Times 1
                        Assert-MockCalled -CommandName Get-AdfsSyncProperties -Exactly -Times 1
                        Assert-MockCalled -CommandName Assert-GroupServiceAccount -Exactly -Times 1
                        Assert-MockCalled -CommandName Get-ObjectType -Exactly -Times 1
                    }

                    Context 'When Get-AdfsSslCertificate throws an exception' {
                        BeforeAll {
                            Mock Get-AdfsSslCertificate -MockWith { throw $mockExceptionErrorMessage }
                        }

                        It 'Should throw the correct exception' {
                            { Get-TargetResource @getTargetResourceParameters } | Should -Throw (
                                $script:localizedData.GettingAdfsSslCertificateErrorMessage -f
                                $mockWidResource.FederationServiceName)
                        }
                    }

                    Context 'When Get-AdfsSslCertificate returns an empty result' {
                        BeforeAll {
                            Mock Get-AdfsSslCertificate
                        }

                        It 'Should throw the correct exception' {
                            { Get-TargetResource @getTargetResourceParameters } | Should -Throw (
                                $script:localizedData.GettingAdfsSslCertificateErrorMessage -f
                                $mockWidResource.FederationServiceName)
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
                                $mockWidResource.FederationServiceName)
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
                                $mockWidResource.FederationServiceName)
                        }
                    }

                    Context 'When Get-AdfsSyncProperties throws an exception' {
                        BeforeAll {
                            Mock Get-AdfsSyncProperties -MockWith { throw $mockExceptionErrorMessage }
                        }

                        It 'Should throw the correct exception' {
                            { Get-TargetResource @getTargetResourceParameters } | Should -Throw (
                                $script:localizedData.GettingAdfsSyncPropertiesErrorMessage -f
                                $mockWidResource.FederationServiceName)
                        }
                    }

                    Context 'When Get-AdfsSyncProperties returns an unexpected type' {
                        BeforeAll {
                            $mockUnexpectedType = 'UnexpectedType'
                            Mock Get-ObjectType -MockWith { $mockUnexpectedType }
                        }

                        It 'Should throw the correct exception' {
                            { Get-TargetResource @getTargetResourceParameters } | Should -Throw (
                                $script:localizedData.UnknownAdfsSyncPropertiesObjectTypeErrorMessage -f
                                $mockUnexpectedType)
                        }
                    }
                }

                Context "When the configured database is SQL" {
                    BeforeAll {
                        Mock -CommandName Get-AdfsSyncProperties
                        Mock -CommandName Get-ObjectType -MockWith { $script:syncPropertiesBaseTypeName }

                        $result = Get-TargetResource @getTargetResourceParameters
                    }

                    foreach ($property in $mockGsaSqlResource.Keys)
                    {
                        It "Should return the correct $property property" {
                            $result.$property | Should -Be $mockGsaSqlResource.$property
                        }
                    }

                    It 'Should call the expected mocks' {
                        Assert-MockCalled -CommandName Assert-Module `
                            -ParameterFilter { $ModuleName -eq $Global:PSModuleName } `
                            -Exactly -Times 1
                        Assert-MockCalled -CommandName Assert-DomainMember -Exactly -Times 1
                        Assert-MockCalled -CommandName Assert-AdfsService -Exactly -Times 1
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
                        Assert-MockCalled -CommandName Get-AdfsSslCertificate -Exactly -Times 1
                        Assert-MockCalled -CommandName Get-AdfsSyncProperties -Exactly -Times 1
                        Assert-MockCalled -CommandName Assert-GroupServiceAccount -Exactly -Times 1
                        Assert-MockCalled -CommandName Get-ObjectType -Exactly -Times 1
                    }
                }
            }

            Context "When the $($Global:DscResourceFriendlyName) Resource is not configured" {
                BeforeAll {
                    Mock -CommandName $ResourceCommand.Get -MockWith { 'NotConfigured' }

                    $result = Get-TargetResource @getTargetResourceParameters
                }

                foreach ($property in $mockGsaWidResource.Keys)
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
                    Assert-MockCalled -CommandName Get-ObjectType -Exactly -Times 0
                }
            }
        }

        Describe 'MSFT_AdfsFarmNode\Set-TargetResource' -Tag 'Set' {
            BeforeAll {
                $setTargetResourceParameters = @{
                    FederationServiceName         = $mockGsaWidResource.FederationServiceName
                    Credential                    = $mockCredential
                    CertificateThumbprint         = $mockGsaWidResource.CertificateThumbprint
                    GroupServiceAccountIdentifier = $mockGsaWidResource.GroupServiceAccountIdentifier
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

                Mock -CommandName $ResourceCommand.Install -MockWith { $mockAddAdfsFarmNodeSuccessResult }
                Mock -CommandName $ResourceCommand.Uninstall
            }

            Context 'When both credential parameters have been specified' {
                BeforeAll {
                    $setTargetResourceBothCredentialParameters = $setTargetResourceParameters.Clone()
                    $setTargetResourceBothCredentialParameters.Add('ServiceAccountCredential', $mockCredential)
                }

                It 'Should throw the correct error' {
                    { Set-TargetResource @setTargetResourceBothCredentialParameters } |
                    Should -Throw ($script:localizedData.ResourceDuplicateCredentialErrorMessage -f
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
                    Should -Throw ($script:localizedData.ResourceMissingCredentialErrorMessage -f
                        $setTargetResourceBothCredentialParameters.FederationServiceName)
                }
            }

            Context "When the $($Global:DscResourceFriendlyName) Resource should be installed" {

                Context "When the $($Global:DscResourceFriendlyName) Resource is not installed" {
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
                        Assert-MockCalled -CommandName $ResourceCommand.Install `
                            -ParameterFilter { `
                                $CertificateThumbprint -eq $setTargetResourcePresentParameters.CertificateThumbprint } `
                            -Exactly -Times 1
                        Assert-MockCalled -CommandName $ResourceCommand.Uninstall -Exactly -Times 0
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
                                -ParameterFilter { `
                                    $CertificateThumbprint -eq $setTargetResourcePresentParameters.CertificateThumbprint } `
                                -Exactly -Times 1
                        }
                    }

                    Context "When $($ResourceCommand.Install) throws an exception" {
                        BeforeAll {
                            Mock $ResourceCommand.Install -MockWith { throw $mockExceptionErrorMessage }
                        }

                        It 'Should throw the correct error' {
                            { Set-TargetResource @setTargetResourcePresentParameters } | Should -Throw (
                                $script:localizedData.InstallationErrorMessage -f
                                $setTargetResourcePresentParameters.FederationServiceName)
                        }
                    }

                    Context "When $($ResourceCommand.Install) returns a result with a status of 'Error'" {
                        BeforeAll {
                            Mock $ResourceCommand.Install -MockWith { $mockAddAdfsFarmNodeErrorResult }
                        }

                        It 'Should throw the correct error' {
                            { Set-TargetResource @setTargetResourceParameters } | Should -Throw (
                                $mockAddAdfsFarmNodeErrorResult.Message)
                        }
                    }
                }

                Context "When the $($Global:DscResourceFriendlyName) Resource is installed" {
                    BeforeAll {
                        Mock -CommandName Get-TargetResource -MockWith { $mockGetTargetGsaWidResourcePresentResult }
                    }

                    It 'Should not throw' {
                        { Set-TargetResource @setTargetResourcePresentParameters } | Should -Not -Throw
                    }
                }
            }

            Context "When the $($Global:DscResourceFriendlyName) Resource should not be installed" {

                Context "When the $($Global:DscResourceFriendlyName) Resource is installed" {
                    BeforeAll {
                        Mock -CommandName Get-TargetResource -MockWith { $mockGetTargetGsaWidResourcePresentResult }
                    }

                    It 'Should not throw' {
                        { Set-TargetResource @setTargetResourceAbsentParameters } | Should -Not -Throw
                    }

                    It 'Should call the expected mocks' {
                        Assert-MockCalled -CommandName $ResourceCommand.Uninstall -Exactly -Times 1
                        Assert-MockCalled -CommandName $ResourceCommand.Install -Exactly -Times 0
                    }

                    Context "When $($ResourceCommand.Uninstall) throws an exception" {
                        BeforeAll {
                            Mock $ResourceCommand.Uninstall -MockWith { throw $mockExceptionErrorMessage }
                        }

                        It 'Should throw the correct error' {
                            { Set-TargetResource @setTargetResourceAbsentParameters } | Should -Throw (
                                $script:localizedData.RemovalErrorMessage -f
                                $setTargetResourceAbsentParameters.FederationServiceName)
                        }
                    }
                }

                Context "When the $($Global:DscResourceFriendlyName) Resource is not installed" {
                    BeforeAll {
                        Mock -CommandName Get-TargetResource -MockWith { $mockGetTargetResourceAbsentResult }
                    }

                    It 'Should not throw' {
                        { Set-TargetResource @setTargetResourceAbsentParameters } | Should -Not -Throw
                    }

                    It 'Should call the expected mocks' {
                        Assert-MockCalled -CommandName $ResourceCommand.Uninstall -Exactly -Times 0
                        Assert-MockCalled -CommandName $ResourceCommand.Install -Exactly -Times 0
                    }
                }
            }
        }

        Describe 'MSFT_AdfsFarmNode\Test-TargetResource' -Tag 'Test' {
            BeforeAll {
                $testTargetResourceParameters = @{
                    FederationServiceName         = $mockGsaWidResource.FederationServiceName
                    Credential                    = $mockCredential
                    CertificateThumbprint         = $mockGsaWidResource.CertificateThumbprint
                    GroupServiceAccountIdentifier = $mockGsaWidResource.GroupServiceAccountIdentifier
                    PrimaryComputerName           = $mockGsaWidResource.PrimaryComputerName
                    PrimaryComputerPort           = $mockGsaWidResource.PrimaryComputerPort
                }

                $testTargetResourcePresentParameters = $testTargetResourceParameters.Clone()
                $testTargetResourcePresentParameters.Ensure = 'Present'

                $testTargetResourceAbsentParameters = $testTargetResourceParameters.Clone()
                $testTargetResourceAbsentParameters.Ensure = 'Absent'
            }

            Context "When the $($Global:DscResourceFriendlyName) Resource is installed" {
                BeforeAll {
                    Mock Get-TargetResource -MockWith { $mockGetTargetGsaWidResourcePresentResult }
                }

                Context "When the $($Global:DscResourceFriendlyName) Resource should be installed" {
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

                Context "When the $($Global:DscResourceFriendlyName) Resource should not be installed" {
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

            Context "When the $($Global:DscResourceFriendlyName) Resource is not installed" {
                BeforeAll {
                    Mock Get-TargetResource -MockWith { $mockGetTargetResourceAbsentResult }
                }

                Context "When the $($Global:DscResourceFriendlyName) Resource should not be installed" {
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

                Context "When the $($Global:DscResourceFriendlyName) Resource should be installed" {
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
