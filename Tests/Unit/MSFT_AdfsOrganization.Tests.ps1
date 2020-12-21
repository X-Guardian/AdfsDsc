$script:dscModuleName = 'AdfsDsc'
$global:psModuleName = 'ADFS'
$script:dscResourceName = 'MSFT_AdfsOrganization'

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
            Get = 'Get-AdfsProperties'
            Set = 'Set-AdfsProperties'
        }

        $mockResource = @{
            FederationServiceName = 'sts.contoso.com'
            DisplayName           = 'Contoso Inc.'
            Name                  = 'Contoso'
            OrganizationUrl       = 'https://www.contoso.com/'
        }

        $mockChangedResource = @{
            DisplayName     = 'Fabrikam Inc.'
            Name            = 'Fabrikam'
            OrganizationUrl = 'https://www.fabrikam.com/'
        }

        $mockGetTargetResourceResult = @{
            FederationServiceName = $mockResource.FederationServiceName
            DisplayName           = $mockResource.DisplayName
            Name                  = $mockResource.Name
            OrganizationUrl       = $mockResource.OrganizationUrl
        }

        Describe 'MSFT_AdfsOrganization\Get-TargetResource' -Tag 'Get' {
            BeforeAll {
                $getTargetResourceParameters = @{
                    FederationServiceName = $mockResource.FederationServiceName
                    DisplayName           = $mockResource.DisplayName
                    Name                  = $mockResource.Name
                    OrganizationUrl       = $mockResource.OrganizationUrl
                }

                Mock -CommandName Assert-Module
                Mock -CommandName "Assert-$($global:psModuleName)Service"
            }

            Context 'When the organization is not empty' {
                BeforeAll {
                    $mockOrganization = New-MockObject -Type Microsoft.IdentityServer.Management.Resources.Organization

                    $mockOrganization.DisplayName = $mockResource.DisplayName
                    $mockOrganization.Name = $mockResource.Name
                    $mockOrganization.OrganizationUrl = $mockResource.OrganizationUrl

                    $mockGetResourceCommandResult = @{
                        OrganizationInfo = $mockOrganization
                    }

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
            }

            Context 'When the organization is empty' {
                BeforeAll {
                    $mockGetResourceCommandEmptyResult = @{
                        OrganizationInfo = $null
                    }

                    Mock -CommandName $ResourceCommand.Get -MockWith { $mockGetResourceCommandEmptyResult }

                    $result = Get-TargetResource @getTargetResourceParameters
                }

                foreach ($property in $mockResource.Keys)
                {
                    It "Should return the correct $property property" {
                        if ($property -eq 'FederationServiceName')
                        {
                            $result.$property | Should -Be $mockResource.FederationServiceName
                        }
                        else
                        {
                            $result.$property | Should -BeNullOrEmpty
                        }
                    }
                }

                It 'Should call the expected mocks' {
                    Assert-MockCalled -CommandName Assert-Module `
                        -ParameterFilter { $ModuleName -eq $global:psModuleName } `
                        -Exactly -Times 1
                    Assert-MockCalled -CommandName "Assert-$($global:psModuleName)Service" -Exactly -Times 1
                    Assert-MockCalled -CommandName $ResourceCommand.Get -Exactly -Times 1
                }
            }

            Context "When $($ResourceCommand.Get) throws an exception" {
                BeforeAll {
                    Mock -CommandName $ResourceCommand.Get -MockWith { Throw 'Error' }
                }

                It 'Should throw the correct exception' {
                    { Get-TargetResource @getTargetResourceParameters } | Should -Throw (
                        $script:localizedData.GettingResourceErrorMessage -f $getTargetResourceParameters.FederationServiceName )
                }
            }
        }

        Describe 'MSFT_AdfsOrganization\Set-TargetResource' -Tag 'Set' {
            BeforeAll {
                $setTargetResourceParameters = @{
                    FederationServiceName = $mockResource.FederationServiceName
                    DisplayName           = $mockResource.DisplayName
                    Name                  = $mockResource.Name
                    OrganizationUrl       = $mockResource.OrganizationUrl
                }

                Mock -CommandName $ResourceCommand.Set
                Mock -CommandName New-AdfsOrganization -MockWith { New-MockObject -Type Microsoft.IdentityServer.Management.Resources.Organization }
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
                                $FederationServiceName -eq $setTargetResourceParametersChangedProperty.FederationServiceName } `
                            -Exactly -Times 1
                        Assert-MockCalled -CommandName $ResourceCommand.Set -Exactly -Times 1
                        Assert-MockCalled -CommandName New-AdfsOrganization -Exactly -Times 1
                    }
                }
            }

            Context 'When all the properties are empty' {
                BeforeAll {
                    $setEmptyTargetResourceParameters = @{
                        FederationServiceName = $mockResource.FederationServiceName
                        DisplayName           = ''
                        Name                  = ''
                        OrganizationUrl       = ''
                    }
                }

                It 'Should not throw' {
                    { Set-TargetResource @setEmptyTargetResourceParameters } | Should -Not -Throw
                }

                It 'Should call the correct mocks' {
                    Assert-MockCalled -CommandName Get-TargetResource `
                        -ParameterFilter { `
                            $FederationServiceName -eq $setEmptyTargetResourceParameters.FederationServiceName } `
                        -Exactly -Times 1
                    Assert-MockCalled -CommandName $ResourceCommand.Set -Exactly -Times 1
                    Assert-MockCalled -CommandName New-AdfsOrganization -Exactly -Times 0
                }
            }

            Context 'When New-AdfsOrganization throws an exception' {
                BeforeAll {
                    Mock -CommandName New-AdfsOrganization -MockWith { Throw 'Error' }
                }

                It 'Should throw the correct exception' {
                    { Set-TargetResource @setTargetResourceParameters } | Should -Throw (
                        $script:localizedData.NewAdfsOrganizationErrorMessage -f $setTargetResourceParameters.FederationServiceName )
                }
            }

            Context "When $($ResourceCommand.Set) throws an exception" {
                BeforeAll {
                    Mock -CommandName $ResourceCommand.Set -MockWith { Throw 'Error' }
                }

                It 'Should throw the correct exception' {
                    { Set-TargetResource @setTargetResourceParameters } | Should -Throw (
                        $script:localizedData.SettingResourceErrorMessage -f $setTargetResourceParameters.FederationServiceName )
                }
            }
        }

        Describe 'MSFT_AdfsOrganization\Test-TargetResource' -Tag 'Test' {
            BeforeAll {
                $testTargetResourceParameters = @{
                    FederationServiceName = $mockResource.FederationServiceName
                    DisplayName           = $mockResource.DisplayName
                    Name                  = $mockResource.Name
                    OrganizationUrl       = $mockResource.OrganizationUrl
                }

                Mock -CommandName Get-TargetResource -MockWith { $mockGetTargetResourceResult }
            }

            It 'Should not throw' {
                { Test-TargetResource @testTargetResourceParameters } | Should -Not -Throw
            }

            It 'Should call the expected mocks' {
                Assert-MockCalled -CommandName Get-TargetResource `
                    -ParameterFilter { $FederationServiceName -eq $testTargetResourceParameters.FederationServiceName } `
                    -Exactly -Times 1
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
