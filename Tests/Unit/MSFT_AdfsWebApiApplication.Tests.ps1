$Global:DSCModuleName = 'AdfsDsc'
$Global:PSModuleName = 'ADFS'
$Global:DSCResourceName = 'MSFT_AdfsWebApiApplication'

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

        # Define Resource Commands
        $ResourceCommand = @{
            Get    = 'Get-AdfsWebApiApplication'
            Set    = 'Set-AdfsWebApiApplication'
            Add    = 'Add-AdfsWebApiApplication'
            Remove = 'Remove-AdfsWebApiApplication'
        }

        $mockResource = @{
            Name                                 = 'AppGroup1 - Web API'
            ApplicationGroupIdentifier           = 'AppGroup1'
            Identifier                           = 'e7bfb303-c5f6-4028-a360-b6293d41338c'
            Description                          = 'App1 Web Api'
            AccessControlPolicyName              = 'Permit everyone'
            AllowedAuthenticationClassReferences = @()
            ClaimsProviderName                   = @()
            IssuanceAuthorizationRules           = 'rule'
            DelegationAuthorizationRules         = 'rule'
            ImpersonationAuthorizationRules      = 'rule'
            IssuanceTransformRules               = 'rule'
            AdditionalAuthenticationRules        = 'rule'
            NotBeforeSkew                        = 5
            TokenLifetime                        = 90
            AlwaysRequireAuthentication          = $false
            AllowedClientTypes                   = 'Public'
            IssueOAuthRefreshTokensTo            = 'AllDevices'
            RefreshTokenProtectionEnabled        = $true
            RequestMFAFromClaimsProviders        = $true
            Ensure                               = 'Present'
        }

        $mockAbsentResource = @{
            Name                                 = 'AppGroup1 - Web API'
            ApplicationGroupIdentifier           = 'AppGroup1'
            Identifier                           = 'e7bfb303-c5f6-4028-a360-b6293d41338c'
            Description                          = $null
            AllowedAuthenticationClassReferences = @()
            ClaimsProviderName                   = @()
            IssuanceAuthorizationRules           = $null
            DelegationAuthorizationRules         = $null
            ImpersonationAuthorizationRules      = $null
            IssuanceTransformRules               = $null
            AdditionalAuthenticationRules        = $null
            AccessControlPolicyName              = $null
            NotBeforeSkew                        = 0
            TokenLifetime                        = 0
            AlwaysRequireAuthentication          = $null
            AllowedClientTypes                   = 'None'
            IssueOAuthRefreshTokensTo            = 'NoDevice'
            RefreshTokenProtectionEnabled        = $false
            RequestMFAFromClaimsProviders        = $false
            Ensure                               = 'Absent'
        }

        $mockChangedResource = @{
            ApplicationGroupIdentifier           = 'AppGroup2'
            Identifier                           = 'e7bfb303-c5f6-4028-a360-b6293d41338d'
            Description                          = 'App2 Web Api'
            AccessControlPolicyName              = 'changed'
            AllowedAuthenticationClassReferences = 'changed'
            ClaimsProviderName                   = 'changed'
            IssuanceAuthorizationRules           = 'changedrule'
            DelegationAuthorizationRules         = 'changedrule'
            ImpersonationAuthorizationRules      = 'changedrule'
            IssuanceTransformRules               = 'changedrule'
            AdditionalAuthenticationRules        = 'changedrule'
            NotBeforeSkew                        = 10
            TokenLifetime                        = 180
            AlwaysRequireAuthentication          = $true
            AllowedClientTypes                   = 'Confidential'
            IssueOAuthRefreshTokensTo            = 'WorkplaceJoinedDevices'
            RefreshTokenProtectionEnabled        = $false
            RequestMFAFromClaimsProviders        = $false
        }

        $mockGetTargetResourceResult = @{
            Name                                 = $mockResource.Name
            ApplicationGroupIdentifier           = $mockResource.ApplicationGroupIdentifier
            Identifier                           = $mockResource.Identifier
            Description                          = $mockResource.Description
            AccessControlPolicyName              = $mockResource.AccessControlPolicyName
            AllowedAuthenticationClassReferences = $mockResource.AllowedAuthenticationClassReferences
            ClaimsProviderName                   = $mockResource.ClaimsProviderName
            IssuanceAuthorizationRules           = $mockResource.IssuanceAuthorizationRules
            DelegationAuthorizationRules         = $mockResource.DelegationAuthorizationRules
            ImpersonationAuthorizationRules      = $mockResource.ImpersonationAuthorizationRules
            IssuanceTransformRules               = $mockResource.IssuanceTransformRules
            AdditionalAuthenticationRules        = $mockResource.AdditionalAuthenticationRules
            NotBeforeSkew                        = $mockResource.NotBeforeSkew
            TokenLifetime                        = $mockResource.TokenLifetime
            AlwaysRequireAuthentication          = $mockResource.AlwaysRequireAuthentication
            AllowedClientTypes                   = $mockResource.AllowedClientTypes
            IssueOAuthRefreshTokensTo            = $mockResource.IssueOAuthRefreshTokensTo
            RefreshTokenProtectionEnabled        = $mockResource.RefreshTokenProtectionEnabled
            RequestMFAFromClaimsProviders        = $mockResource.RequestMFAFromClaimsProviders
        }

        $mockGetTargetResourcePresentResult = $mockGetTargetResourceResult.Clone()
        $mockGetTargetResourcePresentResult.Ensure = 'Present'

        $mockGetTargetResourceAbsentResult = $mockGetTargetResourceResult.Clone()
        $mockGetTargetResourceAbsentResult.Ensure = 'Absent'

        Describe "$Global:DSCResourceName\Get-TargetResource" -Tag 'Get' {
            $getTargetResourceParameters = @{
                Name                       = $mockResource.Name
                ApplicationGroupIdentifier = $mockResource.ApplicationGroupIdentifier
                Identifier                 = $mockResource.Identifier
            }

            $mockGetResourceCommandResult = @{
                Name                                 = $mockResource.Name
                ApplicationGroupIdentifier           = $mockResource.ApplicationGroupIdentifier
                Identifier                           = $mockResource.Identifier
                Description                          = $mockResource.Description
                AccessControlPolicyName              = $mockResource.AccessControlPolicyName
                AllowedAuthenticationClassReferences = $mockResource.AllowedAuthenticationClassReferences
                ClaimsProviderName                   = $mockResource.ClaimsProviderName
                IssuanceAuthorizationRules           = $mockResource.IssuanceAuthorizationRules
                DelegationAuthorizationRules         = $mockResource.DelegationAuthorizationRules
                ImpersonationAuthorizationRules      = $mockResource.ImpersonationAuthorizationRules
                IssuanceTransformRules               = $mockResource.IssuanceTransformRules
                AdditionalAuthenticationRules        = $mockResource.AdditionalAuthenticationRules
                NotBeforeSkew                        = $mockResource.NotBeforeSkew
                TokenLifetime                        = $mockResource.TokenLifetime
                AlwaysRequireAuthentication          = $mockResource.AlwaysRequireAuthentication
                AllowedClientTypes                   = $mockResource.AllowedClientTypes
                IssueOAuthRefreshTokensTo            = $mockResource.IssueOAuthRefreshTokensTo
                RefreshTokenProtectionEnabled        = $mockResource.RefreshTokenProtectionEnabled
                RequestMFAFromClaimsProviders        = $mockResource.RequestMFAFromClaimsProviders
            }

            Mock -CommandName Assert-Module
            Mock -CommandName Assert-Command
            Mock -CommandName Assert-AdfsService

            Context 'When the Resource is Present' {
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
                    Assert-MockCalled -CommandName Assert-Command `
                        -ParameterFilter { $Module -eq $Global:PSModuleName -and $Command -eq $ResourceCommand.Get } `
                        -Exactly -Times 1
                    Assert-MockCalled -CommandName Assert-AdfsService -Exactly -Times 1
                    Assert-MockCalled -CommandName $ResourceCommand.Get -Exactly -Times 1
                }
            }

            Context 'When the Resource is Absent' {
                Mock -CommandName $ResourceCommand.Get

                $result = Get-TargetResource @getTargetResourceParameters

                foreach ($property in $mockAbsentResource.Keys)
                {
                    It "Should return the correct $property property" {
                        $result.$property | Should -Be $mockAbsentResource.$property
                    }
                }

                It 'Should call the expected mocks' {
                    Assert-MockCalled -CommandName Assert-Module `
                        -ParameterFilter { $ModuleName -eq $Global:PSModuleName } `
                        -Exactly -Times 1
                    Assert-MockCalled -CommandName Assert-Command `
                        -ParameterFilter { $Module -eq $Global:PSModuleName -and $Command -eq $ResourceCommand.Get } `
                        -Exactly -Times 1
                    Assert-MockCalled -CommandName Assert-AdfsService -Exactly -Times 1
                    Assert-MockCalled -CommandName $ResourceCommand.Get -Exactly -Times 1
                }
            }
        }

        Describe "$Global:DSCResourceName\Set-TargetResource" -Tag 'Set' {
            $setTargetResourceParameters = @{
                Name                                 = $mockResource.Name
                ApplicationGroupIdentifier           = $mockResource.ApplicationGroupIdentifier
                Identifier                           = $mockResource.Identifier
                Description                          = $mockResource.Description
                AccessControlPolicyName              = $mockResource.AccessControlPolicyName
                AllowedAuthenticationClassReferences = $mockResource.AllowedAuthenticationClassReferences
                ClaimsProviderName                   = $mockResource.ClaimsProviderName
                IssuanceAuthorizationRules           = $mockResource.IssuanceAuthorizationRules
                DelegationAuthorizationRules         = $mockResource.DelegationAuthorizationRules
                ImpersonationAuthorizationRules      = $mockResource.ImpersonationAuthorizationRules
                IssuanceTransformRules               = $mockResource.IssuanceTransformRules
                AdditionalAuthenticationRules        = $mockResource.AdditionalAuthenticationRules
                NotBeforeSkew                        = $mockResource.NotBeforeSkew
                TokenLifetime                        = $mockResource.TokenLifetime
                AlwaysRequireAuthentication          = $mockResource.AlwaysRequireAuthentication
                AllowedClientTypes                   = $mockResource.AllowedClientTypes
                IssueOAuthRefreshTokensTo            = $mockResource.IssueOAuthRefreshTokensTo
                RefreshTokenProtectionEnabled        = $mockResource.RefreshTokenProtectionEnabled
                RequestMFAFromClaimsProviders        = $mockResource.RequestMFAFromClaimsProviders
            }

            $setTargetResourcePresentParameters = $setTargetResourceParameters.Clone()
            $setTargetResourcePresentParameters.Ensure = 'Present'

            $setTargetResourceAbsentParameters = $setTargetResourceParameters.Clone()
            $setTargetResourceAbsentParameters.Ensure = 'Absent'

            Mock -CommandName $ResourceCommand.Set
            Mock -CommandName $ResourceCommand.Add
            Mock -CommandName $ResourceCommand.Remove

            Context 'When the Resource is Present' {
                Mock -CommandName Get-TargetResource -MockWith { $mockGetTargetResourcePresentResult }

                Context 'When the Resource should be Present' {
                    It 'Should not throw' {
                        { Set-TargetResource @setTargetResourcePresentParameters } | Should -Not -Throw
                    }

                    It 'Should call the expected mocks' {
                        Assert-MockCalled -CommandName Get-TargetResource `
                            -ParameterFilter { $Name -eq $setTargetResourcePresentParameters.Name } `
                            -Exactly -Times 1
                        Assert-MockCalled -CommandName $ResourceCommand.Set -Exactly -Times 1
                        Assert-MockCalled -CommandName $ResourceCommand.Add -Exactly -Times 0
                        Assert-MockCalled -CommandName $ResourceCommand.Remove -Exactly -Times 0
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
                        Assert-MockCalled -CommandName $ResourceCommand.Remove -Exactly -Times 1
                        Assert-MockCalled -CommandName $ResourceCommand.Set -Exactly -Times 0
                        Assert-MockCalled -CommandName $ResourceCommand.Add -Exactly -Times 0
                    }
                }
            }

            Context 'When the Resource is Absent' {
                Mock -CommandName Get-TargetResource -MockWith { $mockGetTargetResourceAbsentResult }

                Context 'When the Resource should be Present' {
                    It 'Should not throw' {
                        { Set-TargetResource @setTargetResourcePresentParameters } | Should -Not -Throw
                    }

                    It 'Should call the expected mocks' {
                        Assert-MockCalled -CommandName Get-TargetResource `
                            -ParameterFilter { $Name -eq $setTargetResourcePresentParameters.Name } `
                            -Exactly -Times 1
                        Assert-MockCalled -CommandName $ResourceCommand.Add -Exactly -Times 1
                        Assert-MockCalled -CommandName $ResourceCommand.Set -Exactly -Times 0
                        Assert-MockCalled -CommandName $ResourceCommand.Remove -Exactly -Times 0
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

        Describe "$Global:DSCResourceName\Test-TargetResource" -Tag 'Test' {
            $testTargetResourceParameters = @{
                Name                                 = $mockResource.Name
                ApplicationGroupIdentifier           = $mockResource.ApplicationGroupIdentifier
                Identifier                           = $mockResource.Identifier
                Description                          = $mockResource.Description
                AccessControlPolicyName              = $mockResource.AccessControlPolicyName
                AllowedAuthenticationClassReferences = $mockResource.AllowedAuthenticationClassReferences
                ClaimsProviderName                   = $mockResource.ClaimsProviderName
                IssuanceAuthorizationRules           = $mockResource.IssuanceAuthorizationRules
                DelegationAuthorizationRules         = $mockResource.DelegationAuthorizationRules
                ImpersonationAuthorizationRules      = $mockResource.ImpersonationAuthorizationRules
                IssuanceTransformRules               = $mockResource.IssuanceTransformRules
                AdditionalAuthenticationRules        = $mockResource.AdditionalAuthenticationRules
                NotBeforeSkew                        = $mockResource.NotBeforeSkew
                TokenLifetime                        = $mockResource.TokenLifetime
                AlwaysRequireAuthentication          = $mockResource.AlwaysRequireAuthentication
                AllowedClientTypes                   = $mockResource.AllowedClientTypes
                IssueOAuthRefreshTokensTo            = $mockResource.IssueOAuthRefreshTokensTo
                RefreshTokenProtectionEnabled        = $mockResource.RefreshTokenProtectionEnabled
                RequestMFAFromClaimsProviders        = $mockResource.RequestMFAFromClaimsProviders
            }

            $testTargetResourcePresentParameters = $testTargetResourceParameters.Clone()
            $testTargetResourcePresentParameters.Ensure = 'Present'

            $testTargetResourceAbsentParameters = $testTargetResourceParameters.Clone()
            $testTargetResourceAbsentParameters.Ensure = 'Absent'

            Context 'When the Resource is Present' {
                Mock -CommandName Get-TargetResource -MockWith { $mockGetTargetResourcePresentResult }

                Context 'When the Resource should be Present' {
                    It 'Should not throw' {
                        { Test-TargetResource @testTargetResourcePresentParameters } | Should -Not -Throw
                    }

                    It 'Should call the expected mocks' {
                        Assert-MockCalled -CommandName Get-TargetResource `
                            -ParameterFilter { $Name -eq $testTargetResourcePresentParameters.Name } `
                            -Exactly -Times 1
                    }

                    Context 'When all the resource properties are in the desired state' {
                        It 'Should return $true' {
                            Test-TargetResource @testTargetResourcePresentParameters | Should -Be $true
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

                Context 'When the Resource should be Absent' {
                    It 'Should not throw' {
                        { Test-TargetResource @testTargetResourceAbsentParameters } | Should -Not -Throw
                    }

                    It 'Should call the expected mocks' {
                        Assert-MockCalled -CommandName Get-TargetResource `
                            -ParameterFilter { $Name -eq $testTargetResourceAbsentParameters.Name } `
                            -Exactly -Times 1
                    }

                    It 'Should return $false' {
                        Test-TargetResource @testTargetResourceAbsentParameters | Should -Be $false
                    }
                }
            }

            Context 'When the Resource is Absent' {
                Mock -CommandName Get-TargetResource -MockWith { $mockGetTargetResourceAbsentResult }

                Context 'When the Resource should be Present' {
                    It 'Should not throw' {
                        { Test-TargetResource @testTargetResourcePresentParameters } | Should -Not -Throw
                    }

                    It 'Should call the expected mocks' {
                        Assert-MockCalled -CommandName Get-TargetResource `
                            -ParameterFilter { $Name -eq $testTargetResourcePresentParameters.Name } `
                            -Exactly -Times 1
                    }

                    It 'Should return $false' {
                        Test-TargetResource @testTargetResourcePresentParameters | Should -Be $false
                    }
                }

                Context 'When the Resource should be Absent' {
                    It 'Should not throw' {
                        { Test-TargetResource @testTargetResourceAbsentParameters } | Should -Not -Throw
                    }

                    It 'Should call the expected mocks' {
                        Assert-MockCalled -CommandName Get-TargetResource `
                            -ParameterFilter { $Name -eq $testTargetResourceAbsentParameters.Name } `
                            -Exactly -Times 1
                    }

                    It 'Should return $true' {
                        Test-TargetResource @testTargetResourceAbsentParameters | Should -Be $true
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
