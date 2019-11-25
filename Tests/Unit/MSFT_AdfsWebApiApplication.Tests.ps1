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
        # Import Stub Module
        Import-Module (Join-Path -Path $PSScriptRoot -ChildPath "Stubs\$($Global:PSModuleName)Stub.psm1") -Force

        # Define Resource Commands
        $ResourceCommand = @{
            Get    = 'Get-AdfsWebApiApplication'
            Set    = 'Set-AdfsWebApiApplication'
            Add    = 'Add-AdfsWebApiApplication'
            Remove = 'Remove-AdfsWebApiApplication'
        }

        $mockError = 'Error'

        $mockLdapAttributes = @(
            'mail'
            'sn'
        )

        $mockOutgoingClaimTypes = @(
            'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress'
            'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname'
        )

        $mockMSFTAdfsLdapMappingProperties = @(
            @{
                LdapAttribute     = $mockLdapAttributes[0]
                OutgoingClaimType = $mockOutgoingClaimTypes[0]
            }
            @{
                LdapAttribute     = $mockLdapAttributes[1]
                OutgoingClaimType = $mockOutgoingClaimTypes[1]
            }
        )

        $mockTemplateName = 'LdapClaims'
        $mockRuleName = 'Test'

        $mockLdapMapping = [CIMInstance[]]@(
            New-CimInstance -ClassName MSFT_AdfsLdapMapping `
                -Namespace root/microsoft/Windows/DesiredStateConfiguration `
                -Property $mockMSFTAdfsLdapMappingProperties[0] -ClientOnly
            New-CimInstance -ClassName MSFT_AdfsLdapMapping `
                -Namespace root/microsoft/Windows/DesiredStateConfiguration `
                -Property $mockMSFTAdfsLdapMappingProperties[1] -ClientOnly
        )

        $mockMSFTAdfsIssuanceTransformRuleProperties = @{
            TemplateName   = $mockTemplateName
            Name           = $mockRuleName
            AttributeStore = 'Active Directory'
            LdapMapping    = $mockLdapMapping
        }


        $mockIssuanceTransformRules = [CIMInstance[]]@(
            New-CimInstance -ClassName MSFT_AdfsIssuanceTransformRule `
                -Namespace root/microsoft/Windows/DesiredStateConfiguration `
                -Property $mockMSFTAdfsIssuanceTransformRuleProperties -ClientOnly
        )

        $mockLdapClaimsTransformRule = @(
            '@RuleTemplate = "{0}"' -f $mockTemplateName
            '@RuleName = "{0}"' -f $mockRuleName
            'c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname", Issuer == "AD AUTHORITY"]'
            '=> issue(store = "Active Directory", types = ("{1}", "{2}"), query = ";{3},{4};{0}", param = c.Value);' -f `
                '{0}', $mockOutgoingClaimTypes[0], $mockOutgoingClaimTypes[1], $mockLdapAttributes[0], $mockLdapAttributes[1]
        ) | Out-String

        $mockGroups = 'CONTOSO\Group1', 'CONTOSO\Group2'

        $mockMSFTAccessControlPolicyParametersProperties = @{
            GroupParameter = $mockGroups
        }

        $mockAccessControlPolicyParameters = New-CimInstance -ClassName MSFT_AdfsAccessControlPolicyParameters `
            -Namespace root/microsoft/Windows/DesiredStateConfiguration `
            -Property $mockMSFTAccessControlPolicyParametersProperties -ClientOnly

        $mockGroupAccessControlPolicyParameters = @{
            GroupParameter = $mockGroups
        }

        $mockResource = @{
            Name                                 = 'AppGroup1 - Web API'
            ApplicationGroupIdentifier           = 'AppGroup1'
            Identifier                           = 'e7bfb303-c5f6-4028-a360-b6293d41338c'
            AccessControlPolicyName              = 'Permit everyone'
            AccessControlPolicyParameters        = $mockAccessControlPolicyParameters
            AdditionalAuthenticationRules        = 'rule'
            AllowedAuthenticationClassReferences = @()
            AllowedClientTypes                   = 'Public'
            AlwaysRequireAuthentication          = $false
            ClaimsProviderName                   = @()
            DelegationAuthorizationRules         = 'rule'
            Description                          = 'App1 Web Api'
            ImpersonationAuthorizationRules      = 'rule'
            IssuanceAuthorizationRules           = 'rule'
            IssuanceTransformRules               = $mockIssuanceTransformRules
            IssueOAuthRefreshTokensTo            = 'AllDevices'
            NotBeforeSkew                        = 5
            RefreshTokenProtectionEnabled        = $true
            RequestMFAFromClaimsProviders        = $true
            TokenLifetime                        = 90
            Ensure                               = 'Present'
        }

        $mockAbsentResource = @{
            Name                                 = 'AppGroup1 - Web API'
            ApplicationGroupIdentifier           = 'AppGroup1'
            Identifier                           = 'e7bfb303-c5f6-4028-a360-b6293d41338c'
            AccessControlPolicyName              = $null
            AccessControlPolicyParameters        = $null
            AdditionalAuthenticationRules        = $null
            AllowedAuthenticationClassReferences = @()
            AllowedClientTypes                   = 'None'
            AlwaysRequireAuthentication          = $null
            ClaimsProviderName                   = @()
            DelegationAuthorizationRules         = $null
            Description                          = $null
            ImpersonationAuthorizationRules      = $null
            IssuanceAuthorizationRules           = $null
            IssuanceTransformRules               = $null
            IssueOAuthRefreshTokensTo            = 'NoDevice'
            NotBeforeSkew                        = 0
            RefreshTokenProtectionEnabled        = $false
            RequestMFAFromClaimsProviders        = $false
            TokenLifetime                        = 0
            Ensure                               = 'Absent'
        }

        $mockChangedMSFTAdfsLdapMappingProperties = @{
            LdapAttribute     = 'givenname'
            OutgoingClaimType = 'givenName'
        }

        $mockLdapChangedMapping = [CIMInstance[]]@(
            New-CimInstance -ClassName MSFT_AdfsLdapMapping `
                -Namespace root/microsoft/Windows/DesiredStateConfiguration `
                -Property $mockChangedMSFTAdfsLdapMappingProperties -ClientOnly
        )

        $mockChangedMSFTAdfsIssuanceTransformRuleProperties = @{
            TemplateName   = 'LdapClaims'
            Name           = 'Test2'
            AttributeStore = 'ActiveDirectory'
            LdapMapping    = $mockLdapChangedMapping
        }

        $mockChangedIssuanceTransformRules = [CIMInstance[]]@(
            New-CimInstance -ClassName MSFT_AdfsIssuanceTransformRule `
                -Namespace root/microsoft/Windows/DesiredStateConfiguration `
                -Property $mockChangedMSFTAdfsIssuanceTransformRuleProperties -ClientOnly
        )

        $mockChangedGroups = 'CONTOSO\Group3', 'CONTOSO\Group4'

        $mockChangedMSFTAccessControlPolicyParametersProperties = @{
            GroupParameter = $mockChangedGroups
        }

        $mockChangedAccessControlPolicyParameters = New-CimInstance -ClassName MSFT_AccessControlPolicyParameters `
            -Namespace root/microsoft/Windows/DesiredStateConfiguration `
            -Property $mockChangedMSFTAccessControlPolicyParametersProperties -ClientOnly

        $mockChangedResource = @{
            Identifier                           = 'e7bfb303-c5f6-4028-a360-b6293d41338d'
            AccessControlPolicyName              = 'changed'
            AccessControlPolicyParameters        = $mockChangedAccessControlPolicyParameters
            AdditionalAuthenticationRules        = 'changedrule'
            AllowedAuthenticationClassReferences = 'changed'
            AllowedClientTypes                   = 'Confidential'
            AlwaysRequireAuthentication          = $true
            ClaimsProviderName                   = 'changed'
            DelegationAuthorizationRules         = 'changedrule'
            Description                          = 'App2 Web Api'
            ImpersonationAuthorizationRules      = 'changedrule'
            IssuanceAuthorizationRules           = 'changedrule'
            IssuanceTransformRules               = $mockChangedIssuanceTransformRules
            IssueOAuthRefreshTokensTo            = 'WorkplaceJoinedDevices'
            NotBeforeSkew                        = 10
            RefreshTokenProtectionEnabled        = $false
            RequestMFAFromClaimsProviders        = $false
            TokenLifetime                        = 180
        }

        $mockChangedApplicationGroupIdentifier = 'AppGroup2'

        $mockGetTargetResourceResult = @{
            Name                                 = $mockResource.Name
            ApplicationGroupIdentifier           = $mockResource.ApplicationGroupIdentifier
            Identifier                           = $mockResource.Identifier
            AccessControlPolicyName              = $mockResource.AccessControlPolicyName
            AccessControlPolicyParameters        = $mockResource.AccessControlPolicyParameters
            AdditionalAuthenticationRules        = $mockResource.AdditionalAuthenticationRules
            AllowedAuthenticationClassReferences = $mockResource.AllowedAuthenticationClassReferences
            AllowedClientTypes                   = $mockResource.AllowedClientTypes
            AlwaysRequireAuthentication          = $mockResource.AlwaysRequireAuthentication
            ClaimsProviderName                   = $mockResource.ClaimsProviderName
            DelegationAuthorizationRules         = $mockResource.DelegationAuthorizationRules
            Description                          = $mockResource.Description
            ImpersonationAuthorizationRules      = $mockResource.ImpersonationAuthorizationRules
            IssuanceTransformRules               = $mockResource.IssuanceTransformRules
            IssuanceAuthorizationRules           = $mockResource.IssuanceAuthorizationRules
            IssueOAuthRefreshTokensTo            = $mockResource.IssueOAuthRefreshTokensTo
            NotBeforeSkew                        = $mockResource.NotBeforeSkew
            RefreshTokenProtectionEnabled        = $mockResource.RefreshTokenProtectionEnabled
            RequestMFAFromClaimsProviders        = $mockResource.RequestMFAFromClaimsProviders
            TokenLifetime                        = $mockResource.TokenLifetime
        }

        $mockGetTargetResourcePresentResult = $mockGetTargetResourceResult.Clone()
        $mockGetTargetResourcePresentResult.Ensure = 'Present'

        $mockGetTargetResourceAbsentResult = $mockGetTargetResourceResult.Clone()
        $mockGetTargetResourceAbsentResult.Ensure = 'Absent'

        Describe 'MSFT_AdfsWebApiApplication\Get-TargetResource' -Tag 'Get' {
            BeforeAll {
                $getTargetResourceParameters = @{
                    Name                       = $mockResource.Name
                    ApplicationGroupIdentifier = $mockResource.ApplicationGroupIdentifier
                    Identifier                 = $mockResource.Identifier
                }

                $mockGetResourceCommandResult = @{
                    Name                                 = $mockResource.Name
                    ApplicationGroupIdentifier           = $mockResource.ApplicationGroupIdentifier
                    Identifier                           = $mockResource.Identifier
                    AccessControlPolicyName              = $mockResource.AccessControlPolicyName
                    AccessControlPolicyParameters        = $mockGroupAccessControlPolicyParameters
                    AdditionalAuthenticationRules        = $mockResource.AdditionalAuthenticationRules
                    AllowedAuthenticationClassReferences = $mockResource.AllowedAuthenticationClassReferences
                    AllowedClientTypes                   = $mockResource.AllowedClientTypes
                    AlwaysRequireAuthentication          = $mockResource.AlwaysRequireAuthentication
                    ClaimsProviderName                   = $mockResource.ClaimsProviderName
                    DelegationAuthorizationRules         = $mockResource.DelegationAuthorizationRules
                    Description                          = $mockResource.Description
                    ImpersonationAuthorizationRules      = $mockResource.ImpersonationAuthorizationRules
                    IssuanceAuthorizationRules           = $mockResource.IssuanceAuthorizationRules
                    IssuanceTransformRules               = $mockLdapClaimsTransformRule
                    IssueOAuthRefreshTokensTo            = $mockResource.IssueOAuthRefreshTokensTo
                    NotBeforeSkew                        = $mockResource.NotBeforeSkew
                    RefreshTokenProtectionEnabled        = $mockResource.RefreshTokenProtectionEnabled
                    RequestMFAFromClaimsProviders        = $mockResource.RequestMFAFromClaimsProviders
                    TokenLifetime                        = $mockResource.TokenLifetime
                }

                Mock -CommandName Assert-Module
                Mock -CommandName Assert-Command
                Mock -CommandName Assert-AdfsService
            }

            Context 'When the Resource is Present' {
                BeforeAll {
                    Mock -CommandName $ResourceCommand.Get -MockWith { $mockGetResourceCommandResult }

                    $result = Get-TargetResource @getTargetResourceParameters
                }

                foreach ($property in $mockResource.Keys)
                {
                    It "Should return the correct $property property" {
                        # Using ConvertTo-Json to support comparing custom objects
                        $result.$property | ConvertTo-Json | Should -Be ($mockResource.$property | ConvertTo-Json)
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
                    Assert-MockCalled -CommandName $ResourceCommand.Get `
                        -ParameterFilter { $Name -eq $getTargetResourceParameters.Name } `
                        -Exactly -Times 1
                }
            }

            Context 'When the Resource is Absent' {
                BeforeAll {
                    Mock -CommandName $ResourceCommand.Get

                    $result = Get-TargetResource @getTargetResourceParameters
                }

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
                    Assert-MockCalled -CommandName "Assert-AdfsService" -Exactly -Times 1
                    Assert-MockCalled -CommandName $ResourceCommand.Get `
                        -ParameterFilter { $Name -eq $getTargetResourceParameters.Name } `
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

        Describe 'MSFT_AdfsWebApiApplication\Set-TargetResource' -Tag 'Set' {
            BeforeAll {
                $setTargetResourceParameters = @{
                    Name                                 = $mockResource.Name
                    ApplicationGroupIdentifier           = $mockResource.ApplicationGroupIdentifier
                    Identifier                           = $mockResource.Identifier
                    AccessControlPolicyName              = $mockResource.AccessControlPolicyName
                    AccessControlPolicyParameters        = $mockResource.AccessControlPolicyParameters
                    AdditionalAuthenticationRules        = $mockResource.AdditionalAuthenticationRules
                    AllowedClientTypes                   = $mockResource.AllowedClientTypes
                    AllowedAuthenticationClassReferences = $mockResource.AllowedAuthenticationClassReferences
                    AlwaysRequireAuthentication          = $mockResource.AlwaysRequireAuthentication
                    ClaimsProviderName                   = $mockResource.ClaimsProviderName
                    DelegationAuthorizationRules         = $mockResource.DelegationAuthorizationRules
                    Description                          = $mockResource.Description
                    ImpersonationAuthorizationRules      = $mockResource.ImpersonationAuthorizationRules
                    IssuanceAuthorizationRules           = $mockResource.IssuanceAuthorizationRules
                    IssuanceTransformRules               = $mockResource.IssuanceTransformRules
                    IssueOAuthRefreshTokensTo            = $mockResource.IssueOAuthRefreshTokensTo
                    NotBeforeSkew                        = $mockResource.NotBeforeSkew
                    RefreshTokenProtectionEnabled        = $mockResource.RefreshTokenProtectionEnabled
                    RequestMFAFromClaimsProviders        = $mockResource.RequestMFAFromClaimsProviders
                    TokenLifetime                        = $mockResource.TokenLifetime
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
                            $setTargetResourcePresentAgiChangedParameters = $setTargetResourcePresentParameters.Clone()
                            $setTargetResourcePresentAgiChangedParameters.ApplicationGroupIdentifier = $mockChangedApplicationGroupIdentifier
                        }

                        It 'Should not throw' {
                            { Set-TargetResource @setTargetResourcePresentAGIChangedParameters } | Should -Not -Throw
                        }

                        It 'Should call the expected mocks' {
                            Assert-MockCalled -CommandName Get-TargetResource `
                                -ParameterFilter { $Name -eq $setTargetResourcePresentAgiChangedParameters.Name } `
                                -Exactly -Times 1
                            Assert-MockCalled -CommandName $ResourceCommand.Set -Exactly -Times 0
                            Assert-MockCalled -CommandName $ResourceCommand.Remove `
                                -ParameterFilter { $TargetName -eq $setTargetResourcePresentParameters.Name } `
                                -Exactly -Times 1
                            Assert-MockCalled -CommandName $ResourceCommand.Add `
                                -ParameterFilter { $Name -eq $setTargetResourcePresentAgiChangedParameters.Name } `
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
                                        -ParameterFilter { `
                                            $TargetName -eq $setTargetResourceParametersChangedProperty.Name } `
                                        -Exactly -Times 1
                                    Assert-MockCalled -CommandName $ResourceCommand.Add -Exactly -Times 0
                                    Assert-MockCalled -CommandName $ResourceCommand.Remove -Exactly -Times 0
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
                            -ParameterFilter { $Name -eq $setTargetResourceAbsentParameters.Name } `
                            -Exactly -Times 1
                        Assert-MockCalled -CommandName $ResourceCommand.Remove `
                            -ParameterFilter { $TargetName -eq $setTargetResourceAbsentParameters.Name } `
                            -Exactly -Times 1
                        Assert-MockCalled -CommandName $ResourceCommand.Set -Exactly -Times 0
                        Assert-MockCalled -CommandName $ResourceCommand.Add -Exactly -Times 0
                    }
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
                            -ParameterFilter { $Name -eq $setTargetResourcePresentParameters.Name } `
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

        Describe "MSFT_AdfsWebApiApplication\Test-TargetResource" -Tag 'Test' {
            BeforeAll {
                $testTargetResourceParameters = @{
                    Name                                 = $mockResource.Name
                    ApplicationGroupIdentifier           = $mockResource.ApplicationGroupIdentifier
                    Identifier                           = $mockResource.Identifier
                    AccessControlPolicyName              = $mockResource.AccessControlPolicyName
                    AccessControlPolicyParameters        = $mockResource.AccessControlPolicyParameters
                    AdditionalAuthenticationRules        = $mockResource.AdditionalAuthenticationRules
                    AllowedClientTypes                   = $mockResource.AllowedClientTypes
                    AllowedAuthenticationClassReferences = $mockResource.AllowedAuthenticationClassReferences
                    AlwaysRequireAuthentication          = $mockResource.AlwaysRequireAuthentication
                    ClaimsProviderName                   = $mockResource.ClaimsProviderName
                    DelegationAuthorizationRules         = $mockResource.DelegationAuthorizationRules
                    Description                          = $mockResource.Description
                    ImpersonationAuthorizationRules      = $mockResource.ImpersonationAuthorizationRules
                    IssuanceAuthorizationRules           = $mockResource.IssuanceAuthorizationRules
                    IssuanceTransformRules               = $mockResource.IssuanceTransformRules
                    IssueOAuthRefreshTokensTo            = $mockResource.IssueOAuthRefreshTokensTo
                    NotBeforeSkew                        = $mockResource.NotBeforeSkew
                    RefreshTokenProtectionEnabled        = $mockResource.RefreshTokenProtectionEnabled
                    RequestMFAFromClaimsProviders        = $mockResource.RequestMFAFromClaimsProviders
                    TokenLifetime                        = $mockResource.TokenLifetime
                }

                $testTargetResourcePresentParameters = $testTargetResourceParameters.Clone()
                $testTargetResourcePresentParameters.Ensure = 'Present'

                $testTargetResourceAbsentParameters = $testTargetResourceParameters.Clone()
                $testTargetResourceAbsentParameters.Ensure = 'Absent'
            }

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

                            It 'Should return the desired result' {
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
    Restore-TestEnvironment -TestEnvironment $TestEnvironment
}
