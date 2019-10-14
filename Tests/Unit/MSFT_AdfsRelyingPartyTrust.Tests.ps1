$Global:DSCModuleName = 'AdfsDsc'
$Global:PSModuleName = 'ADFS'
$Global:DSCResourceName = 'MSFT_AdfsRelyingPartyTrust'

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
            Get    = 'Get-AdfsRelyingPartyTrust'
            Set    = 'Set-AdfsRelyingPartyTrust'
            Add    = 'Add-AdfsRelyingPartyTrust'
            Remove = 'Remove-AdfsRelyingPartyTrust'
        }

        $mockClaim = @{
            ClaimType = 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress'
            ShortName = 'email'
        }

        $mockChangedClaim = @{
            ClaimType = 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn'
            ShortName = 'upn'
        }

        $mockClaimAccepted = @{
            ClaimType = $mockClaim.ClaimType
        }

        $mockChangedClaimAccepted = @{
            ClaimType = $mockChangedClaim.ClaimType
        }

        $mockResource = @{
            Name                                 = 'Outlook Web App'
            AdditionalAuthenticationRules        = ''
            AdditionalWSFedEndpoint              = ''
            AutoUpdateEnabled                    = $true
            ClaimAccepted                        = $mockClaim.ShortName
            ClaimsProviderName                   = ''
            DelegationAuthorizationRules         = ''
            EnableJWT                            = $true
            EncryptClaims                        = $true
            EncryptedNameIdRequired              = $true
            EncryptionCertificateRevocationCheck = 'CheckEndCert'
            Identifier                           = 'https://mail.contoso.com/owa'
            ImpersonationAuthorizationRules      = ''
            IssuanceAuthorizationRules           = ''
            IssuanceTransformRules               = ''
            MetadataUrl                          = ''
            MonitoringEnabled                    = $true
            NotBeforeSkew                        = 1
            Notes                                = 'This is a trust for https://mail.contoso.com/owa'
            ProtocolProfile                      = 'SAML'
            SamlResponseSignature                = 'AssertionOnly'
            SignatureAlgorithm                   = 'http://www.w3.org/2000/09/xmldsig#rsa-sha1'
            SignedSamlRequestsRequired           = $true
            SigningCertificateRevocationCheck    = 'CheckEndCert'
            TokenLifetime                        = 1
            WSFedEndpoint                        = 'https://mail.contoso.com/owa'
            Ensure                               = 'Present'
        }

        $mockAbsentResource = @{
            Name                                 = 'Outlook Web App'
            AdditionalAuthenticationRules        = $null
            AdditionalWSFedEndpoint              = @()
            AutoUpdateEnabled                    = $false
            ClaimAccepted                        = @()
            ClaimsProviderName                   = @()
            DelegationAuthorizationRules         = $null
            EnableJWT                            = $false
            EncryptClaims                        = $false
            EncryptedNameIdRequired              = $false
            EncryptionCertificateRevocationCheck = 'CheckEndCert'
            Identifier                           = @()
            ImpersonationAuthorizationRules      = $null
            IssuanceAuthorizationRules           = $null
            IssuanceTransformRules               = $null
            MetadataUrl                          = $null
            MonitoringEnabled                    = $false
            NotBeforeSkew                        = 0
            Notes                                = $null
            ProtocolProfile                      = 'SAML'
            SamlResponseSignature                = 'AssertionOnly'
            SignatureAlgorithm                   = 'http://www.w3.org/2000/09/xmldsig#rsa-sha1'
            SignedSamlRequestsRequired           = $false
            SigningCertificateRevocationCheck    = 'CheckEndCert'
            TokenLifetime                        = 0
            WSFedEndpoint                        = $null
            Ensure                               = 'Absent'
        }

        $mockChangedResource = @{
            AdditionalAuthenticationRules        = 'changed'
            AdditionalWSFedEndpoint              = 'changed'
            AutoUpdateEnabled                    = $false
            ClaimAccepted                        = $mockChangedClaimAccepted
            ClaimsProviderName                   = 'changed'
            DelegationAuthorizationRules         = 'changed'
            EnableJWT                            = $false
            EncryptClaims                        = $false
            EncryptedNameIdRequired              = $false
            EncryptionCertificateRevocationCheck = 'CheckChain'
            Identifier                           = 'https://mail.fabrikam.com/owa'
            ImpersonationAuthorizationRules      = 'changed'
            IssuanceAuthorizationRules           = 'changed'
            IssuanceTransformRules               = 'changed'
            MetadataUrl                          = 'changed'
            MonitoringEnabled                    = $false
            NotBeforeSkew                        = 0
            Notes                                = 'This is a trust for https://mail.fabrikam.com/owa'
            ProtocolProfile                      = 'WsFederation'
            SamlResponseSignature                = 'MessageOnly'
            SignatureAlgorithm                   = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256'
            SignedSamlRequestsRequired           = $false
            SigningCertificateRevocationCheck    = 'CheckChain'
            TokenLifetime                        = 0
            WSFedEndpoint                        = 'https://mail.fabrikam.com/owa'
        }

        $mockGetTargetResourceResult = @{
            Name                                 = $mockResource.Name
            Notes                                = $mockResource.Notes
            WSFedEndpoint                        = $mockResource.WSFedEndpoint
            Identifier                           = $mockResource.Identifier
            IssuanceTransformRules               = $mockResource.IssuanceTransformRules
            IssuanceAuthorizationRules           = $mockResource.IssuanceAuthorizationRules
            AdditionalAuthenticationRules        = $mockResource.AdditionalAuthenticationRules
            AdditionalWSFedEndpoint              = $mockResource.AdditionalWSFedEndpoint
            AutoUpdateEnabled                    = $mockResource.AutoUpdateEnabled
            ClaimAccepted                        = $mockResource.ClaimAccepted
            ClaimsProviderName                   = $mockResource.ClaimsProviderName
            DelegationAuthorizationRules         = $mockResource.DelegationAuthorizationRules
            EnableJWT                            = $mockResource.EnableJWT
            EncryptClaims                        = $mockResource.EncryptClaims
            EncryptedNameIdRequired              = $mockResource.EncryptedNameIdRequired
            EncryptionCertificateRevocationCheck = $mockResource.EncryptionCertificateRevocationCheck
            ImpersonationAuthorizationRules      = $mockResource.ImpersonationAuthorizationRules
            MetadataUrl                          = $mockResource.MetadataUrl
            MonitoringEnabled                    = $mockResource.MonitoringEnabled
            NotBeforeSkew                        = $mockResource.NotBeforeSkew
            ProtocolProfile                      = $mockResource.ProtocolProfile
            SamlResponseSignature                = $mockResource.SamlResponseSignature
            SignatureAlgorithm                   = $mockResource.SignatureAlgorithm
            SignedSamlRequestsRequired           = $mockResource.SignedSamlRequestsRequired
            SigningCertificateRevocationCheck    = $mockResource.SigningCertificateRevocationCheck
            TokenLifetime                        = $mockResource.TokenLifetime
        }

        $mockGetTargetResourcePresentResult = $mockGetTargetResourceResult.Clone()
        $mockGetTargetResourcePresentResult.Ensure = 'Present'

        $mockGetTargetResourceAbsentResult = $mockGetTargetResourceResult.Clone()
        $mockGetTargetResourceAbsentResult.Ensure = 'Absent'

        $mockGetAdfsClaimDescriptionResult = New-MockObject -Type Microsoft.IdentityServer.Management.Resources.ClaimDescription

        Describe "$Global:DSCResourceName\Get-TargetResource" -Tag 'Get' {
            $getTargetResourceParameters = @{
                Name = $mockResource.Name
            }

            $mockGetResourceCommandResult = @{
                Name                                 = $mockResource.Name
                Notes                                = $mockResource.Notes
                WSFedEndpoint                        = $mockResource.WSFedEndpoint
                Identifier                           = $mockResource.Identifier
                IssuanceTransformRules               = $mockResource.IssuanceTransformRules
                IssuanceAuthorizationRules           = $mockResource.IssuanceAuthorizationRules
                AdditionalAuthenticationRules        = $mockResource.AdditionalAuthenticationRules
                AdditionalWSFedEndpoint              = $mockResource.AdditionalWSFedEndpoint
                AutoUpdateEnabled                    = $mockResource.AutoUpdateEnabled
                ClaimsAccepted                       = $mockClaimAccepted
                ClaimsProviderName                   = $mockResource.ClaimsProviderName
                DelegationAuthorizationRules         = $mockResource.DelegationAuthorizationRules
                EnableJWT                            = $mockResource.EnableJWT
                EncryptClaims                        = $mockResource.EncryptClaims
                EncryptedNameIdRequired              = $mockResource.EncryptedNameIdRequired
                EncryptionCertificateRevocationCheck = $mockResource.EncryptionCertificateRevocationCheck
                ImpersonationAuthorizationRules      = $mockResource.ImpersonationAuthorizationRules
                MetadataUrl                          = $mockResource.MetadataUrl
                MonitoringEnabled                    = $mockResource.MonitoringEnabled
                NotBeforeSkew                        = $mockResource.NotBeforeSkew
                ProtocolProfile                      = $mockResource.ProtocolProfile
                SamlResponseSignature                = $mockResource.SamlResponseSignature
                SignatureAlgorithm                   = $mockResource.SignatureAlgorithm
                SignedSamlRequestsRequired           = $mockResource.SignedSamlRequestsRequired
                SigningCertificateRevocationCheck    = $mockResource.SigningCertificateRevocationCheck
                TokenLifetime                        = $mockResource.TokenLifetime
            }

            Mock -CommandName Assert-Module
            Mock -CommandName Assert-Command
            Mock -CommandName Assert-AdfsService
            Mock -CommandName Get-AdfsClaimDescription -MockWith { $mockGetAdfsClaimDescriptionResult }

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
                Notes                                = $mockResource.Notes
                WSFedEndpoint                        = $mockResource.WSFedEndpoint
                Identifier                           = $mockResource.Identifier
                IssuanceTransformRules               = $mockResource.IssuanceTransformRules
                IssuanceAuthorizationRules           = $mockResource.IssuanceAuthorizationRules
                AdditionalAuthenticationRules        = $mockResource.AdditionalAuthenticationRules
                AdditionalWSFedEndpoint              = $mockResource.AdditionalWSFedEndpoint
                AutoUpdateEnabled                    = $mockResource.AutoUpdateEnabled
                ClaimAccepted                        = $mockResource.ClaimAccepted
                ClaimsProviderName                   = $mockResource.ClaimsProviderName
                DelegationAuthorizationRules         = $mockResource.DelegationAuthorizationRules
                EnableJWT                            = $mockResource.EnableJWT
                EncryptClaims                        = $mockResource.EncryptClaims
                EncryptedNameIdRequired              = $mockResource.EncryptedNameIdRequired
                EncryptionCertificateRevocationCheck = $mockResource.EncryptionCertificateRevocationCheck
                ImpersonationAuthorizationRules      = $mockResource.ImpersonationAuthorizationRules
                MonitoringEnabled                    = $mockResource.MonitoringEnabled
                NotBeforeSkew                        = $mockResource.NotBeforeSkew
                ProtocolProfile                      = $mockResource.ProtocolProfile
                SamlResponseSignature                = $mockResource.SamlResponseSignature
                SignatureAlgorithm                   = $mockResource.SignatureAlgorithm
                SignedSamlRequestsRequired           = $mockResource.SignedSamlRequestsRequired
                SigningCertificateRevocationCheck    = $mockResource.SigningCertificateRevocationCheck
                TokenLifetime                        = $mockResource.TokenLifetime
            }

            $setTargetResourcePresentParameters = $setTargetResourceParameters.Clone()
            $setTargetResourcePresentParameters.Ensure = 'Present'

            $setTargetResourceAbsentParameters = $setTargetResourceParameters.Clone()
            $setTargetResourceAbsentParameters.Ensure = 'Absent'

            Mock -CommandName $ResourceCommand.Set
            Mock -CommandName $ResourceCommand.Add
            Mock -CommandName $ResourceCommand.Remove

            Context 'When the Resource is Present' {
                BeforeAll {
                    Mock -CommandName Get-TargetResource -MockWith { $mockGetTargetResourcePresentResult }
                }

                Context 'When the Resource should be Present' {
                    BeforeAll {
                        Mock -CommandName Get-AdfsClaimDescription -MockWith { $mockGetAdfsClaimDescriptionResult }
                    }

                    foreach ($property in $mockChangedResource.Keys)
                    {
                        $setTargetResourceParametersChangedProperty = $setTargetResourceParameters.Clone()
                        $setTargetResourceParametersChangedProperty.$property = $mockChangedResource.$property

                        Mock -CommandName Get-TargetResource `
                            -ParameterFilter { $mockGetResourceResults.Name -eq $Name } `
                            -MockWith { $mockGetTargetResourceResults }

                        It "Should call the correct mocks when $property has changed" {
                            Set-TargetResource @setTargetResourceParametersChangedProperty

                            Assert-MockCalled -CommandName Get-TargetResource `
                                -ParameterFilter { `
                                    $Name -eq $setTargetResourceParametersChangedProperty.Name } `
                                -Scope It -Exactly -Times 1
                            Assert-MockCalled -CommandName $ResourceCommand.Set `
                                -ParameterFilter { `
                                    $TargetName -eq $setTargetResourceParametersChangedProperty.Name } `
                                -Scope It -Exactly -Times 1
                            Assert-MockCalled -CommandName $ResourceCommand.Add -Exactly -Times 0
                            Assert-MockCalled -CommandName $ResourceCommand.Remove -Exactly -Times 0
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
                        Assert-MockCalled -CommandName $ResourceCommand.Remove -Exactly -Times 1
                        Assert-MockCalled -CommandName $ResourceCommand.Set -Exactly -Times 0
                        Assert-MockCalled -CommandName $ResourceCommand.Add -Exactly -Times 0
                    }
                }
            }

            Context 'When the Resource is Absent' {
                Mock -CommandName Get-TargetResource -MockWith { $mockGetTargetResourceAbsentResult }

                Context 'When the Resource should be Present' {
                    Mock -CommandName Get-AdfsClaimDescription -MockWith { $mockGetAdfsClaimDescriptionResult }

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
                Notes                                = $mockResource.Notes
                WSFedEndpoint                        = $mockResource.WSFedEndpoint
                Identifier                           = $mockResource.Identifier
                IssuanceTransformRules               = $mockResource.IssuanceTransformRules
                IssuanceAuthorizationRules           = $mockResource.IssuanceAuthorizationRules
                AdditionalAuthenticationRules        = $mockResource.AdditionalAuthenticationRules
                AdditionalWSFedEndpoint              = $mockResource.AdditionalWSFedEndpoint
                AutoUpdateEnabled                    = $mockResource.AutoUpdateEnabled
                ClaimAccepted                        = $mockResource.ClaimAccepted
                ClaimsProviderName                   = $mockResource.ClaimsProviderName
                DelegationAuthorizationRules         = $mockResource.DelegationAuthorizationRules
                EnableJWT                            = $mockResource.EnableJWT
                EncryptClaims                        = $mockResource.EncryptClaims
                EncryptedNameIdRequired              = $mockResource.EncryptedNameIdRequired
                EncryptionCertificateRevocationCheck = $mockResource.EncryptionCertificateRevocationCheck
                ImpersonationAuthorizationRules      = $mockResource.ImpersonationAuthorizationRules
                MetadataUrl                          = $mockResource.MetadataUrl
                MonitoringEnabled                    = $mockResource.MonitoringEnabled
                NotBeforeSkew                        = $mockResource.NotBeforeSkew
                ProtocolProfile                      = $mockResource.ProtocolProfile
                SamlResponseSignature                = $mockResource.SamlResponseSignature
                SignatureAlgorithm                   = $mockResource.SignatureAlgorithm
                SignedSamlRequestsRequired           = $mockResource.SignedSamlRequestsRequired
                SigningCertificateRevocationCheck    = $mockResource.SigningCertificateRevocationCheck
                TokenLifetime                        = $mockResource.TokenLifetime
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
