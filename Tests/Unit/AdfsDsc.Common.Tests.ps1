$script:resourceModulePath = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent
$script:modulesFolderPath = Join-Path -Path $script:resourceModulePath -ChildPath 'Modules\AdfsDsc.Common'

Import-Module -Name (Join-Path -Path $script:modulesFolderPath -ChildPath 'AdfsDsc.Common.psm1') -Force

InModuleScope 'AdfsDsc.Common' {
    Describe 'AdfsDsc.Common\Get-LocalizedData' {
        $mockTestPath = {
            return $mockTestPathReturnValue
        }

        $mockImportLocalizedData = {
            $BaseDirectory | Should -Be $mockExpectedLanguagePath
        }

        BeforeEach {
            Mock -CommandName Test-Path -MockWith $mockTestPath -Verifiable
            Mock -CommandName Import-LocalizedData -MockWith $mockImportLocalizedData -Verifiable
        }

        Context 'When loading localized data for Swedish' {
            $mockExpectedLanguagePath = 'sv-SE'
            $mockTestPathReturnValue = $true

            It 'Should call Import-LocalizedData with sv-SE language' {
                Mock -CommandName Join-Path -MockWith {
                    return 'sv-SE'
                } -Verifiable

                { Get-LocalizedData -ResourceName 'DummyResource' } | Should -Not -Throw

                Assert-MockCalled -CommandName Join-Path -Exactly -Times 3 -Scope It
                Assert-MockCalled -CommandName Test-Path -Exactly -Times 1 -Scope It
                Assert-MockCalled -CommandName Import-LocalizedData -Exactly -Times 1 -Scope It
            }

            $mockExpectedLanguagePath = 'en-US'
            $mockTestPathReturnValue = $false

            It 'Should call Import-LocalizedData and fallback to en-US if sv-SE language does not exist' {
                Mock -CommandName Join-Path -MockWith {
                    return $ChildPath
                } -Verifiable

                { Get-LocalizedData -ResourceName 'DummyResource' } | Should -Not -Throw

                Assert-MockCalled -CommandName Join-Path -Exactly -Times 4 -Scope It
                Assert-MockCalled -CommandName Test-Path -Exactly -Times 1 -Scope It
                Assert-MockCalled -CommandName Import-LocalizedData -Exactly -Times 1 -Scope It
            }

            Context 'When $ScriptRoot is set to a path' {
                $mockExpectedLanguagePath = 'sv-SE'
                $mockTestPathReturnValue = $true

                It 'Should call Import-LocalizedData with sv-SE language' {
                    Mock -CommandName Join-Path -MockWith {
                        return 'sv-SE'
                    } -Verifiable

                    { Get-LocalizedData -ResourceName 'DummyResource' -ScriptRoot '.' } | Should -Not -Throw

                    Assert-MockCalled -CommandName Join-Path -Exactly -Times 1 -Scope It
                    Assert-MockCalled -CommandName Test-Path -Exactly -Times 1 -Scope It
                    Assert-MockCalled -CommandName Import-LocalizedData -Exactly -Times 1 -Scope It
                }

                $mockExpectedLanguagePath = 'en-US'
                $mockTestPathReturnValue = $false

                It 'Should call Import-LocalizedData and fallback to en-US if sv-SE language does not exist' {
                    Mock -CommandName Join-Path -MockWith {
                        return $ChildPath
                    } -Verifiable

                    { Get-LocalizedData -ResourceName 'DummyResource' -ScriptRoot '.' } | Should -Not -Throw

                    Assert-MockCalled -CommandName Join-Path -Exactly -Times 2 -Scope It
                    Assert-MockCalled -CommandName Test-Path -Exactly -Times 1 -Scope It
                    Assert-MockCalled -CommandName Import-LocalizedData -Exactly -Times 1 -Scope It
                }
            }
        }

        Context 'When loading localized data for English' {
            Mock -CommandName Join-Path -MockWith {
                return 'en-US'
            } -Verifiable

            $mockExpectedLanguagePath = 'en-US'
            $mockTestPathReturnValue = $true

            It 'Should call Import-LocalizedData with en-US language' {
                { Get-LocalizedData -ResourceName 'DummyResource' } | Should -Not -Throw
            }
        }

        Assert-VerifiableMock
    }

    Describe 'AdfsDsc.Common\New-InvalidResultException' {
        Context 'When calling with Message parameter only' {
            It 'Should throw the correct error' {
                $mockErrorMessage = 'Mocked error'

                { New-InvalidResultException -Message $mockErrorMessage } | Should -Throw $mockErrorMessage
            }
        }

        Context 'When calling with both the Message and ErrorRecord parameter' {
            It 'Should throw the correct error' {
                $mockErrorMessage = 'Mocked error'
                $mockExceptionErrorMessage = 'Mocked exception error message'

                $mockException = New-Object -TypeName 'System.Exception' -ArgumentList $mockExceptionErrorMessage
                $mockErrorRecord = New-Object -TypeName 'System.Management.Automation.ErrorRecord' -ArgumentList @($mockException, $null, 'InvalidResult', $null)

                { New-InvalidResultException -Message $mockErrorMessage -ErrorRecord $mockErrorRecord } | Should -Throw ('System.Exception: {0} ---> System.Exception: {1}' -f $mockErrorMessage, $mockExceptionErrorMessage)
            }
        }

        Assert-VerifiableMock
    }

    Describe 'AdfsDsc.Common\New-ObjectNotFoundException' {
        Context 'When calling with Message parameter only' {
            It 'Should throw the correct error' {
                $mockErrorMessage = 'Mocked error'

                { New-ObjectNotFoundException -Message $mockErrorMessage } | Should -Throw $mockErrorMessage
            }
        }

        Context 'When calling with both the Message and ErrorRecord parameter' {
            It 'Should throw the correct error' {
                $mockErrorMessage = 'Mocked error'
                $mockExceptionErrorMessage = 'Mocked exception error message'

                $mockException = New-Object -TypeName 'System.Exception' -ArgumentList $mockExceptionErrorMessage
                $mockErrorRecord = New-Object -TypeName 'System.Management.Automation.ErrorRecord' -ArgumentList @($mockException, $null, 'InvalidResult', $null)

                { New-ObjectNotFoundException -Message $mockErrorMessage -ErrorRecord $mockErrorRecord } | Should -Throw ('System.Exception: {0} ---> System.Exception: {1}' -f $mockErrorMessage, $mockExceptionErrorMessage)
            }
        }

        Assert-VerifiableMock
    }

    Describe 'AdfsDsc.Common\New-InvalidOperationException' {
        Context 'When calling with Message parameter only' {
            It 'Should throw the correct error' {
                $mockErrorMessage = 'Mocked error'

                { New-InvalidOperationException -Message $mockErrorMessage } | Should -Throw $mockErrorMessage
            }
        }

        Context 'When calling with both the Message and ErrorRecord parameter' {
            It 'Should throw the correct error' {
                $mockErrorMessage = 'Mocked error'
                $mockExceptionErrorMessage = 'Mocked exception error message'

                $mockException = New-Object -TypeName 'System.Exception' -ArgumentList $mockExceptionErrorMessage
                $mockErrorRecord = New-Object -TypeName 'System.Management.Automation.ErrorRecord' -ArgumentList @($mockException, $null, 'InvalidResult', $null)

                { New-InvalidOperationException -Message $mockErrorMessage -ErrorRecord $mockErrorRecord } | Should -Throw ('System.InvalidOperationException: {0} ---> System.Exception: {1}' -f $mockErrorMessage, $mockExceptionErrorMessage)
            }
        }

        Assert-VerifiableMock
    }

    Describe 'AdfsDsc.Common\New-InvalidArgumentException' {
        Context 'When calling with both the Message and ArgumentName parameter' {
            It 'Should throw the correct error' {
                $mockErrorMessage = 'Mocked error'
                $mockArgumentName = 'MockArgument'

                { New-InvalidArgumentException -Message $mockErrorMessage -ArgumentName $mockArgumentName } | Should -Throw ('Parameter name: {0}' -f $mockArgumentName)
            }
        }

        Assert-VerifiableMock
    }

    Describe 'AdfsDsc.Common\Assert-Module' {
        BeforeAll {
            $testModuleName = 'TestModule'
        }

        Context 'When module is not installed' {
            BeforeAll {
                Mock -CommandName Get-Module
            }

            It 'Should throw the correct error' {
                { Assert-Module -ModuleName $testModuleName } | Should -Throw ($script:localizedData.RoleNotFoundError -f $testModuleName)
            }
        }

        Context 'When module is available' {
            BeforeAll {
                Mock -CommandName Import-Module
                Mock -CommandName Get-Module -MockWith {
                    return @{
                        Name = $testModuleName
                    }
                }
            }

            Context 'When module should not be imported' {
                It 'Should not throw an error' {
                    { Assert-Module -ModuleName $testModuleName } | Should -Not -Throw

                    Assert-MockCalled -CommandName Import-Module -Exactly -Times 0 -Scope It
                }
            }

            Context 'When module should be imported' {
                It 'Should not throw an error' {
                    { Assert-Module -ModuleName $testModuleName -ImportModule } | Should -Not -Throw

                    Assert-MockCalled -CommandName Import-Module -Exactly -Times 1 -Scope It
                }
            }
        }
    }

    Describe 'AdfsDsc.Common\ConvertTo-Timespan' {
        It "Returns 'System.TimeSpan' object type" {
            $testIntTimeSpan = 60

            $result = ConvertTo-TimeSpan -TimeSpan $testIntTimeSpan -TimeSpanType Minutes

            $result -is [System.TimeSpan] | Should -Be $true
        }

        It 'Creates TimeSpan from seconds' {
            $testIntTimeSpan = 60

            $result = ConvertTo-TimeSpan -TimeSpan $testIntTimeSpan -TimeSpanType Seconds

            $result.TotalSeconds | Should -Be $testIntTimeSpan
        }

        It 'Creates TimeSpan from minutes' {
            $testIntTimeSpan = 60

            $result = ConvertTo-TimeSpan -TimeSpan $testIntTimeSpan -TimeSpanType Minutes

            $result.TotalMinutes | Should -Be $testIntTimeSpan
        }

        It 'Creates TimeSpan from hours' {
            $testIntTimeSpan = 60

            $result = ConvertTo-TimeSpan -TimeSpan $testIntTimeSpan -TimeSpanType Hours

            $result.TotalHours | Should -Be $testIntTimeSpan
        }

        It 'Creates TimeSpan from days' {
            $testIntTimeSpan = 60

            $result = ConvertTo-TimeSpan -TimeSpan $testIntTimeSpan -TimeSpanType Days

            $result.TotalDays | Should -Be $testIntTimeSpan
        }
    }

    Describe 'AdfsDsc.Common\ConvertFrom-Timespan' {
        It "Returns 'System.UInt32' object type" {
            $testIntTimeSpan = 60
            $testTimeSpan = New-TimeSpan -Seconds $testIntTimeSpan

            $result = ConvertFrom-TimeSpan -TimeSpan $testTimeSpan -TimeSpanType Seconds

            $result -is [System.UInt32] | Should -Be $true
        }

        It 'Converts TimeSpan to total seconds' {
            $testIntTimeSpan = 60
            $testTimeSpan = New-TimeSpan -Seconds $testIntTimeSpan

            $result = ConvertFrom-TimeSpan -TimeSpan $testTimeSpan -TimeSpanType Seconds

            $result | Should -Be $testTimeSpan.TotalSeconds
        }

        It 'Converts TimeSpan to total minutes' {
            $testIntTimeSpan = 60
            $testTimeSpan = New-TimeSpan -Minutes $testIntTimeSpan

            $result = ConvertFrom-TimeSpan -TimeSpan $testTimeSpan -TimeSpanType Minutes

            $result | Should -Be $testTimeSpan.TotalMinutes
        }

        It 'Converts TimeSpan to total hours' {
            $testIntTimeSpan = 60
            $testTimeSpan = New-TimeSpan -Hours $testIntTimeSpan

            $result = ConvertFrom-TimeSpan -TimeSpan $testTimeSpan -TimeSpanType Hours

            $result | Should -Be $testTimeSpan.TotalHours
        }

        It 'Converts TimeSpan to total days' {
            $testIntTimeSpan = 60
            $testTimeSpan = New-TimeSpan -Days $testIntTimeSpan

            $result = ConvertFrom-TimeSpan -TimeSpan $testTimeSpan -TimeSpanType Days

            $result | Should -Be $testTimeSpan.TotalDays
        }
    }

    Describe 'DscResource.Common\Test-DscPropertyState' -Tag 'TestDscPropertyState' {
        Context 'When comparing tables' {
            It 'Should return true for two identical tables' {
                $mockValues = @{
                    CurrentValue = 'Test'
                    DesiredValue = 'Test'
                }

                Test-DscPropertyState -Values $mockValues | Should -Be $true
            }
        }

        Context 'When comparing strings' {
            It 'Should return false when a value is different for [System.String]' {
                $mockValues = @{
                    CurrentValue = [System.String] 'something'
                    DesiredValue = [System.String] 'test'
                }

                Test-DscPropertyState -Values $mockValues | Should -Be $false
            }

            It 'Should return false when a String value is missing' {
                $mockValues = @{
                    CurrentValue = $null
                    DesiredValue = [System.String] 'Something'
                }

                Test-DscPropertyState -Values $mockValues | Should -Be $false
            }
        }

        Context 'When comparing integers' {
            It 'Should return false when a value is different for [System.Int32]' {
                $mockValues = @{
                    CurrentValue = [System.Int32] 1
                    DesiredValue = [System.Int32] 2
                }

                Test-DscPropertyState -Values $mockValues | Should -Be $false
            }

            It 'Should return false when a value is different for [System.Int16]' {
                $mockValues = @{
                    CurrentValue = [System.Int16] 1
                    DesiredValue = [System.Int16] 2
                }

                Test-DscPropertyState -Values $mockValues | Should -Be $false
            }

            It 'Should return false when a value is different for [System.UInt16]' {
                $mockValues = @{
                    CurrentValue = [System.UInt16] 1
                    DesiredValue = [System.UInt16] 2
                }

                Test-DscPropertyState -Values $mockValues | Should -Be $false
            }

            It 'Should return false when a Integer value is missing' {
                $mockValues = @{
                    CurrentValue = $null
                    DesiredValue = [System.Int32] 1
                }

                Test-DscPropertyState -Values $mockValues | Should -Be $false
            }
        }

        Context 'When comparing booleans' {
            It 'Should return false when a value is different for [System.Boolean]' {
                $mockValues = @{
                    CurrentValue = [System.Boolean] $true
                    DesiredValue = [System.Boolean] $false
                }

                Test-DscPropertyState -Values $mockValues | Should -Be $false
            }

            It 'Should return false when a Boolean value is missing' {
                $mockValues = @{
                    CurrentValue = $null
                    DesiredValue = [System.Boolean] $true
                }

                Test-DscPropertyState -Values $mockValues | Should -Be $false
            }
        }

        Context 'When comparing arrays' {
            It 'Should return true when evaluating an array' {
                $mockValues = @{
                    CurrentValue = @('1', '2')
                    DesiredValue = @('1', '2')
                }

                Test-DscPropertyState -Values $mockValues | Should -BeTrue
            }

            It 'Should return false when evaluating an array with wrong values' {
                $mockValues = @{
                    CurrentValue = @('CurrentValueA', 'CurrentValueB')
                    DesiredValue = @('DesiredValue1', 'DesiredValue2')
                }

                Test-DscPropertyState -Values $mockValues | Should -BeFalse
            }

            It 'Should return false when evaluating an array, but the current value is $null' {
                $mockValues = @{
                    CurrentValue = $null
                    DesiredValue = @('1', '2')
                }

                Test-DscPropertyState -Values $mockValues | Should -BeFalse
            }

            It 'Should return false when evaluating an array, but the desired value is $null' {
                $mockValues = @{
                    CurrentValue = @('1', '2')
                    DesiredValue = $null
                }

                Test-DscPropertyState -Values $mockValues | Should -BeFalse
            }

            It 'Should return false when evaluating an array, but the current value is an empty array' {
                $mockValues = @{
                    CurrentValue = @()
                    DesiredValue = @('1', '2')
                }

                Test-DscPropertyState -Values $mockValues | Should -BeFalse
            }

            It 'Should return false when evaluating an array, but the desired value is an empty array' {
                $mockValues = @{
                    CurrentValue = @('1', '2')
                    DesiredValue = @()
                }

                Test-DscPropertyState -Values $mockValues | Should -BeFalse
            }

            It 'Should return true when evaluating an array, when both values are $null' {
                $mockValues = @{
                    CurrentValue = $null
                    DesiredValue = $null
                }

                Test-DscPropertyState -Values $mockValues -Verbose | Should -BeTrue
            }

            It 'Should return true when evaluating an array, when both values are an empty array' {
                $mockValues = @{
                    CurrentValue = @()
                    DesiredValue = @()
                }

                Test-DscPropertyState -Values $mockValues -Verbose | Should -BeTrue
            }
        }

        Context -Name 'When passing invalid types for DesiredValue' {
            It 'Should write a warning when DesiredValue contain an unsupported type' {
                Mock -CommandName Write-Warning -Verifiable

                # This is a dummy type to test with a type that could never be a correct one.
                class MockUnknownType
                {
                    [ValidateNotNullOrEmpty()]
                    [System.String]
                    $Property1

                    [ValidateNotNullOrEmpty()]
                    [System.String]
                    $Property2

                    MockUnknownType()
                    {
                    }
                }

                $mockValues = @{
                    CurrentValue = New-Object -TypeName 'MockUnknownType'
                    DesiredValue = New-Object -TypeName 'MockUnknownType'
                }

                Test-DscPropertyState -Values $mockValues | Should -Be $false

                Assert-MockCalled -CommandName Write-Warning -Exactly -Times 1 -Scope It
            }
        }

        Assert-VerifiableMock
    }

    Describe 'AdfsDsc.Common\Compare-ResourcePropertyState' {
        Context 'When one property is in desired state' {
            BeforeAll {
                $mockCurrentValues = @{
                    ComputerName = 'DC01'
                }

                $mockDesiredValues = @{
                    ComputerName = 'DC01'
                }
            }

            It 'Should return the correct values' {
                $compareTargetResourceStateParameters = @{
                    CurrentValues = $mockCurrentValues
                    DesiredValues = $mockDesiredValues
                }

                $compareTargetResourceStateResult = Compare-ResourcePropertyState @compareTargetResourceStateParameters
                $compareTargetResourceStateResult | Should -HaveCount 1
                $compareTargetResourceStateResult.ParameterName | Should -Be 'ComputerName'
                $compareTargetResourceStateResult.Expected | Should -Be 'DC01'
                $compareTargetResourceStateResult.Actual | Should -Be 'DC01'
                $compareTargetResourceStateResult.InDesiredState | Should -BeTrue
            }
        }

        Context 'When two properties are in desired state' {
            BeforeAll {
                $mockCurrentValues = @{
                    ComputerName = 'DC01'
                    Location     = 'Sweden'
                }

                $mockDesiredValues = @{
                    ComputerName = 'DC01'
                    Location     = 'Sweden'
                }
            }

            It 'Should return the correct values' {
                $compareTargetResourceStateParameters = @{
                    CurrentValues = $mockCurrentValues
                    DesiredValues = $mockDesiredValues
                }

                $compareTargetResourceStateResult = Compare-ResourcePropertyState @compareTargetResourceStateParameters
                $compareTargetResourceStateResult | Should -HaveCount 2
                $compareTargetResourceStateResult[0].ParameterName | Should -Be 'ComputerName'
                $compareTargetResourceStateResult[0].Expected | Should -Be 'DC01'
                $compareTargetResourceStateResult[0].Actual | Should -Be 'DC01'
                $compareTargetResourceStateResult[0].InDesiredState | Should -BeTrue
                $compareTargetResourceStateResult[1].ParameterName | Should -Be 'Location'
                $compareTargetResourceStateResult[1].Expected | Should -Be 'Sweden'
                $compareTargetResourceStateResult[1].Actual | Should -Be 'Sweden'
                $compareTargetResourceStateResult[1].InDesiredState | Should -BeTrue
            }
        }

        Context 'When passing just one property and that property is not in desired state' {
            BeforeAll {
                $mockCurrentValues = @{
                    ComputerName = 'DC01'
                }

                $mockDesiredValues = @{
                    ComputerName = 'APP01'
                }
            }

            It 'Should return the correct values' {
                $compareTargetResourceStateParameters = @{
                    CurrentValues = $mockCurrentValues
                    DesiredValues = $mockDesiredValues
                }

                $compareTargetResourceStateResult = Compare-ResourcePropertyState @compareTargetResourceStateParameters
                $compareTargetResourceStateResult | Should -HaveCount 1
                $compareTargetResourceStateResult.ParameterName | Should -Be 'ComputerName'
                $compareTargetResourceStateResult.Expected | Should -Be 'APP01'
                $compareTargetResourceStateResult.Actual | Should -Be 'DC01'
                $compareTargetResourceStateResult.InDesiredState | Should -BeFalse
            }
        }

        Context 'When passing two properties and one property is not in desired state' {
            BeforeAll {
                $mockCurrentValues = @{
                    ComputerName = 'DC01'
                    Location     = 'Sweden'
                }

                $mockDesiredValues = @{
                    ComputerName = 'DC01'
                    Location     = 'Europe'
                }
            }

            It 'Should return the correct values' {
                $compareTargetResourceStateParameters = @{
                    CurrentValues = $mockCurrentValues
                    DesiredValues = $mockDesiredValues
                }

                $compareTargetResourceStateResult = Compare-ResourcePropertyState @compareTargetResourceStateParameters
                $compareTargetResourceStateResult | Should -HaveCount 2
                $compareTargetResourceStateResult[0].ParameterName | Should -Be 'ComputerName'
                $compareTargetResourceStateResult[0].Expected | Should -Be 'DC01'
                $compareTargetResourceStateResult[0].Actual | Should -Be 'DC01'
                $compareTargetResourceStateResult[0].InDesiredState | Should -BeTrue
                $compareTargetResourceStateResult[1].ParameterName | Should -Be 'Location'
                $compareTargetResourceStateResult[1].Expected | Should -Be 'Europe'
                $compareTargetResourceStateResult[1].Actual | Should -Be 'Sweden'
                $compareTargetResourceStateResult[1].InDesiredState | Should -BeFalse
            }
        }

        Context 'When passing a common parameter set to desired value' {
            BeforeAll {
                $mockCurrentValues = @{
                    ComputerName = 'DC01'
                }

                $mockDesiredValues = @{
                    ComputerName = 'DC01'
                    Verbose      = $true
                }
            }

            It 'Should return the correct values' {
                $compareTargetResourceStateParameters = @{
                    CurrentValues = $mockCurrentValues
                    DesiredValues = $mockDesiredValues
                }

                $compareTargetResourceStateResult = Compare-ResourcePropertyState @compareTargetResourceStateParameters
                $compareTargetResourceStateResult | Should -HaveCount 1
                $compareTargetResourceStateResult.ParameterName | Should -Be 'ComputerName'
                $compareTargetResourceStateResult.Expected | Should -Be 'DC01'
                $compareTargetResourceStateResult.Actual | Should -Be 'DC01'
                $compareTargetResourceStateResult.InDesiredState | Should -BeTrue
            }
        }

        Context 'When using parameter Properties to compare desired values' {
            BeforeAll {
                $mockCurrentValues = @{
                    ComputerName = 'DC01'
                    Location     = 'Sweden'
                }

                $mockDesiredValues = @{
                    ComputerName = 'DC01'
                    Location     = 'Europe'
                }
            }

            It 'Should return the correct values' {
                $compareTargetResourceStateParameters = @{
                    CurrentValues = $mockCurrentValues
                    DesiredValues = $mockDesiredValues
                    Properties    = @(
                        'ComputerName'
                    )
                }

                $compareTargetResourceStateResult = Compare-ResourcePropertyState @compareTargetResourceStateParameters
                $compareTargetResourceStateResult | Should -HaveCount 1
                $compareTargetResourceStateResult.ParameterName | Should -Be 'ComputerName'
                $compareTargetResourceStateResult.Expected | Should -Be 'DC01'
                $compareTargetResourceStateResult.Actual | Should -Be 'DC01'
                $compareTargetResourceStateResult.InDesiredState | Should -BeTrue
            }
        }

        Context 'When using parameter Properties and IgnoreProperties to compare desired values' {
            BeforeAll {
                $mockCurrentValues = @{
                    ComputerName = 'DC01'
                    Location     = 'Sweden'
                    Ensure       = 'Present'
                }

                $mockDesiredValues = @{
                    ComputerName = 'DC01'
                    Location     = 'Europe'
                    Ensure       = 'Absent'
                }
            }

            It 'Should return the correct values' {
                $compareTargetResourceStateParameters = @{
                    CurrentValues    = $mockCurrentValues
                    DesiredValues    = $mockDesiredValues
                    IgnoreProperties = @(
                        'Ensure'
                    )
                }

                $compareTargetResourceStateResult = Compare-ResourcePropertyState @compareTargetResourceStateParameters
                $compareTargetResourceStateResult | Should -HaveCount 2
                $compareTargetResourceStateResult[0].ParameterName | Should -Be 'ComputerName'
                $compareTargetResourceStateResult[0].Expected | Should -Be 'DC01'
                $compareTargetResourceStateResult[0].Actual | Should -Be 'DC01'
                $compareTargetResourceStateResult[0].InDesiredState | Should -BeTrue
                $compareTargetResourceStateResult[1].ParameterName | Should -Be 'Location'
                $compareTargetResourceStateResult[1].Expected | Should -Be 'Europe'
                $compareTargetResourceStateResult[1].Actual | Should -Be 'Sweden'
                $compareTargetResourceStateResult[1].InDesiredState | Should -BeFalse
            }
        }

        Context 'When using parameter Properties and IgnoreProperties to compare desired values' {
            BeforeAll {
                $mockCurrentValues = @{
                    ComputerName = 'DC01'
                    Location     = 'Sweden'
                    Ensure       = 'Present'
                }

                $mockDesiredValues = @{
                    ComputerName = 'DC01'
                    Location     = 'Europe'
                    Ensure       = 'Absent'
                }
            }

            It 'Should return an empty array' {
                $compareTargetResourceStateParameters = @{
                    CurrentValues    = $mockCurrentValues
                    DesiredValues    = $mockDesiredValues
                    Properties       = @(
                        'ComputerName'
                    )
                    IgnoreProperties = @(
                        'ComputerName'
                    )
                }

                $compareTargetResourceStateResult = Compare-ResourcePropertyState @compareTargetResourceStateParameters
                $compareTargetResourceStateResult | Should -BeNullOrEmpty
            }
        }
    }
}
