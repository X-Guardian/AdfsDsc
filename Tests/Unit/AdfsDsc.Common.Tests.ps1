$Global:PSModuleName = 'ADFS'

$script:resourceModulePath = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent
$script:modulesFolderPath = Join-Path -Path $script:resourceModulePath -ChildPath 'Modules\AdfsDsc.Common'

Import-Module -Name (Join-Path -Path $script:modulesFolderPath -ChildPath 'AdfsDsc.Common.psm1') -Force

InModuleScope 'AdfsDsc.Common' {
    # Import Stub Module
    Import-Module (Join-Path -Path $PSScriptRoot -ChildPath "Stubs\$($Global:PSModuleName)Stub.psm1") -Force

    Describe 'AdfsDsc.Common\Get-LocalizedData' {
        BeforeAll {
            $mockImportLocalizedData = {
                $BaseDirectory | Should -Be $mockExpectedLanguagePath
            }

            Mock -CommandName Import-LocalizedData -MockWith $mockImportLocalizedData -Verifiable
        }

        Context 'When loading localized data for Swedish' {

            Context 'When the Swedish language path exists' {
                BeforeAll {
                    $mockExpectedLanguagePath = 'sv-SE'
                    $mockTestPathReturnValue = $true

                    Mock -CommandName Test-Path -MockWith { $mockTestPathReturnValue } -Verifiable
                    Mock -CommandName Join-Path -MockWith { $mockExpectedLanguagePath } -Verifiable
                }

                It 'Should not throw an error' {
                    { Get-LocalizedData -ResourceName 'DummyResource' } | Should -Not -Throw
                }

                It 'Should call the expected mocks' {
                    Assert-MockCalled -CommandName Join-Path -Exactly -Times 3
                    Assert-MockCalled -CommandName Test-Path -Exactly -Times 1
                    Assert-MockCalled -CommandName Import-LocalizedData -Exactly -Times 1
                }
            }

            Context ' When the Swedish language path does not exist' {
                BeforeAll {
                    $mockExpectedLanguagePath = 'en-US'
                    $mockTestPathReturnValue = $false

                    Mock -CommandName Test-Path -MockWith { $mockTestPathReturnValue } -Verifiable
                    Mock -CommandName Join-Path -MockWith { $ChildPath } -Verifiable
                }

                It 'Should not throw an error' {
                    { Get-LocalizedData -ResourceName 'DummyResource' } | Should -Not -Throw
                }

                It 'Should call the expected mocks' {
                    Assert-MockCalled -CommandName Join-Path -Exactly -Times 4
                    Assert-MockCalled -CommandName Test-Path -Exactly -Times 1
                    Assert-MockCalled -CommandName Import-LocalizedData -Exactly -Times 1
                }
            }

            Context 'When $ScriptRoot is set to a path' {

                Context 'When the Swedish language path exists' {
                    BeforeAll {
                        $mockExpectedLanguagePath = 'sv-SE'
                        $mockTestPathReturnValue = $true

                        Mock -CommandName Test-Path -MockWith { $mockTestPathReturnValue } -Verifiable
                        Mock -CommandName Join-Path -MockWith { $mockExpectedLanguagePath } -Verifiable
                    }

                    It 'Should not throw an error' {
                        { Get-LocalizedData -ResourceName 'DummyResource' -ScriptRoot '.' } | Should -Not -Throw
                    }

                    It 'Should call the expected mocks' {
                        Assert-MockCalled -CommandName Join-Path -Exactly -Times 1
                        Assert-MockCalled -CommandName Test-Path -Exactly -Times 1
                        Assert-MockCalled -CommandName Import-LocalizedData -Exactly -Times 1
                    }
                }

                Context 'When the Swedish language path does not exist' {
                    BeforeAll {
                        $mockExpectedLanguagePath = 'en-US'
                        $mockTestPathReturnValue = $false

                        Mock -CommandName Test-Path -MockWith { $mockTestPathReturnValue } -Verifiable
                        Mock -CommandName Join-Path -MockWith { $ChildPath } -Verifiable
                    }

                    It 'Should not throw an error' {
                        { Get-LocalizedData -ResourceName 'DummyResource' -ScriptRoot '.' } | Should -Not -Throw
                    }

                    It 'Should call the expected mocks' {
                        Assert-MockCalled -CommandName Join-Path -Exactly -Times 2
                        Assert-MockCalled -CommandName Test-Path -Exactly -Times 1
                        Assert-MockCalled -CommandName Import-LocalizedData -Exactly -Times 1
                    }
                }
            }
        }

        Context 'When loading localized data for US English' {
            BeforeAll {
                $mockExpectedLanguagePath = 'en-US'
                $mockTestPathReturnValue = $true

                Mock -CommandName Test-Path -MockWith { $mockTestPathReturnValue } -Verifiable
                Mock -CommandName Join-Path -MockWith { $mockExpectedLanguagePath } -Verifiable
            }

            It 'Should not throw an error' {
                { Get-LocalizedData -ResourceName 'DummyResource' } | Should -Not -Throw
            }

            It 'Should call the expected mocks' {
                Assert-MockCalled -CommandName Join-Path -Exactly -Times 3
                Assert-MockCalled -CommandName Test-Path -Exactly -Times 1
                Assert-MockCalled -CommandName Import-LocalizedData -Exactly -Times 1
            }
        }

        Assert-VerifiableMock
    }

    Describe 'AdfsDsc.Common\New-InvalidArgumentException' {
        Context 'When calling with both the Message and ArgumentName parameter' {
            BeforeAll {
                $mockErrorMessage = 'Mocked error'
                $mockArgumentName = 'MockArgument'
            }

            It 'Should throw the correct error' {
                { New-InvalidArgumentException -Message $mockErrorMessage -ArgumentName $mockArgumentName } |
                Should -Throw ('Parameter name: {0}' -f $mockArgumentName)
            }
        }
    }

    Describe 'AdfsDsc.Common\New-InvalidOperationException' {
        Context 'When calling with Message parameter only' {
            BeforeAll {
                $mockErrorMessage = 'Mocked error'
            }

            It 'Should throw the correct error' {
                { New-InvalidOperationException -Message $mockErrorMessage } | Should -Throw $mockErrorMessage
            }
        }

        Context 'When calling with both the Message and ErrorRecord parameter' {
            BeforeAll {
                $mockErrorMessage = 'Mocked error'
                $mockExceptionErrorMessage = 'Mocked exception error message'

                $mockException = New-Object -TypeName 'System.Exception' -ArgumentList $mockExceptionErrorMessage
                $mockErrorRecord = New-Object -TypeName 'System.Management.Automation.ErrorRecord' `
                    -ArgumentList @($mockException, $null, 'InvalidResult', $null)
            }

            It 'Should throw the correct error' {
                { New-InvalidOperationException -Message $mockErrorMessage -ErrorRecord $mockErrorRecord } |
                Should -Throw ('System.InvalidOperationException: {0} ---> System.Exception: {1}' -f
                    $mockErrorMessage, $mockExceptionErrorMessage)
            }
        }
    }

    Describe 'AdfsDsc.Common\New-ObjectNotFoundException' {
        Context 'When calling with Message parameter only' {
            BeforeAll {
                $mockErrorMessage = 'Mocked error'
            }

            It 'Should throw the correct error' {
                { New-ObjectNotFoundException -Message $mockErrorMessage } | Should -Throw $mockErrorMessage
            }
        }

        Context 'When calling with both the Message and ErrorRecord parameter' {
            BeforeAll {
                $mockErrorMessage = 'Mocked error'
                $mockExceptionErrorMessage = 'Mocked exception error message'

                $mockException = New-Object -TypeName 'System.Exception' -ArgumentList $mockExceptionErrorMessage
                $mockErrorRecord = New-Object -TypeName 'System.Management.Automation.ErrorRecord' `
                    -ArgumentList @($mockException, $null, 'InvalidResult', $null)
            }

            It 'Should throw the correct error' {
                { New-ObjectNotFoundException -Message $mockErrorMessage -ErrorRecord $mockErrorRecord } |
                Should -Throw ('System.Exception: {0} ---> System.Exception: {1}' -f
                    $mockErrorMessage, $mockExceptionErrorMessage)
            }
        }
    }

    Describe 'AdfsDsc.Common\New-InvalidResultException' {
        Context 'When calling with Message parameter only' {
            BeforeAll {
                $mockErrorMessage = 'Mocked error'
            }

            It 'Should throw the correct error' {
                { New-InvalidResultException -Message $mockErrorMessage } | Should -Throw $mockErrorMessage
            }
        }

        Context 'When calling with both the Message and ErrorRecord parameter' {
            BeforeAll {
                $mockErrorMessage = 'Mocked error'
                $mockExceptionErrorMessage = 'Mocked exception error message'

                $mockException = New-Object -TypeName 'System.Exception' -ArgumentList $mockExceptionErrorMessage
                $mockErrorRecord = New-Object -TypeName 'System.Management.Automation.ErrorRecord' `
                    -ArgumentList @($mockException, $null, 'InvalidResult', $null)
            }

            It 'Should throw the correct error' {
                { New-InvalidResultException -Message $mockErrorMessage -ErrorRecord $mockErrorRecord } |
                Should -Throw ('System.Exception: {0} ---> System.Exception: {1}' -f
                    $mockErrorMessage, $mockExceptionErrorMessage)
            }
        }
    }

    Describe 'AdfsDsc.Common\New-NotImplementedException' {
        Context 'When calling with Message parameter only' {
            BeforeAll {
                $mockErrorMessage = 'Mocked error'
            }

            It 'Should throw the correct error' {
                { New-NotImplementedException -Message $mockErrorMessage } | Should -Throw $mockErrorMessage
            }
        }

        Context 'When calling with both the Message and ErrorRecord parameter' {
            BeforeAll {
                $mockErrorMessage = 'Mocked error'
                $mockExceptionErrorMessage = 'Mocked exception error message'

                $mockException = New-Object -TypeName 'System.Exception' -ArgumentList $mockExceptionErrorMessage
                $mockErrorRecord = New-Object -TypeName 'System.Management.Automation.ErrorRecord' `
                    -ArgumentList @($mockException, $null, 'NotImplemented', $null)
            }

            It 'Should throw the correct error' {
                { New-NotImplementedException -Message $mockErrorMessage -ErrorRecord $mockErrorRecord } |
                Should -Throw ('System.NotImplementedException: {0} ---> System.Exception: {1}' -f
                    $mockErrorMessage, $mockExceptionErrorMessage)
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

    Describe 'DscResource.Common\Test-DscPropertyState' -Tag 'TestDscPropertyState' {
        Context 'When comparing strings' {

            Context 'When the strings match' {
                BeforeAll {
                    $mockValues = @{
                        CurrentValue = [System.String] 'Test'
                        DesiredValue = [System.String] 'Test'
                    }
                }

                It 'Should return true' {
                    Test-DscPropertyState -Values $mockValues | Should -Be $true
                }
            }

            Context 'When the strings do not match' {
                BeforeAll {
                    $mockValues = @{
                        CurrentValue = [System.String] 'something'
                        DesiredValue = [System.String] 'test'
                    }
                }

                It 'Should return false' {
                    Test-DscPropertyState -Values $mockValues | Should -Be $false
                }
            }

            Context 'When the string current value is missing' {
                BeforeAll {
                    $mockValues = @{
                        CurrentValue = $null
                        DesiredValue = [System.String] 'Something'
                    }
                }

                It 'Should return false' {
                    Test-DscPropertyState -Values $mockValues | Should -Be $false
                }
            }

            Context 'When the string desired value is missing' {
                BeforeAll {
                    $mockValues = @{
                        CurrentValue = [System.String] 'Something'
                        DesiredValue = $null
                    }
                }

                It 'Should return false' {
                    Test-DscPropertyState -Values $mockValues | Should -Be $false
                }
            }
        }

        Context 'When comparing Int16' {

            Context 'When the integers match' {
                BeforeAll {
                    $mockValues = @{
                        CurrentValue = [System.Int16] 1
                        DesiredValue = [System.Int16] 1
                    }
                }

                It 'Should return true' {
                    Test-DscPropertyState -Values $mockValues | Should -Be $true
                }
            }

            Context 'When the integers do not match' {
                BeforeAll {
                    $mockValues = @{
                        CurrentValue = [System.Int16] 1
                        DesiredValue = [System.Int16] 2
                    }
                }

                It 'Should return false' {
                    Test-DscPropertyState -Values $mockValues | Should -Be $false
                }
            }

            Context 'When the integers current value is missing' {
                BeforeAll {
                    $mockValues = @{
                        CurrentValue = $null
                        DesiredValue = [System.Int16] 1
                    }
                }

                It 'Should return false' {
                    Test-DscPropertyState -Values $mockValues | Should -Be $false
                }
            }

            Context 'When the integers desired value is missing' {
                BeforeAll {
                    $mockValues = @{
                        CurrentValue = [System.Int16] 1
                        DesiredValue = $null
                    }
                }

                It 'Should return false' {
                    Test-DscPropertyState -Values $mockValues | Should -Be $false
                }
            }
        }

        Context 'When comparing UInt16' {
            Context 'When the integers match' {
                BeforeAll {
                    $mockValues = @{
                        CurrentValue = [System.UInt16] 1
                        DesiredValue = [System.UInt16] 1
                    }
                }

                It 'Should return true' {
                    Test-DscPropertyState -Values $mockValues | Should -Be $true
                }
            }

            Context 'When the integers do not match' {
                BeforeAll {
                    $mockValues = @{
                        CurrentValue = [System.UInt16] 1
                        DesiredValue = [System.UInt16] 2
                    }
                }

                It 'Should return false' {
                    Test-DscPropertyState -Values $mockValues | Should -Be $false
                }
            }

            Context 'When the integers current value is missing' {
                BeforeAll {
                    $mockValues = @{
                        CurrentValue = $null
                        DesiredValue = [System.UInt16] 1
                    }
                }

                It 'Should return false' {
                    Test-DscPropertyState -Values $mockValues | Should -Be $false
                }
            }

            Context 'When the integers desired value is missing' {
                BeforeAll {
                    $mockValues = @{
                        CurrentValue = [System.UInt16] 1
                        DesiredValue = $null
                    }
                }

                It 'Should return false' {
                    Test-DscPropertyState -Values $mockValues | Should -Be $false
                }
            }
        }

        Context 'When comparing Int32' {
            Context 'When the integers match' {
                BeforeAll {
                    $mockValues = @{
                        CurrentValue = [System.Int32] 1
                        DesiredValue = [System.Int32] 1
                    }
                }

                It 'Should return true' {
                    Test-DscPropertyState -Values $mockValues | Should -Be $true
                }
            }

            Context 'When the integers do not match' {
                BeforeAll {
                    $mockValues = @{
                        CurrentValue = [System.Int32] 1
                        DesiredValue = [System.Int32] 2
                    }
                }

                It 'Should return false' {
                    Test-DscPropertyState -Values $mockValues | Should -Be $false
                }
            }

            Context 'When the integers current value is missing' {
                BeforeAll {
                    $mockValues = @{
                        CurrentValue = $null
                        DesiredValue = [System.Int32] 1
                    }
                }

                It 'Should return false' {
                    Test-DscPropertyState -Values $mockValues | Should -Be $false
                }
            }

            Context 'When the integers desired value is missing' {
                BeforeAll {
                    $mockValues = @{
                        CurrentValue = [System.Int32] 1
                        DesiredValue = $null
                    }
                }

                It 'Should return false' {
                    Test-DscPropertyState -Values $mockValues | Should -Be $false
                }
            }
        }

        Context 'When comparing UInt32' {
            Context 'When the integers match' {
                BeforeAll {
                    $mockValues = @{
                        CurrentValue = [System.UInt32] 1
                        DesiredValue = [System.UInt32] 1
                    }
                }

                It 'Should return true' {
                    Test-DscPropertyState -Values $mockValues | Should -Be $true
                }
            }

            Context 'When the integers do not match' {
                BeforeAll {
                    $mockValues = @{
                        CurrentValue = [System.UInt32] 1
                        DesiredValue = [System.UInt32] 2
                    }
                }

                It 'Should return false' {
                    Test-DscPropertyState -Values $mockValues | Should -Be $false
                }
            }

            Context 'When the integers current value is missing' {
                BeforeAll {
                    $mockValues = @{
                        CurrentValue = $null
                        DesiredValue = [System.UInt32] 1
                    }
                }

                It 'Should return false' {
                    Test-DscPropertyState -Values $mockValues | Should -Be $false
                }
            }

            Context 'When the integers desired value is missing' {
                BeforeAll {
                    $mockValues = @{
                        CurrentValue = [System.UInt32] 1
                        DesiredValue = $null
                    }
                }

                It 'Should return false' {
                    Test-DscPropertyState -Values $mockValues | Should -Be $false
                }
            }
        }

        Context 'When comparing Single' {
            Context 'When the singles match' {
                BeforeAll {
                    $mockValues = @{
                        CurrentValue = [System.Single] 1.5
                        DesiredValue = [System.Single] 1.5
                    }
                }

                It 'Should return true' {
                    Test-DscPropertyState -Values $mockValues | Should -Be $true
                }
            }

            Context 'When the singles do not match' {
                BeforeAll {
                    $mockValues = @{
                        CurrentValue = [System.Single] 1.5
                        DesiredValue = [System.Single] 2.5
                    }
                }

                It 'Should return false' {
                    Test-DscPropertyState -Values $mockValues | Should -Be $false
                }
            }

            Context 'When the single current value is missing' {
                BeforeAll {
                    $mockValues = @{
                        CurrentValue = $null
                        DesiredValue = [System.Single] 1.5
                    }
                }

                It 'Should return false' {
                    Test-DscPropertyState -Values $mockValues | Should -Be $false
                }
            }

            Context 'When the single desired value is missing' {
                BeforeAll {
                    $mockValues = @{
                        CurrentValue = [System.Single] 1.5
                        DesiredValue = $null
                    }
                }

                It 'Should return false' {
                    Test-DscPropertyState -Values $mockValues | Should -Be $false
                }
            }
        }

        Context 'When comparing booleans' {
            Context 'When the booleans match' {
                BeforeAll {
                    $mockValues = @{
                        CurrentValue = [System.Boolean] $true
                        DesiredValue = [System.Boolean] $true
                    }
                }

                It 'Should return true' {
                    Test-DscPropertyState -Values $mockValues | Should -Be $true
                }
            }

            Context 'When the booleans do not match' {
                BeforeAll {
                    $mockValues = @{
                        CurrentValue = [System.Boolean] $true
                        DesiredValue = [System.Boolean] $false
                    }
                }

                It 'Should return false' {
                    Test-DscPropertyState -Values $mockValues | Should -Be $false
                }
            }

            Context 'When a boolean value is missing' {
                BeforeAll {
                    $mockValues = @{
                        CurrentValue = $null
                        DesiredValue = [System.Boolean] $true
                    }
                }

                It 'Should return false' {
                    Test-DscPropertyState -Values $mockValues | Should -Be $false
                }
            }
        }

        Context 'When comparing arrays' {
            Context 'When the arrays match' {
                BeforeAll {
                    $mockValues = @{
                        CurrentValue = @('1', '2')
                        DesiredValue = @('1', '2')
                    }
                }

                It 'Should return true' {
                    Test-DscPropertyState -Values $mockValues | Should -BeTrue
                }
            }

            Context 'When the arrays do not match' {
                BeforeAll {
                    $mockValues = @{
                        CurrentValue = @('CurrentValueA', 'CurrentValueB')
                        DesiredValue = @('DesiredValue1', 'DesiredValue2')
                    }
                }

                It 'Should return false' {
                    Test-DscPropertyState -Values $mockValues | Should -BeFalse
                }
            }

            Context 'When the current value is $null' {
                BeforeAll {
                    $mockValues = @{
                        CurrentValue = $null
                        DesiredValue = @('1', '2')
                    }
                }

                It 'Should return false' {
                    Test-DscPropertyState -Values $mockValues | Should -BeFalse
                }
            }

            Context 'When the desired value is $null' {
                BeforeAll {
                    $mockValues = @{
                        CurrentValue = @('1', '2')
                        DesiredValue = $null
                    }
                }

                It 'Should return false' {
                    Test-DscPropertyState -Values $mockValues | Should -BeFalse
                }
            }

            Context 'When the current value is an empty array' {
                BeforeAll {
                    $mockValues = @{
                        CurrentValue = @()
                        DesiredValue = @('1', '2')
                    }

                }

                It 'Should return false' {
                    Test-DscPropertyState -Values $mockValues | Should -BeFalse
                }
            }

            Context 'when the desired value is an empty array' {
                BeforeAll {
                    $mockValues = @{
                        CurrentValue = @('1', '2')
                        DesiredValue = @()
                    }
                }

                It 'Should return false' {
                    Test-DscPropertyState -Values $mockValues | Should -BeFalse
                }
            }

            Context 'when both values are $null' {
                BeforeAll {
                    $mockValues = @{
                        CurrentValue = $null
                        DesiredValue = $null
                    }
                }

                It 'Should return true ' {
                    Test-DscPropertyState -Values $mockValues -Verbose | Should -BeTrue
                }
            }

            Context 'When both values are an empty array' {
                BeforeAll {
                    $mockValues = @{
                        CurrentValue = @()
                        DesiredValue = @()
                    }
                }

                It 'Should return true' {
                    Test-DscPropertyState -Values $mockValues -Verbose | Should -BeTrue
                }
            }
        }

        Context -Name 'When passing unsupported types for DesiredValue' {
            BeforeAll {
                Mock -CommandName Write-Warning -Verifiable
                $mockUnknownType = 'MockUnknowntype'

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
                    CurrentValue = New-Object -TypeName $mockUnknownType
                    DesiredValue = New-Object -TypeName $mockUnknownType
                }
            }

            It 'Should return false' {
                Test-DscPropertyState -Values $mockValues | Should -Be $false
            }

            It 'Should write the correct warning' {
                Assert-MockCalled -CommandName Write-Warning `
                    -ParameterFilter { $Message -eq ($script:localizedData.UnableToCompareType -f $mockUnknownType) } `
                    -Exactly -Times 1
            }
        }

        Assert-VerifiableMock
    }

    Describe 'AdfsDsc.Common\New-CimCredentialInstance' {
        Context 'When creating a new MSFT_Credential CIM instance credential object' {
            BeforeAll {
                $mockAdministratorUser = 'admin@contoso.com'
                $mockAdministratorPassword = 'P@ssw0rd-12P@ssw0rd-12'
                $mockAdministratorCredential = New-Object -TypeName 'System.Management.Automation.PSCredential' `
                    -ArgumentList @(
                    $mockAdministratorUser,
                    ($mockAdministratorPassword | ConvertTo-SecureString -AsPlainText -Force)
                )
            }

            Context 'When the Credential parameter is specified' {
                It 'Should return the correct values' {
                    $newCimCredentialInstanceResult = New-CimCredentialInstance -Credential $mockAdministratorCredential
                    $newCimCredentialInstanceResult | Should -BeOfType 'Microsoft.Management.Infrastructure.CimInstance'
                    $newCimCredentialInstanceResult.CimClass.CimClassName | Should -Be 'MSFT_Credential'
                    $newCimCredentialInstanceResult.UserName | Should -Be $mockAdministratorUser
                    $newCimCredentialInstanceResult.Password | Should -BeNullOrEmpty
                }
            }

            Context 'When the UserName parameter is specified' {
                It 'Should return the correct values' {
                    $newCimCredentialInstanceResult = New-CimCredentialInstance -UserName $mockAdministratorUser
                    $newCimCredentialInstanceResult | Should -BeOfType 'Microsoft.Management.Infrastructure.CimInstance'
                    $newCimCredentialInstanceResult.CimClass.CimClassName | Should -Be 'MSFT_Credential'
                    $newCimCredentialInstanceResult.UserName | Should -Be $mockAdministratorUser
                    $newCimCredentialInstanceResult.Password | Should -BeNullOrEmpty
                }
            }
        }
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
                { Assert-Module -ModuleName $testModuleName } |
                Should -Throw ($script:localizedData.ModuleNotFoundError -f $testModuleName)
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

                    Assert-MockCalled -CommandName Import-Module -Exactly -Times 0
                }
            }

            Context 'When module should be imported' {
                It 'Should not throw an error' {
                    { Assert-Module -ModuleName $testModuleName -ImportModule } | Should -Not -Throw

                    Assert-MockCalled -CommandName Import-Module -Exactly -Times 1
                }
            }
        }
    }

    Describe 'AdfsDsc.Common\Assert-DomainMember' {
        BeforeAll {
            $mockGetCimInstanceDomainMemberResult = @{
                PartOfDomain = $true
            }

            $mockGetCimInstanceNotDomainMemberResult = @{
                PartOfDomain = $false
            }
        }

        Context 'When the computer is a domain member' {
            BeforeAll {
                Mock -CommandName Get-CimInstance -MockWith { $mockGetCimInstanceDomainMemberResult }
            }

            It 'Should not throw an error' {
                { Assert-DomainMember } | Should -Not -Throw
            }

            It 'Should call the correct mocks' {
                Assert-MockCalled -CommandName Get-CimInstance `
                    -ParameterFilter { $ClassName -eq 'Win32_ComputerSystem' } `
                    -Exactly -Times 1
            }
        }

        Context 'When the computer is not a domain member' {
            BeforeAll {
                Mock -CommandName Get-CimInstance -MockWith { $mockGetCimInstanceNotDomainMemberResult }
            }

            It 'Should throw the correct error' {
                { Assert-DomainMember } | Should -Throw $script:localizedData.NotDomainMemberError
            }
        }
    }

    Describe 'AdfsDsc.Common\Assert-AdfsService' {
        BeforeAll {
            $mockGetCimInstanceResult = @{
                LastBootUpTime = [DateTime]'05 October 2019 01:00:00'
            }
            $mockGetDateInsideResult = [DateTime]'05 October 2019 01:10:00'
            $mockGetDateOutsideResult = [DateTime]'05 October 2019 02:00:00'
            $mockGetServiceRunningResult = @{
                Status = 'Running'
            }
            $mockGetServiceNotRunningResult = @{
                Status = 'Stopped'
            }
        }

        Mock -CommandName Start-Sleep

        Context 'When it is inside the retry window' {
            BeforeAll {
                Mock -CommandName Get-CimInstance -MockWith { $mockGetCimInstanceResult }
                Mock -CommandName Get-Date -MockWith { $mockGetDateInsideResult }
            }

            Context 'When the ADFS service is running' {
                BeforeAll {
                    Mock -CommandName Get-Service -MockWith { $mockGetServiceRunningResult }
                }

                It 'Should not throw an error' {
                    { Assert-AdfsService } | Should -Not -Throw
                }

                It 'Should call the correct mocks' {
                    Assert-MockCalled -CommandName Get-CimInstance `
                        -ParameterFilter { $ClassName -eq 'Win32_OperatingSystem' } `
                        -Exactly -Times 1
                    Assert-MockCalled -CommandName Get-Date -Exactly -Times 1
                    Assert-MockCalled -CommandName Get-Service `
                        -ParameterFilter { $Name -eq $script:adfsServiceName } `
                        -Exactly -Times 1
                    Assert-MockCalled -CommandName Start-Sleep -Exactly -Times 0
                }
            }

            Context 'When the ADFS service is not running' {
                BeforeAll {
                    Mock -CommandName Get-Service -MockWith { $mockGetServiceNotRunningResult }
                }

                It 'Should throw the correct error' {
                    { Assert-AdfsService } | Should -Throw $script:localizedData.AdfsServiceNotRunningError
                }

                It 'Should call the correct mocks' {
                    Assert-MockCalled -CommandName Get-CimInstance `
                        -ParameterFilter { $ClassName -eq 'Win32_OperatingSystem' } `
                        -Exactly -Times 1
                    Assert-MockCalled -CommandName Get-Date -Exactly -Times 10
                    Assert-MockCalled -CommandName Get-Service `
                        -ParameterFilter { $Name -eq $script:adfsServiceName } `
                        -Exactly -Times 10
                    Assert-MockCalled -CommandName Start-Sleep -Exactly -Times 10
                }
            }

            Context 'When Get-Service throws an error' {
                BeforeAll {
                    Mock -CommandName Get-Service -MockWith { Throw 'Error' }
                }

                It 'Should throw the correct error' {
                    { Assert-AdfsService } | Should -Throw $script:localizedData.GetAdfsServiceError
                }
            }
        }

        Context 'When it is outside the retry window' {
            BeforeAll {
                Mock -CommandName Get-CimInstance -MockWith { $mockGetCimInstanceResult }
                Mock -CommandName Get-Date -MockWith { $mockGetDateOutsideResult }
            }

            Context 'When the ADFS service is running' {
                BeforeAll {
                    Mock -CommandName Get-Service -MockWith { $mockGetServiceRunningResult }
                }

                It 'Should not throw an error' {
                    { Assert-AdfsService } | Should -Not -Throw
                }

                It 'Should call the correct mocks' {
                    Assert-MockCalled -CommandName Get-CimInstance `
                        -ParameterFilter { $ClassName -eq 'Win32_OperatingSystem' } `
                        -Exactly -Times 1
                    Assert-MockCalled -CommandName Get-Date -Exactly -Times 1
                    Assert-MockCalled -CommandName Get-Service `
                        -ParameterFilter { $Name -eq $script:adfsServiceName } `
                        -Exactly -Times 1
                    Assert-MockCalled -CommandName Start-Sleep -Exactly -Times 0
                }
            }

            Context 'When Get-Service throws an error' {
                BeforeAll {
                    Mock -CommandName Get-Service -MockWith { Throw 'Error' }
                }

                It 'Should throw the correct error' {
                    { Assert-AdfsService } | Should -Throw $script:localizedData.GetAdfsServiceError
                }
            }

            Context 'When the ADFS service is not running' {
                BeforeAll {
                    Mock -CommandName Get-Service -MockWith { $mockGetServiceNotRunningResult }
                }

                It 'Should throw the correct error' {
                    { Assert-AdfsService } | Should -Throw $script:localizedData.AdfsServiceNotRunningError
                }
            }
        }
    }

    Describe 'AdfsDsc.Common\Assert-Command' {
        BeforeAll {
            $mockCommand = 'Get-MockCommand'
            $mockModule = 'MockModule'

            $mockGetCommandExistsResult = @{
                CommandType = 'Cmdlet'
                Name        = $mockCommand
                Source      = $mockModule
            }
        }

        Context 'When the specified command exists' {
            BeforeAll {
                Mock -CommandName Get-Command -MockWith { $mockGetCommandExistsResult }
            }

            It 'Should not throw an error' {
                { Assert-Command -Command $mockCommand -Module $mockModule } | Should -Not -Throw
            }

            It 'Should call the correct mocks' {
                Assert-MockCalled -CommandName Get-Command `
                    -ParameterFilter { $Name -eq $mockCommand -and $Module -eq $mockModule } `
                    -Exactly -Times 1
            }
        }

        Context 'When the specified command does not exist' {
            BeforeAll {
                Mock -CommandName Get-Command
            }

            It 'Should throw the correct error' {
                { Assert-Command -Command $mockCommand -Module $mockModule } | Should -Throw ( `
                        $script:localizedData.ResourceNotImplementedError -f $mockModule, $mockCommand)
            }
        }
    }

    Describe 'AdfsDsc.Common\Assert-GroupServiceAccount' {
        BeforeAll {
            $mockDomainDn = 'DC=contoso,DC=com'
            $mockGmsaName = 'mockgmsa'
            $mockGetADObjectByNameGmsaResult = @{
                Path       = "LDAP://CN=$mockGmsaName,CN=Managed Service Accounts,$mockDomainDn"
                Properties = @{
                    objectcategory = "CN=ms-DS-Group-Managed-Service-Account,CN=Schema,CN=Configuration,$mockDomainDn"
                }
            }
            $mockDomainDn = 'DC=contoso,DC=com'
            $mockSmsaName = 'mocksmsa'
            $mockGetADObjectByNameSmsaResult = @{
                Path       = "LDAP://CN=$mockSmsaName,CN=Managed Service Accounts,$mockDomainDn"
                Properties = @{
                    objectcategory = "CN=ms-DS-Managed-Service-Account,CN=Schema,CN=Configuration,$mockDomainDn"
                }
            }
            $mockUserName = 'mockUserAccount'
            $mockGetADObjectByNameUserResult = @{
                Path       = "LDAP://CN=$mockUserName,CN=Users,$mockDomainDn"
                Properties = @{
                    objectcategory = "CN=Person,CN=Schema,CN=Configuration,$mockDomainDn"
                }
            }
            $mockComputerName = 'mockComputerAccount'
            $mockGetADObjectByNameComputerResult = @{
                Path       = "LDAP://CN=$mockComputerName,CN=Computers,$mockDomainDn"
                Properties = @{
                    objectcategory = "CN=Computer,CN=Schema,CN=Configuration,$mockDomainDn"
                }
            }
            $mockUnknownAccountName = 'UnknownAccount'
        }

        Context 'When the account is a Group Managed Service Account' {
            BeforeAll {
                Mock -CommandName Get-ADObjectByQualifiedName -MockWith { $mockGetADObjectByNameGmsaResult }
            }

            It 'Should return true' {
                Assert-GroupServiceAccount -Name $mockGmsaName | Should -BeTrue
            }
        }

        Context 'When the account is a Standalone Managed Service Account' {
            BeforeAll {
                Mock -CommandName Get-ADObjectByQualifiedName -MockWith { $mockGetADObjectByNameSmsaResult }
            }

            It 'Should return false' {
                Assert-GroupServiceAccount -Name $mockSmsaName | Should -BeFalse
            }
        }

        Context 'When the account is a User Account' {
            BeforeAll {
                Mock -CommandName Get-ADObjectByQualifiedName -MockWith { $mockGetADObjectByNameUserResult }
            }

            It 'Should return false' {
                Assert-GroupServiceAccount -Name $mockUserName | Should -BeFalse
            }
        }

        Context 'When the account is not a User/Service Account' {
            BeforeAll {
                Mock -CommandName Get-ADObjectByQualifiedName -MockWith { $mockGetADObjectByNameComputerResult }
            }

            It 'Should throw the correct error' {
                { Assert-GroupServiceAccount -Name $mockComputerName } | Should -Throw (
                    $script:localizedData.UnexpectedServiceAccountCategoryError -f
                    $mockGetADObjectByNameComputerResult.Properties.ObjectCategory, $mockComputerName)
            }
        }

        Context 'When the account is not found' {
            BeforeAll {
                Mock -CommandName Get-ADObjectByQualifiedName
            }

            It 'Should throw the correct error' {
                { Assert-GroupServiceAccount -Name $mockUnknownAccountName } | Should -Throw (
                    $script:localizedData.ServiceAccountNotFoundError -f $mockUnknownAccountName)
            }
        }
    }

    Describe 'AdfsDsc.Common\Get-AdfsConfigurationStatus' {
        BeforeAll {
            $mockGetItemPropertyFsConfigurationStatusNotConfigured0Result = @{
                FSConfigurationStatus = 0
            }
            $mockGetItemPropertyFsConfigurationStatusNotConfigured1Result = @{
                FSConfigurationStatus = 1
            }
            $mockGetItemPropertyFsConfigurationStatusConfiguredResult = @{
                FSConfigurationStatus = 2
            }
            $mockUnexpectedStatus = 99
            $mockGetItemPropertyFsConfigurationStatusUnexpectedResult = @{
                FSConfigurationStatus = $mockUnexpectedStatus
            }
        }

        Context 'When the ADFS Configuration Status is Configured' {
            BeforeAll {
                Mock -CommandName Get-ItemProperty -MockWith { $mockGetItemPropertyFsConfigurationStatusConfiguredResult }
            }

            It 'Should return the correct result' {
                Get-AdfsConfigurationStatus | Should -Be 'Configured'
            }

            It 'Should call the correct mocks' {
                Assert-MockCalled -CommandName Get-ItemProperty `
                    -ParameterFilter { $Path -eq 'HKLM:\SOFTWARE\Microsoft\ADFS' } `
                    -Exactly -Times 1
            }
        }

        Context 'When the ADFS Configuration Status is NotConfigured with a value of 1' {
            BeforeAll {
                Mock -CommandName Get-ItemProperty -MockWith { $mockGetItemPropertyFsConfigurationStatusNotConfigured0Result }
            }

            It 'Should return the correct result' {
                Get-AdfsConfigurationStatus | Should -Be 'NotConfigured'
            }

            It 'Should call the correct mocks' {
                Assert-MockCalled -CommandName Get-ItemProperty `
                    -ParameterFilter { $Path -eq 'HKLM:\SOFTWARE\Microsoft\ADFS' } `
                    -Exactly -Times 1
            }
        }

        Context 'When the ADFS Configuration Status is NotConfigured with a value of 2' {
            BeforeAll {
                Mock -CommandName Get-ItemProperty -MockWith { $mockGetItemPropertyFsConfigurationStatusNotConfigured1Result }
            }

            It 'Should return the correct result' {
                Get-AdfsConfigurationStatus | Should -Be 'NotConfigured'
            }

            It 'Should call the correct mocks' {
                Assert-MockCalled -CommandName Get-ItemProperty `
                    -ParameterFilter { $Path -eq 'HKLM:\SOFTWARE\Microsoft\ADFS' } `
                    -Exactly -Times 1
            }
        }

        Context 'When Get-ItemProperty throws an error' {
            BeforeAll {
                Mock -CommandName Get-ItemProperty -MockWith { Throw 'Error' }
            }

            It 'Should throw the correct error' {
                { Get-AdfsConfigurationStatus } | Should -Throw $script:localizedData.ConfigurationStatusNotFoundError
            }
        }

        Context 'When FSConfigurationStatus is an unexpected value' {
            BeforeAll {
                Mock -CommandName Get-ItemProperty -MockWith { $mockGetItemPropertyFsConfigurationStatusUnexpectedResult }
            }

            It 'Should throw the correct error' {
                { Get-AdfsConfigurationStatus } | Should -Throw ($script:localizedData.UnknownConfigurationStatusError -f
                    $mockUnexpectedStatus)
            }
        }
    }

    Describe 'AdfsDsc.Common\Get-ObjectType' {
        BeforeAll {
            $mockStringObject = [System.String]'StringObject'
        }

        It 'Should return the correct result' {
            Get-ObjectType -Object $mockStringObject | Should -Be 'System.String'
        }
    }

    Describe 'AdfsDsc.Common\ConvertTo-IssuanceTransformRule' {
        BeforeAll {
            mock -CommandName Get-AdGroupSid
        }

        Context 'When the transform rule is of type LdapClaims' {
            BeforeAll {
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

                $mockLdapClaimsTemplateName = 'LdapClaims'
                $mockLdapClaimsRuleName = 'Test'

                $mockLdapMapping = [CIMInstance[]]@(
                    New-CimInstance -ClassName MSFT_AdfsLdapMapping `
                        -Namespace root/microsoft/Windows/DesiredStateConfiguration `
                        -Property $mockMSFTAdfsLdapMappingProperties[0] -ClientOnly
                    New-CimInstance -ClassName MSFT_AdfsLdapMapping `
                        -Namespace root/microsoft/Windows/DesiredStateConfiguration `
                        -Property $mockMSFTAdfsLdapMappingProperties[1] -ClientOnly
                )

                $mockLdapClaimsMSFT_AdfsIssuanceTransformRuleProperties = @{
                    TemplateName   = $mockLdapClaimsTemplateName
                    Name           = $mockLdapClaimsRuleName
                    AttributeStore = 'Active Directory'
                    LdapMapping    = $mockLdapMapping
                }

                $mockLdapClaimsIssuanceTransformRules = [CIMInstance[]]@(
                    New-CimInstance -ClassName MSFT_AdfsIssuanceTransformRule `
                        -Namespace root/microsoft/Windows/DesiredStateConfiguration `
                        -Property $mockLdapClaimsMSFT_AdfsIssuanceTransformRuleProperties -ClientOnly
                )

                $mockLdapClaimsTransformRule = @(
                    '@RuleTemplate = "{0}"' -f $mockLdapClaimsTemplateName
                    '@RuleName = "{0}"' -f $mockLdapClaimsRuleName
                    'c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname", Issuer == "AD AUTHORITY"]'
                    '=> issue(store = "Active Directory", types = ("{1}", "{2}"), query = ";{3},{4};{0}", param = c.Value);' -f `
                        '{0}', $mockOutgoingClaimTypes[0], $mockOutgoingClaimTypes[1], $mockLdapAttributes[0], $mockLdapAttributes[1]
                ) | Out-String
            }

            It 'Should return the correct result' {
                ConvertTo-IssuanceTransformRule -InputObject $mockLdapClaimsIssuanceTransformRules | `
                    Should -Be $mockLdapClaimsTransformRule
            }

            It 'Should call the expected mocks' {
                Assert-MockCalled -CommandName Get-AdGroupSid -Exactly -Times 0
            }
        }

        Context 'When the transform rule is of type EmitGroupClaims' {
            BeforeAll {
                $mockEmitGroupClaimsTemplateName = 'EmitGroupClaims'
                $mockEmitGroupClaimsRuleName = 'Test'
                $mockAdGroupName = 'Test Group'
                $mockAdGroupSid = 'd382a151-2a2c-4f0f-a6e7-8de159333cd2'
                $mockOutgoingClaimType = 'http://schemas.microsoft.com/ws/2008/06/identity/claims/role'
                $mockOutgoingClaimValue = 'User'

                $mockEmitGroupClaimsMSFT_AdfsIssuanceTransformRuleProperties = @{
                    TemplateName       = $mockEmitGroupClaimsTemplateName
                    Name               = $mockEmitGroupClaimsRuleName
                    GroupName          = $mockAdGroupName
                    OutgoingClaimType  = $mockOutgoingClaimType
                    OutgoingClaimValue = $mockOutgoingClaimValue
                }

                $mockEmitGroupClaimsIssuanceTransformRules = [CIMInstance[]]@(
                    New-CimInstance -ClassName MSFT_AdfsIssuanceTransformRule `
                        -Namespace root/microsoft/Windows/DesiredStateConfiguration `
                        -Property $mockEmitGroupClaimsMSFT_AdfsIssuanceTransformRuleProperties -ClientOnly
                )

                $mockEmitGroupClaimsTransformRule = @(
                    '@RuleTemplate = "{0}"' -f $mockEmitGroupClaimsTemplateName
                    '@RuleName = "{0}"' -f $mockEmitGroupClaimsRuleName
                    'c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/groupsid", Value == "{0}", Issuer == "AD AUTHORITY"]' -f `
                        $mockAdGroupSid
                    '=> issue(Type = "{0}", Value = "{1}", Issuer = c.Issuer, OriginalIssuer = c.OriginalIssuer, ValueType = c.ValueType);' -f `
                        $mockOutgoingClaimType, $mockOutgoingClaimValue
                ) | Out-String

                mock -CommandName Get-AdGroupSid -MockWith { $mockAdGroupSid }
            }

            It 'Should return the correct result' {
                ConvertTo-IssuanceTransformRule -InputObject $mockEmitGroupClaimsIssuanceTransformRules | `
                    Should -Be $mockEmitGroupClaimsTransformRule
            }

            It 'Should call the expected mocks' {
                Assert-MockCalled -CommandName Get-AdGroupSid `
                    -ParameterFilter { $GroupName -eq $mockAdGroupName } `
                    -Exactly -Times 1
            }
        }

        Context 'When the transform rule is of type CustomClaims' {
            BeforeAll {
                $mockCustomClaimsTemplateName = 'CustomClaims'
                $mockCustomClaimsRuleName = 'Test'
                $customRule = 'Custom Claim Rule Text'

                $mockCustomClaimsMSFT_AdfsIssuanceTransformRuleProperties = @{
                    TemplateName = $mockCustomClaimsTemplateName
                    Name         = $mockCustomClaimsRuleName
                    CustomRule   = $customRule
                }

                $mockCustomClaimsIssuanceTransformRules = [CIMInstance[]]@(
                    New-CimInstance -ClassName MSFT_AdfsIssuanceTransformRule `
                        -Namespace root/microsoft/Windows/DesiredStateConfiguration `
                        -Property $mockCustomClaimsMSFT_AdfsIssuanceTransformRuleProperties -ClientOnly
                )

                $mockCustomClaimsTransformRule = @(
                    '@RuleName = "{0}"' -f $mockCustomClaimsRuleName
                    $customRule
                ) | Out-String
            }

            It 'Should return the correct result' {
                ConvertTo-IssuanceTransformRule -InputObject $mockCustomClaimsIssuanceTransformRules | `
                    Should -Be $mockCustomClaimsTransformRule
            }

            It 'Should call the expected mocks' {
                Assert-MockCalled -CommandName Get-AdGroupSid -Exactly -Times 0
            }
        }

        Context 'When the transform rule template is of an unknown type' {
            BeforeAll {
                $mockUnknownTemplateName = 'UnknownClaims'
                $mockUnknownRuleName = 'Test'

                $mockUnknownMSFT_AdfsIssuanceTransformRuleProperties = @{
                    TemplateName = $mockUnknownTemplateName
                    Name         = $mockUnknownRuleName
                }

                $mockUnknownIssuanceTransformRules = [CIMInstance[]]@(
                    New-CimInstance -ClassName MSFT_AdfsIssuanceTransformRule `
                        -Namespace root/microsoft/Windows/DesiredStateConfiguration `
                        -Property $mockUnknownMSFT_AdfsIssuanceTransformRuleProperties -ClientOnly
                )

                It 'Should return the correct error' {
                    { ConvertTo-IssuanceTransformRule -InputObject $mockUnknownIssuanceTransformRules } |
                    Should Throw ($script:localizedData.UnknownIssuanceTransformRuleTemplateError -f
                        $mockUnknownTemplateName)
                }

                It 'Should call the expected mocks' {
                    Assert-MockCalled -CommandName Get-AdGroupSid -Exactly -Times 0
                }
            }
        }
    }

    Describe 'AdfsDsc.Common\ConvertFrom-IssuanceTransformRule' {
        BeforeAll {
            mock -CommandName Get-AdGroupNameFromSid
        }

        Context 'When the transform rule is of type LdapClaims' {
            BeforeAll {
                $mockLdapAttributes = @(
                    'mail'
                    'sn'
                )

                $mockOutgoingClaimTypes = @(
                    'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress'
                    'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname'
                )

                $MSFT_AdfsLdapMappingProperties = @(
                    @{
                        LdapAttribute     = $mockLdapAttributes[0]
                        OutgoingClaimType = $mockOutgoingClaimTypes[0]
                    }
                    @{
                        LdapAttribute     = $mockLdapAttributes[1]
                        OutgoingClaimType = $mockOutgoingClaimTypes[1]
                    }
                )

                $mockLdapClaimsTemplateName = 'LdapClaims'
                $mockLdapClaimsRuleName = 'Test'

                $mockParameterName = 'IssuanceTransformRules'
            }

            Context 'When the Ldap Mapping has a single entry' {
                BeforeAll {
                    $mockSingleLdapMapping = [CIMInstance[]]@(
                        New-CimInstance -ClassName MSFT_AdfsLdapMapping `
                            -Namespace root/microsoft/Windows/DesiredStateConfiguration `
                            -Property $MSFT_AdfsLdapMappingProperties[0] -ClientOnly
                    )

                    $mockSingleLdapClaimsMSFT_AdfsIssuanceTransformRuleProperties = @{
                        TemplateName   = $mockLdapClaimsTemplateName
                        Name           = $mockLdapClaimsRuleName
                        AttributeStore = 'Active Directory'
                        LdapMapping    = $mockSingleLdapMapping
                    }

                    $mockSingleLdapClaimsIssuanceTransformRules = [CIMInstance[]]@(
                        New-CimInstance -ClassName MSFT_AdfsIssuanceTransformRule `
                            -Namespace root/microsoft/Windows/DesiredStateConfiguration `
                            -Property $mockSingleLdapClaimsMSFT_AdfsIssuanceTransformRuleProperties -ClientOnly
                    )

                    $mockSingleLdapClaimsTransformRule = @(
                        '@RuleTemplate = "{0}"' -f $mockLdapClaimsTemplateName
                        '@RuleName = "{0}"' -f $mockLdapClaimsRuleName
                        'c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname", Issuer == "AD AUTHORITY"]'
                        '=> issue(store = "Active Directory", types = ("{1}"), query = ";{2};{0}", param = c.Value);' -f `
                            '{0}', $mockOutgoingClaimTypes[0], $mockLdapAttributes[0]
                    ) | Out-String
                }

                It 'Should return the correct result' {
                    $issuanceTransformRule = ConvertFrom-IssuanceTransformRule -Rule $mockSingleLdapClaimsTransformRule
                    (Compare-IssuanceTransformRule -CurrentValue $issuanceTransformRule `
                            -DesiredValue $mockSingleLdapClaimsIssuanceTransformRules `
                            -ParameterName $mockParameterName).InDesiredState | Should -BeTrue
                }

                It 'Should call the expected mocks' {
                    Assert-MockCalled -CommandName Get-AdGroupNameFromSid -Exactly -Times 0
                }
            }

            Context 'When the LDAP mapping has multiple entries' {
                BeforeAll {
                    $mockMultiLdapMapping = [CIMInstance[]]@(
                        New-CimInstance -ClassName MSFT_AdfsLdapMapping `
                            -Namespace root/microsoft/Windows/DesiredStateConfiguration `
                            -Property $MSFT_AdfsLdapMappingProperties[0] -ClientOnly
                        New-CimInstance -ClassName MSFT_AdfsLdapMapping `
                            -Namespace root/microsoft/Windows/DesiredStateConfiguration `
                            -Property $MSFT_AdfsLdapMappingProperties[1] -ClientOnly
                    )

                    $mockMultiLdapClaimsMSFT_AdfsIssuanceTransformRuleProperties = @{
                        TemplateName   = $mockLdapClaimsTemplateName
                        Name           = $mockLdapClaimsRuleName
                        AttributeStore = 'Active Directory'
                        LdapMapping    = $mockMultiLdapMapping
                    }

                    $mockMultiLdapClaimsIssuanceTransformRules = [CIMInstance[]]@(
                        New-CimInstance -ClassName MSFT_AdfsIssuanceTransformRule `
                            -Namespace root/microsoft/Windows/DesiredStateConfiguration `
                            -Property $mockMultiLdapClaimsMSFT_AdfsIssuanceTransformRuleProperties -ClientOnly
                    )

                    $mockMultiLdapClaimsTransformRule = @(
                        '@RuleTemplate = "{0}"' -f $mockLdapClaimsTemplateName
                        '@RuleName = "{0}"' -f $mockLdapClaimsRuleName
                        'c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname", Issuer == "AD AUTHORITY"]'
                        '=> issue(store = "Active Directory", types = ("{1}", "{2}"), query = ";{3},{4};{0}", param = c.Value);' -f `
                            '{0}', $mockOutgoingClaimTypes[0], $mockOutgoingClaimTypes[1], $mockLdapAttributes[0], $mockLdapAttributes[1]
                    ) | Out-String
                }

                It 'Should return the correct result' {
                    $issuanceTransformRule = ConvertFrom-IssuanceTransformRule -Rule $mockMultiLdapClaimsTransformRule
                    (Compare-IssuanceTransformRule -CurrentValue $issuanceTransformRule `
                            -DesiredValue $mockMultiLdapClaimsIssuanceTransformRules `
                            -ParameterName $mockParameterName).InDesiredState | Should -BeTrue

                }

                It 'Should call the expected mocks' {
                    Assert-MockCalled -CommandName Get-AdGroupNameFromSid -Exactly -Times 0
                }
            }
        }

        Context 'When the transform rule is of type EmitGroupClaims' {
            BeforeAll {
                $mockEmitGroupClaimsTemplateName = 'EmitGroupClaims'
                $mockEmitGroupClaimsRuleName = 'Test'
                $mockAdGroupName = 'Test Group'
                $mockAdGroupSid = 'd382a151-2a2c-4f0f-a6e7-8de159333cd2'
                $mockOutgoingClaimType = 'http://schemas.microsoft.com/ws/2008/06/identity/claims/role'
                $mockOutgoingClaimValue = 'User'

                $mockEmitGroupClaimsMSFT_AdfsIssuanceTransformRuleProperties = @{
                    TemplateName       = $mockEmitGroupClaimsTemplateName
                    Name               = $mockEmitGroupClaimsRuleName
                    GroupName          = $mockAdGroupName
                    OutgoingClaimType  = $mockOutgoingClaimType
                    OutgoingClaimValue = $mockOutgoingClaimValue
                }

                $mockEmitGroupClaimsIssuanceTransformRules = [CIMInstance[]]@(
                    New-CimInstance -ClassName MSFT_AdfsIssuanceTransformRule `
                        -Namespace root/microsoft/Windows/DesiredStateConfiguration `
                        -Property $mockEmitGroupClaimsMSFT_AdfsIssuanceTransformRuleProperties -ClientOnly
                )

                $mockEmitGroupClaimsTransformRule = @(
                    '@RuleTemplate = "{0}"' -f $mockEmitGroupClaimsTemplateName
                    '@RuleName = "{0}"' -f $mockEmitGroupClaimsRuleName
                    'c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/groupsid", Value == "{0}", Issuer == "AD AUTHORITY"]' -f `
                        $mockAdGroupSid
                    '=> issue(Type = "{0}", Value = "{1}", Issuer = c.Issuer, OriginalIssuer = c.OriginalIssuer, ValueType = c.ValueType);' -f `
                        $mockOutgoingClaimType, $mockOutgoingClaimValue
                ) | Out-String

                mock -CommandName Get-AdGroupNameFromSid -MockWith { $mockAdGroupName }
            }

            It 'Should return the correct result' {
                $issuanceTransformRule = ConvertFrom-IssuanceTransformRule -Rule $mockEmitGroupClaimsTransformRule
                (Compare-IssuanceTransformRule -CurrentValue $issuanceTransformRule `
                        -DesiredValue $mockEmitGroupClaimsIssuanceTransformRules `
                        -ParameterName $mockParameterName).InDesiredState | Should -BeTrue
            }

            It 'Should call the expected mocks' {
                Assert-MockCalled -CommandName Get-AdGroupNameFromSid `
                    -ParameterFilter { $Sid -eq $mockAdGroupSid } `
                    -Exactly -Times 1
            }
        }

        Context 'When the transform rule is of type CustomClaims' {
            BeforeAll {
                $mockCustomClaimsTemplateName = 'CustomClaims'
                $mockCustomClaimsRuleName = 'Test'
                $customRule = 'Custom Claim Rule Text'

                $mockCustomClaimsMSFT_AdfsIssuanceTransformRuleProperties = @{
                    TemplateName = $mockCustomClaimsTemplateName
                    Name         = $mockCustomClaimsRuleName
                    CustomRule   = $customRule
                }

                $mockCustomClaimsIssuanceTransformRules = [CIMInstance[]]@(
                    New-CimInstance -ClassName MSFT_AdfsIssuanceTransformRule `
                        -Namespace root/microsoft/Windows/DesiredStateConfiguration `
                        -Property $mockCustomClaimsMSFT_AdfsIssuanceTransformRuleProperties -ClientOnly
                )

                $mockCustomClaimsTransformRule = @(
                    '@RuleName = "{0}"' -f $mockCustomClaimsRuleName
                    $customRule
                ) | Out-String
            }

            It 'Should return the correct result' {
                $issuanceTransformRule = ConvertFrom-IssuanceTransformRule -Rule $mockCustomClaimsTransformRule
                (Compare-IssuanceTransformRule -CurrentValue $issuanceTransformRule `
                        -DesiredValue $mockCustomClaimsIssuanceTransformRules `
                        -ParameterName $mockParameterName).InDesiredState | Should -BeTrue
            }

            It 'Should call the expected mocks' {
                Assert-MockCalled -CommandName Get-AdGroupNameFromSid -Exactly -Times 0
            }
        }
    }

    Describe 'AdfsDsc.Common\Compare-IssuanceTransformRule' {
        BeforeAll {
            $mockParameterName = 'IssuanceTransformRules'
        }

        Context 'When the transform rule contains an LdapClaims rule' {
            BeforeAll {
                $mockLdapAttributes = @(
                    'mail'
                    'sn'
                )

                $mockOutgoingClaimTypes = @(
                    'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress'
                    'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname'
                )

                $CurrentMSFTAdfsLdapMappingProperties = @(
                    @{
                        LdapAttribute     = $mockLdapAttributes[0]
                        OutgoingClaimType = $mockOutgoingClaimTypes[0]
                    }
                )

                $mockLdapClaimsTemplateName = 'LdapClaims'
                $mockLdapClaimsRuleName = 'Test'

                $mockCurrentMSFTAdfsLdapMapping = [CIMInstance[]]@(
                    New-CimInstance -ClassName MSFT_AdfsLdapMapping `
                        -Namespace root/microsoft/Windows/DesiredStateConfiguration `
                        -Property $CurrentMSFTAdfsLdapMappingProperties[0] -ClientOnly
                )

                $mockCurrentLdapClaimsMSFTAdfsIssuanceTransformRuleProperties = @{
                    TemplateName   = $mockLdapClaimsTemplateName
                    Name           = $mockLdapClaimsRuleName
                    AttributeStore = 'Active Directory'
                    LdapMapping    = $mockCurrentMSFTAdfsLdapMapping
                }

                $mockCurrentLdapClaimsMSFTAdfsIssuanceTransformRules = [CIMInstance[]]@(
                    New-CimInstance -ClassName MSFT_AdfsIssuanceTransformRule `
                        -Namespace root/microsoft/Windows/DesiredStateConfiguration `
                        -Property $mockCurrentLdapClaimsMSFTAdfsIssuanceTransformRuleProperties -ClientOnly
                )

                $DesiredMSFTAdfsLdapMappingProperties = @(
                    @{
                        LdapAttribute     = $mockLdapAttributes[1]
                        OutgoingClaimType = $mockOutgoingClaimTypes[1]
                    }
                )

                $mockDesiredMSFTAdfsLdapMapping = [CIMInstance[]]@(
                    New-CimInstance -ClassName MSFT_AdfsLdapMapping `
                        -Namespace root/microsoft/Windows/DesiredStateConfiguration `
                        -Property $DesiredMSFTAdfsLdapMappingProperties[1] -ClientOnly
                )

                $mockDesiredLdapClaimsMSFTAdfsIssuanceTransformRuleProperties = @{
                    TemplateName   = $mockLdapClaimsTemplateName
                    Name           = $mockLdapClaimsRuleName
                    AttributeStore = 'Active Directory'
                    LdapMapping    = $mockDesiredMSFTAdfsLdapMapping
                }

                $mockDesiredLdapClaimsMSFTAdfsIssuanceTransformRules = [CIMInstance[]]@(
                    New-CimInstance -ClassName MSFT_AdfsIssuanceTransformRule `
                        -Namespace root/microsoft/Windows/DesiredStateConfiguration `
                        -Property $mockDesiredLdapClaimsMSFTAdfsIssuanceTransformRuleProperties -ClientOnly
                )

            }

            Context 'When both LdapClaims rules are the same' {
                BeforeAll {
                    $compareIssuanceTransformRuleResult = Compare-IssuanceTransformRule `
                        -CurrentValue $mockCurrentLdapClaimsMSFTAdfsIssuanceTransformRules `
                        -DesiredValue $mockCurrentLdapClaimsMSFTAdfsIssuanceTransformRules `
                        -ParameterName $mockParameterName
                }

                It 'Should return the correct result' {
                    $compareIssuanceTransformRuleResult | Should -HaveCount 1
                    $compareIssuanceTransformRuleResult.ParameterName | Should -Be $mockParameterName
                    $compareIssuanceTransformRuleResult.InDesiredState | Should -BeTrue
                }
            }

            Context 'When the LdapClaims rules are different' {
                BeforeAll {
                    $compareIssuanceTransformRuleResult = Compare-IssuanceTransformRule `
                        -CurrentValue $mockCurrentLdapClaimsMSFTAdfsIssuanceTransformRules `
                        -DesiredValue $mockDesiredLdapClaimsMSFTAdfsIssuanceTransformRules `
                        -ParameterName $mockParameterName
                }

                It 'Should return the correct result' {
                    $compareIssuanceTransformRuleResult | Should -HaveCount 1
                    $compareIssuanceTransformRuleResult.ParameterName | Should -Be $mockParameterName
                    $compareIssuanceTransformRuleResult.InDesiredState | Should -BeFalse
                }
            }
        }

        Context 'When the transform rule contains an EmitGroupClaims rule' {
            BeforeAll {
                $mockEmitGroupClaimsTemplateName = 'EmitGroupClaims'
                $mockEmitGroupClaimsRuleName = 'Test'
                $mockCurrentAdGroupName = 'Test Group'
                $mockOutgoingClaimType = 'http://schemas.microsoft.com/ws/2008/06/identity/claims/role'
                $mockOutgoingClaimValue = 'User'

                $mockCurrentEmitGroupClaimsMSFTAdfsIssuanceTransformRuleProperties = @{
                    TemplateName       = $mockEmitGroupClaimsTemplateName
                    Name               = $mockEmitGroupClaimsRuleName
                    GroupName          = $mockCurrentAdGroupName
                    OutgoingClaimType  = $mockOutgoingClaimType
                    OutgoingClaimValue = $mockOutgoingClaimValue
                }

                $mockCurrentEmitGroupClaimsMSFTAdfsIssuanceTransformRules = [CIMInstance[]]@(
                    New-CimInstance -ClassName MSFT_AdfsIssuanceTransformRule `
                        -Namespace root/microsoft/Windows/DesiredStateConfiguration `
                        -Property $mockCurrentEmitGroupClaimsMSFTAdfsIssuanceTransformRuleProperties -ClientOnly
                )

                $mockDesiredAdGroupName = 'Test Group 2'

                $mockDesiredEmitGroupClaimsMSFTAdfsIssuanceTransformRuleProperties = @{
                    TemplateName       = $mockEmitGroupClaimsTemplateName
                    Name               = $mockEmitGroupClaimsRuleName
                    GroupName          = $mockDesiredAdGroupName
                    OutgoingClaimType  = $mockOutgoingClaimType
                    OutgoingClaimValue = $mockOutgoingClaimValue
                }

                $mockDesiredEmitGroupClaimsMSFTAdfsIssuanceTransformRules = [CIMInstance[]]@(
                    New-CimInstance -ClassName MSFT_AdfsIssuanceTransformRule `
                        -Namespace root/microsoft/Windows/DesiredStateConfiguration `
                        -Property $mockDesiredEmitGroupClaimsMSFTAdfsIssuanceTransformRuleProperties -ClientOnly
                )
            }

            Context 'When both EmitGroupClaims rules are the same' {
                BeforeAll {
                    $compareIssuanceTransformRuleResult = Compare-IssuanceTransformRule `
                        -CurrentValue $mockCurrentEmitGroupClaimsMSFTAdfsIssuanceTransformRules `
                        -DesiredValue $mockCurrentEmitGroupClaimsMSFTAdfsIssuanceTransformRules `
                        -ParameterName $mockParameterName
                }

                It 'Should return the correct result' {
                    $compareIssuanceTransformRuleResult | Should -HaveCount 1
                    $compareIssuanceTransformRuleResult.ParameterName | Should -Be 'IssuanceTransformRules'
                    $compareIssuanceTransformRuleResult.InDesiredState | Should -BeTrue
                }
            }

            Context 'When the EmitGroupClaims rules are different' {
                BeforeAll {
                    $compareIssuanceTransformRuleResult = Compare-IssuanceTransformRule `
                        -CurrentValue $mockCurrentEmitGroupClaimsMSFTAdfsIssuanceTransformRules `
                        -DesiredValue $mockDesiredEmitGroupClaimsMSFTAdfsIssuanceTransformRules `
                        -ParameterName $mockParameterName
                }

                It 'Should return the correct result' {
                    $compareIssuanceTransformRuleResult | Should -HaveCount 1
                    $compareIssuanceTransformRuleResult.ParameterName | Should -Be 'IssuanceTransformRules'
                    $compareIssuanceTransformRuleResult.InDesiredState | Should -BeFalse
                }
            }
        }

        Context 'When the transform rule contains a CustomClaims rule' {
            BeforeAll {
                $mockCustomClaimsTemplateName = 'CustomClaims'
                $mockCustomClaimsRuleName = 'Test'
                $mockCustomRule = 'Custom Claim Rule Text'

                $mockCurrentCustomClaimsMSFTAdfsIssuanceTransformRuleProperties = @{
                    TemplateName = $mockCustomClaimsTemplateName
                    Name         = $mockCustomClaimsRuleName
                    CustomRule   = $mockCustomRule
                }

                $mockCurrentCustomClaimsMSFTAdfsIssuanceTransformRules = [CIMInstance[]]@(
                    New-CimInstance -ClassName MSFT_AdfsIssuanceTransformRule `
                        -Namespace root/microsoft/Windows/DesiredStateConfiguration `
                        -Property $mockCurrentCustomClaimsMSFTAdfsIssuanceTransformRuleProperties -ClientOnly
                )
            }

            Context 'When both CustomClaims rules are the same' {
                BeforeAll {
                    $compareIssuanceTransformRuleResult = Compare-IssuanceTransformRule `
                        -CurrentValue $mockCurrentCustomClaimsMSFTAdfsIssuanceTransformRules `
                        -DesiredValue $mockCurrentCustomClaimsMSFTAdfsIssuanceTransformRules `
                        -ParameterName $mockParameterName
                }

                It 'Should return the correct result' {
                    $compareIssuanceTransformRuleResult | Should -HaveCount 1
                    $compareIssuanceTransformRuleResult.ParameterName | Should -Be 'IssuanceTransformRules'
                    $compareIssuanceTransformRuleResult.InDesiredState | Should -BeTrue
                }
            }

            Context 'When the CustomClaims rules are different' {
                BeforeAll {
                    $mockDesiredCustomRule = 'Custom Claim Rule Text 2'

                    $mockDesiredCustomClaimsMSFTAdfsIssuanceTransformRuleProperties = @{
                        TemplateName = $mockCustomClaimsTemplateName
                        Name         = $mockCustomClaimsRuleName
                        CustomRule   = $mockDesiredCustomRule
                    }

                    $mockDesiredCustomClaimsMSFTAdfsIssuanceTransformRules = [CIMInstance[]]@(
                        New-CimInstance -ClassName MSFT_AdfsIssuanceTransformRule `
                            -Namespace root/microsoft/Windows/DesiredStateConfiguration `
                            -Property $mockDesiredCustomClaimsMSFTAdfsIssuanceTransformRuleProperties -ClientOnly
                    )

                    $compareIssuanceTransformRuleResult = Compare-IssuanceTransformRule `
                        -CurrentValue $mockCurrentCustomClaimsMSFTAdfsIssuanceTransformRules `
                        -DesiredValue $mockDesiredCustomClaimsMSFTAdfsIssuanceTransformRules `
                        -ParameterName $mockParameterName
                }

                It 'Should return the correct result' {
                    $compareIssuanceTransformRuleResult | Should -HaveCount 1
                    $compareIssuanceTransformRuleResult.ParameterName | Should -Be 'IssuanceTransformRules'
                    $compareIssuanceTransformRuleResult.InDesiredState | Should -BeFalse
                }
            }

            Context 'When the number of rules has changed' {
                BeforeAll {
                    $mockDesiredCustomClaimsMSFTAdfsIssuanceTransformRuleProperties = @{
                        TemplateName = $mockCustomClaimsTemplateName
                        Name         = $mockCustomClaimsRuleName
                        CustomRule   = $mockCustomRule
                    }

                    $mockDesiredCustomClaimsMSFTAdfsIssuanceTransformRules = [CIMInstance[]]@(
                        New-CimInstance -ClassName MSFT_AdfsIssuanceTransformRule `
                            -Namespace root/microsoft/Windows/DesiredStateConfiguration `
                            -Property $mockCurrentCustomClaimsMSFTAdfsIssuanceTransformRuleProperties -ClientOnly
                        New-CimInstance -ClassName MSFT_AdfsIssuanceTransformRule `
                            -Namespace root/microsoft/Windows/DesiredStateConfiguration `
                            -Property $mockDesiredCustomClaimsMSFTAdfsIssuanceTransformRuleProperties -ClientOnly
                    )

                    $compareIssuanceTransformRuleResult = Compare-IssuanceTransformRule `
                        -CurrentValue $mockCurrentCustomClaimsMSFTAdfsIssuanceTransformRules `
                        -DesiredValue $mockDesiredCustomClaimsMSFTAdfsIssuanceTransformRules `
                        -ParameterName $mockParameterName
                }

                It 'Should return the correct result' {
                    $compareIssuanceTransformRuleResult | Should -HaveCount 1
                    $compareIssuanceTransformRuleResult.ParameterName | Should -Be 'IssuanceTransformRules'
                    $compareIssuanceTransformRuleResult.InDesiredState | Should -BeFalse
                }
            }

            Context 'When the Rule Name has changed' {
                BeforeAll {
                    $mockDesiredCustomClaimsRuleName = 'Test2'

                    $mockDesiredCustomClaimsMSFTAdfsIssuanceTransformRuleProperties = @{
                        TemplateName = $mockCustomClaimsTemplateName
                        Name         = $mockDesiredCustomClaimsRuleName
                        CustomRule   = $mockCustomRule
                    }

                    $mockDesiredCustomClaimsMSFTAdfsIssuanceTransformRules = [CIMInstance[]]@(
                        New-CimInstance -ClassName MSFT_AdfsIssuanceTransformRule `
                            -Namespace root/microsoft/Windows/DesiredStateConfiguration `
                            -Property $mockDesiredCustomClaimsMSFTAdfsIssuanceTransformRuleProperties -ClientOnly
                    )

                    $compareIssuanceTransformRuleResult = Compare-IssuanceTransformRule `
                        -CurrentValue $mockCurrentCustomClaimsMSFTAdfsIssuanceTransformRules `
                        -DesiredValue $mockDesiredCustomClaimsMSFTAdfsIssuanceTransformRules `
                        -ParameterName $mockParameterName
                }

                It 'Should return the correct result' {
                    $compareIssuanceTransformRuleResult | Should -HaveCount 1
                    $compareIssuanceTransformRuleResult.ParameterName | Should -Be 'IssuanceTransformRules'
                    $compareIssuanceTransformRuleResult.InDesiredState | Should -BeFalse
                }
            }
        }

        Context 'When the Template Name has changed' {
            BeforeAll {
                $mockCustomClaimsTemplateName = 'CustomClaims'
                $mockCustomClaimsRuleName = 'Test'

                $mockCurrentCustomClaimsMSFTAdfsIssuanceTransformRuleProperties = @{
                    TemplateName = $mockCustomClaimsTemplateName
                    Name         = $mockCustomClaimsRuleName
                }

                $mockCurrentCustomClaimsMSFTAdfsIssuanceTransformRules = [CIMInstance[]]@(
                    New-CimInstance -ClassName MSFT_AdfsIssuanceTransformRule `
                        -Namespace root/microsoft/Windows/DesiredStateConfiguration `
                        -Property $mockCurrentCustomClaimsMSFTAdfsIssuanceTransformRuleProperties -ClientOnly
                )

                $mockLdapClaimsTemplateName = 'LdapClaims'
                $mockLdapClaimsRuleName = 'Test'

                $mockDesiredCustomClaimsMSFTAdfsIssuanceTransformRuleProperties = @{
                    TemplateName = $mockLdapClaimsTemplateName
                    Name         = $mockLdapClaimsRuleName
                }

                $mockDesiredLdapClaimsMSFTAdfsIssuanceTransformRules = [CIMInstance[]]@(
                    New-CimInstance -ClassName MSFT_AdfsIssuanceTransformRule `
                        -Namespace root/microsoft/Windows/DesiredStateConfiguration `
                        -Property $mockDesiredLdapClaimsMSFTAdfsIssuanceTransformRuleProperties -ClientOnly
                )

                $compareIssuanceTransformRuleResult = Compare-IssuanceTransformRule `
                    -CurrentValue $mockCurrentCustomClaimsMSFTAdfsIssuanceTransformRules `
                    -DesiredValue $mockDesiredLdapClaimsMSFTAdfsIssuanceTransformRules `
                    -ParameterName $mockParameterName
            }

            It 'Should return the correct result' {
                $compareIssuanceTransformRuleResult | Should -HaveCount 1
                $compareIssuanceTransformRuleResult.ParameterName | Should -Be 'IssuanceTransformRules'
                $compareIssuanceTransformRuleResult.InDesiredState | Should -BeFalse
            }
        }
    }

    Describe 'AdfsDsc.Common\ConvertTo-AccessControlPolicyParameter' {

        Context 'When the property is ''Group Parameter''' {
            BeforeAll {
                $mockGroup = 'CONTOSO\App1 Users'

                $mockGroupParameter = @{
                    GroupParameter = $mockGroup
                }

                $mockMSFTAdfsGroupAccessControlPolicyParameters = New-CimInstance -ClassName MSFT_AdfsAccessControlPolicyParameters `
                    -Namespace root/microsoft/Windows/DesiredStateConfiguration `
                    -Property $mockGroupParameter -ClientOnly

                $mockGroupAccessControlPolicyParameters = @{
                    GroupParameter = $mockGroup
                }
            }

            It 'Should return the correct result' {
                (ConvertTo-AccessControlPolicyParameter -InputObject $mockMSFTAdfsGroupAccessControlPolicyParameters | ConvertTo-Json) | `
                    Should -Be ($mockGroupAccessControlPolicyParameters | ConvertTo-Json)
            }
        }
    }

    Describe 'AdfsDsc.Common\ConvertFrom-AccessControlPolicyParameter' {

        Context 'When the property is ''Group Parameter''' {
            BeforeAll {
                $mockGroups = 'CONTOSO\App1 Users', 'CONTOSO\App1 Admins'

                $mockGroupParameter = @{
                    GroupParameter = $mockGroups
                }

                $mockMSFTGroupAccessControlPolicyParameters = New-CimInstance -ClassName MSFT_AdfsAccessControlPolicyParameters `
                    -Namespace root/microsoft/Windows/DesiredStateConfiguration `
                    -Property $mockGroupParameter -ClientOnly

                $mockGroupAccessControlPolicyParameters = @{
                    GroupParameter = $mockGroups
                }
            }

            It 'Should return the correct result' {
                (ConvertFrom-AccessControlPolicyParameter -Policy $mockGroupAccessControlPolicyParameters | ConvertTo-Json) | `
                    Should -Be ($mockMSFTGroupAccessControlPolicyParameters | ConvertTo-Json)
            }
        }
    }

    Describe 'AdfsDsc.Common\Compare-AccessControlPolicyParameter' {
        BeforeAll {
            $mockParameterName = 'AccessControlPolicyParameters'
        }

        Context 'When the parameter lists are the same' {
            Context 'When the policy contains a ''group parameter''' {
                BeforeAll {
                    $mockGroups = 'CONTOSO\App1 Users', 'CONTOSO\App1 Admins'

                    $mockGroupParameter = @{
                        GroupParameter = $mockGroups
                    }

                    $mockCurrentMSFTAdfsGroupAccessControlPolicyParameters = New-CimInstance `
                        -ClassName MSFT_AdfsAccessControlPolicyParameters `
                        -Namespace root/microsoft/Windows/DesiredStateConfiguration `
                        -Property $mockGroupParameter -ClientOnly
                }

                Context 'When both group parameters are the same' {
                    BeforeAll {
                        $compareAccessControlPolicyParameterResult = Compare-AccessControlPolicyParameter `
                            -CurrentValue $mockCurrentMSFTAdfsGroupAccessControlPolicyParameters `
                            -DesiredValue $mockCurrentMSFTAdfsGroupAccessControlPolicyParameters `
                            -ParameterName $mockParameterName
                    }

                    It 'Should return the correct result' {
                        $compareAccessControlPolicyParameterResult | Should -HaveCount 1
                        $compareAccessControlPolicyParameterResult.ParameterName | Should -Be $mockParameterName
                        $compareAccessControlPolicyParameterResult.InDesiredState | Should -BeTrue
                    }
                }

                Context 'When the group parameters are different' {
                    BeforeAll {
                        $mockDesiredGroups = 'FABRIKAM\App1 Users', 'FABRIKAM\App1 Admins'

                        $mockDesiredGroupParameter = @{
                            GroupParameter = $mockDesiredGroups
                        }

                        $mockDesiredMSFTAdfsGroupAccessControlPolicyParameters = New-CimInstance `
                            -ClassName MSFT_AdfsAccessControlPolicyParameters `
                            -Namespace root/microsoft/Windows/DesiredStateConfiguration `
                            -Property $mockDesiredGroupParameter -ClientOnly

                        $compareAccessControlPolicyParameterResult = Compare-AccessControlPolicyParameter `
                            -CurrentValue $mockCurrentMSFTAdfsGroupAccessControlPolicyParameters `
                            -DesiredValue $mockDesiredMSFTAdfsGroupAccessControlPolicyParameters `
                            -ParameterName $mockParameterName
                    }

                    It 'Should return the correct result' {
                        $compareAccessControlPolicyParameterResult | Should -HaveCount 1
                        $compareAccessControlPolicyParameterResult.ParameterName | Should -Be $mockParameterName
                        $compareAccessControlPolicyParameterResult.InDesiredState | Should -BeFalse
                    }
                }
            }
        }
    }

    Describe 'AdfsDsc.Common\ConvertTo-SamlEndpoint' {
        BeforeAll {
            $mockAdfsSamlEndpoint = @{
                Binding     = 'Redirect'
                Protocol    = 'SAMLAssertionConsumer'
                Uri         = 'https://fabrikam.com/saml/ac'
                Index       = 0
                IsDefault   = $false
                ResponseUri = ''
            }

            $mockMSFTAdfsSamlEndpointParameter = @{
                Binding     = $mockAdfsSamlEndpoint.Binding
                Protocol    = $mockAdfsSamlEndpoint.Protocol
                Uri         = $mockAdfsSamlEndpoint.Uri
                Index       = $mockAdfsSamlEndpoint.Index
                IsDefault   = $mockAdfsSamlEndpoint.IsDefault
                ResponseUri = $mockAdfsSamlEndpoint.ResponseUri
            }

            $mockMSFTAdfsSamlEndpoint = New-CimInstance -ClassName MSFT_AdfsSamlEndpoint `
                -Namespace root/microsoft/Windows/DesiredStateConfiguration `
                -Property $mockMSFTAdfsSamlEndpointParameter -ClientOnly

            Mock -CommandName New-AdfsSamlEndpoint -MockWith { $mockAdfsSamlEndpoint }
        }

        It 'Should return the correct result' {
            (ConvertTo-SamlEndpoint -InputObject $mockMSFTAdfsSamlEndpoint | ConvertTo-Json) | `
                Should -Be ($mockAdfsSamlEndpoint | ConvertTo-Json)
        }

        It 'Should call the expected mocks' {
            Assert-MockCalled -CommandName New-AdfsSamlEndpoint -Exactly -Times 1
        }
    }

    Describe 'AdfsDsc.Common\ConvertFrom-SamlEndpoint' {
        BeforeAll {
            $mockSamlEndpoint = New-MockObject -Type 'Microsoft.IdentityServer.Management.Resources.SamlEndpoint'

            $mockSamlEndpoint.Binding = 'Redirect'
            $mockSamlEndpoint.Protocol = 'SAMLLogout'
            $mockSamlEndpoint.Location = 'https://fabrikam.com/saml/ac'
            $mockSamlEndpoint.Index = 0
            $mockSamlEndpoint.IsDefault = $false
            $mockSamlEndpoint.ResponseLocation = 'https://fabrikam.com/saml/logout'

            $mockMSFTAdfsSamlEndpointParameter = @{
                Binding     = $mockSamlEndpoint.Binding
                Protocol    = $mockSamlEndpoint.Protocol
                Uri         = $mockSamlEndpoint.Location.OriginalString
                Index       = $mockSamlEndpoint.Index
                IsDefault   = $mockSamlEndpoint.IsDefault
                ResponseUri = $mockSamlEndpoint.ResponseLocation.OriginalString
            }

            $mockMSFTAdfsSamlEndpoint = New-CimInstance -ClassName MSFT_AdfsSamlEndpoint `
                -Namespace root/microsoft/Windows/DesiredStateConfiguration `
                -Property $mockMSFTAdfsSamlEndpointParameter -ClientOnly
        }

        It 'Should return the correct result' {
            ((ConvertFrom-SamlEndpoint -SamlEndpoint $mockSamlEndpoint).CimInstanceProperties | Sort-Object | `
                ConvertTo-Json) | Should -Be ($mockMSFTAdfsSamlEndpoint.CimInstanceProperties | Sort-Object | `
                ConvertTo-Json)
        }
    }

    Describe 'AdfsDsc.Common\Compare-SamlEndpoint' {
        BeforeAll {
            $mockParameterName = 'SamlEndpoint'

            $mockMSFTAdfsSamlEndpointParameter = @{
                Binding     = 'Redirect'
                Protocol    = 'SAMLAssertionConsumer'
                Uri         = 'https://fabrikam.com/saml/ac'
                Index       = 0
                IsDefault   = $false
                ResponseUri = ''
            }

            $mockCurrentMSFTAdfsSamlEndpoint = New-CimInstance -ClassName MSFT_AdfsSamlEndpoint `
                -Namespace root/microsoft/Windows/DesiredStateConfiguration `
                -Property $mockMSFTAdfsSamlEndpointParameter -ClientOnly
        }

        Context 'When the SamlEndpoints are the same' {
            BeforeAll {
                $compareSamlEndpointResult = Compare-SamlEndpoint `
                    -CurrentValue $mockCurrentMSFTAdfsSamlEndpoint `
                    -DesiredValue $mockCurrentMSFTAdfsSamlEndpoint `
                    -ParameterName $mockParameterName
            }

            It 'Should return the correct result' {
                $compareSamlEndpointResult | Should -HaveCount 1
                $compareSamlEndpointResult.ParameterName | Should -Be $mockParameterName
                $compareSamlEndpointResult.InDesiredState | Should -BeTrue
            }
        }

        Context 'When the SamlEndpoints are different' {
            BeforeAll {
                $mockDesiredMSFTAdfsSamlEndpointParameter = @{
                    Binding     = 'Post'
                    Protocol    = 'SAMLLogout'
                    Uri         = 'https://contoso.com/saml/ac'
                    Index       = 1
                    IsDefault   = $true
                    ResponseUri = ''
                }

                $mockDesiredMSFTAdfsSamlEndpoint = New-CimInstance -ClassName MSFT_AdfsSamlEndpoint `
                    -Namespace root/microsoft/Windows/DesiredStateConfiguration `
                    -Property $mockDesiredMSFTAdfsSamlEndpointParameter -ClientOnly

                $compareSamlEndpointResult = Compare-SamlEndpoint `
                    -CurrentValue $mockCurrentMSFTAdfsSamlEndpoint `
                    -DesiredValue $mockDesiredMSFTAdfsSamlEndpoint `
                    -ParameterName $mockParameterName
            }

            It 'Should return the correct result' {
                $compareSamlEndpointResult | Should -HaveCount 1
                $compareSamlEndpointResult.ParameterName | Should -Be $mockParameterName
                $compareSamlEndpointResult.InDesiredState | Should -BeFalse
            }
        }

        Context 'When the number of SamlEndpoints are different' {
            BeforeAll {
                $mockDesiredMSFTAdfsSamlEndpointParameter1 = @{
                    Binding     = 'Redirect'
                    Protocol    = 'SAMLAssertionConsumer'
                    Uri         = 'https://fabrikam.com/saml/ac'
                    Index       = 0
                    IsDefault   = $false
                    ResponseUri = ''
                }
                $mockDesiredMSFTAdfsSamlEndpointParameter2 = @{
                    Binding     = 'Post'
                    Protocol    = 'SAMLLogout'
                    Uri         = 'https://contoso.com/saml/ac'
                    Index       = 1
                    IsDefault   = $true
                    ResponseUri = ''
                }

                $mockDesiredMSFTAdfsSamlEndpoint = @(
                    New-CimInstance -ClassName MSFT_AdfsSamlEndpoint `
                        -Namespace root/microsoft/Windows/DesiredStateConfiguration `
                        -Property $mockDesiredMSFTAdfsSamlEndpointParameter1 -ClientOnly
                    New-CimInstance -ClassName MSFT_AdfsSamlEndpoint `
                        -Namespace root/microsoft/Windows/DesiredStateConfiguration `
                        -Property $mockDesiredMSFTAdfsSamlEndpointParameter2 -ClientOnly
                )

                $compareSamlEndpointResult = Compare-SamlEndpoint `
                    -CurrentValue $mockCurrentMSFTAdfsSamlEndpoint `
                    -DesiredValue $mockDesiredMSFTAdfsSamlEndpoint `
                    -ParameterName $mockParameterName
            }

            It 'Should return the correct result' {
                $compareSamlEndpointResult | Should -HaveCount 1
                $compareSamlEndpointResult.ParameterName | Should -Be $mockParameterName
                $compareSamlEndpointResult.InDesiredState | Should -BeFalse
            }
        }
    }
}
