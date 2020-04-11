<#
    .SYNOPSIS
        AdfsGlobalAuthenticationPolicy DSC Resource Integration Tests

    .DESCRIPTION
        Verbose/Debug output can be set by running:

        Invoke-pester -Script @{Path='.\MSFT_AdfsGlobalAuthenticationPolicy.Integration.Tests.ps1';Parameters=@{Verbose=$true;Debug=$true}}
#>

[CmdletBinding()]
param()

Set-StrictMode -Version 2.0

$script:dscModuleName = 'AdfsDsc'
$script:dscResourceFriendlyName = 'AdfsGlobalAuthenticationPolicy'
$script:dscResourceName = "MSFT_$($script:dscResourceFriendlyName)"

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
    -TestType 'Integration'

try
{
    #region Integration Tests
    $configurationFile = Join-Path -Path $PSScriptRoot -ChildPath "$($script:dscResourceName).config.ps1"
    . $configurationFile

    Describe "$($script:dscResourceName)_Integration" {
        BeforeAll {
            $resourceId = "[$($script:dscResourceFriendlyName)]Integration_Test"
        }

        $startDscConfigurationParameters = @{
            Path         = $TestDrive
            ComputerName = 'localhost'
            Wait         = $true
            Verbose      = $true
            Force        = $true
            ErrorAction  = 'Stop'
        }

        $configurationName = "$($script:dscResourceName)_Init_Config"

        Context ('When using configuration {0}' -f $configurationName) {
            It 'Should compile and apply the MOF without throwing' {
                {
                    $configurationParameters = @{
                        OutputPath        = $TestDrive
                        ConfigurationData = $ConfigurationData
                    }

                    & $configurationName @configurationParameters

                    Start-DscConfiguration @startDscConfigurationParameters
                } | Should -Not -Throw
            }

            It 'Should be able to call Get-DscConfiguration without throwing' {
                {
                    $script:currentConfiguration = Get-DscConfiguration  -ErrorAction Stop
                } | Should -Not -Throw
            }

            Context 'When the configuration has been set' {
                BeforeAll {
                    $resourceCurrentState = $script:currentConfiguration | Where-Object -FilterScript {
                        $_.ConfigurationName -eq $configurationName `
                            -and $_.ResourceId -eq $resourceId
                    }
                }

                foreach ($property in $ConfigurationData.AdfsGlobalAuthenticationPolicyInit.Keys)
                {
                    It "Should have correctly set the $property parameter" {
                        $resourceCurrentState.$property | Should -Be $ConfigurationData.AdfsGlobalAuthenticationPolicyInit.$property
                    }
                }

                It 'Should return $true when Test-DscConfiguration is run' {
                    Test-DscConfiguration  | Should -Be 'True'
                }
            }
        }

        $configurationName = "$($script:dscResourceName)_Config"

        Context ('When using configuration {0}' -f $configurationName) {
            It 'Should compile and apply the MOF without throwing' {
                {
                    $configurationParameters = @{
                        OutputPath        = $TestDrive
                        ConfigurationData = $ConfigurationData
                    }
                    & $configurationName @configurationParameters

                    Start-DscConfiguration @startDscConfigurationParameters
                } | Should -Not -Throw
            }

            It 'Should be able to call Get-DscConfiguration without throwing' {
                {
                    $script:currentConfiguration = Get-DscConfiguration  -ErrorAction Stop
                } | Should -Not -Throw
            }

            Context 'When the configuration has been set' {
                BeforeAll {
                    $resourceCurrentState = $script:currentConfiguration | Where-Object -FilterScript {
                        $_.ConfigurationName -eq $configurationName `
                            -and $_.ResourceId -eq $resourceId
                    }
                }
                foreach ($property in $ConfigurationData.AdfsGlobalAuthenticationPolicy.Keys)
                {
                    It "Should have correctly set the $property parameter" {
                        $resourceCurrentState.$property | Should -Be $ConfigurationData.AdfsGlobalAuthenticationPolicy.$property
                    }
                }

                It 'Should return $true when Test-DscConfiguration is run' {
                    Test-DscConfiguration  | Should -Be 'True'
                }
            }
        }
    }
    #endregion
}
finally
{
    Restore-TestEnvironment -TestEnvironment $script:testEnvironment
}
