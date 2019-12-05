<#
    .SYNOPSIS
        AdfsProperties DSC Resource Integration Tests
#>

Set-StrictMode -Version 2.0

if ($env:APPVEYOR -eq $true)
{
    Write-Warning -Message 'Integration test is not supported in AppVeyor.'
    return
}

$script:dscModuleName = 'AdfsDsc'
$script:dscResourceFriendlyName = 'AdfsProperties'
$script:dscResourceName = "MSFT_$($script:dscResourceFriendlyName)"

#region HEADER
# Integration Test Template Version: 1.3.3
[String] $script:moduleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if ( (-not (Test-Path -Path (Join-Path -Path $script:moduleRoot -ChildPath 'DSCResource.Tests'))) -or `
    (-not (Test-Path -Path (Join-Path -Path $script:moduleRoot -ChildPath 'DSCResource.Tests\TestHelper.psm1'))) )
{
    & git @('clone', 'https://github.com/PowerShell/DscResource.Tests.git', (Join-Path -Path $script:moduleRoot -ChildPath 'DscResource.Tests'))
}

Import-Module -Name (Join-Path -Path $script:moduleRoot -ChildPath (Join-Path -Path 'DSCResource.Tests' -ChildPath 'TestHelper.psm1')) -Force
$TestEnvironment = Initialize-TestEnvironment `
    -DSCModuleName $script:dscModuleName `
    -DSCResourceName $script:dscResourceName `
    -TestType Integration
#endregion

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
                    $script:currentConfiguration = Get-DscConfiguration -Verbose -ErrorAction Stop
                } | Should -Not -Throw
            }

            Context 'When the configuration has been set' {
                BeforeAll {
                    $resourceCurrentState = $script:currentConfiguration | Where-Object -FilterScript {
                        $_.ConfigurationName -eq $configurationName `
                            -and $_.ResourceId -eq $resourceId
                    }
                }

                foreach ($property in $ConfigurationData.AdfsPropertiesInit.Keys)
                {
                    It "Should have correctly set the $property parameter" {
                        $resourceCurrentState.$property | Should -Be $ConfigurationData.AdfsPropertiesInit.$property
                    }
                }

                It 'Should return $true when Test-DscConfiguration is run' {
                    Test-DscConfiguration -Verbose | Should -Be 'True'
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
                    $script:currentConfiguration = Get-DscConfiguration -Verbose -ErrorAction Stop
                } | Should -Not -Throw
            }

            Context 'When the configuration has been set' {
                BeforeAll {
                    $resourceCurrentState = $script:currentConfiguration | Where-Object -FilterScript {
                        $_.ConfigurationName -eq $configurationName `
                            -and $_.ResourceId -eq $resourceId
                    }
                }
                foreach ($property in $ConfigurationData.AdfsProperties.Keys)
                {
                    It "Should have correctly set the $property parameter" {
                        $resourceCurrentState.$property | Should -Be $ConfigurationData.AdfsProperties.$property
                    }
                }

                It 'Should return $true when Test-DscConfiguration is run' {
                    Test-DscConfiguration -Verbose | Should -Be 'True'
                }
            }
        }
    }
    #endregion
}
finally
{
    #region FOOTER
    Restore-TestEnvironment -TestEnvironment $TestEnvironment
    #endregion
}
