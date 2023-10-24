<#
    .SYNOPSIS
        AdfsServerApplication DSC Resource Integration Tests

    .DESCRIPTION
        Verbose/Debug output can be set by running:

        Invoke-pester -Script @{Path='.\MSFT_AdfsServerApplication.Integration.Tests.ps1';Parameters=@{Verbose=$true;Debug=$true}}

        The AdfsServerApplication resource has a dependency on an AdfsApplicationGroup resource
#>

[CmdletBinding()]
param()

Set-StrictMode -Version 2.0

$script:dscModuleName = 'AdfsDsc'
$script:dscResourceFriendlyName = 'AdfsServerApplication'
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
            Debug        = $true
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

            It 'Should have ensured the resource is absent' {
                $resourceCurrentState = $script:currentConfiguration | Where-Object -FilterScript {
                    $_.ConfigurationName -eq $configurationName
                }
                $resourceCurrentState.Ensure | Should -Be 'Absent'
            }

            It 'Should return $true when Test-DscConfiguration is run' {
                Test-DscConfiguration  | Should -Be 'True'
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

            It 'Should have set the resource and all the parameters should match' {
                $resourceCurrentState = $script:currentConfiguration | Where-Object -FilterScript {
                    $_.ConfigurationName -eq $configurationName `
                        -and $_.ResourceId -eq $resourceId
                }

                Foreach ($property in $ConfigurationData.AdfsServerApplication.Keys)
                {
                    $resourceCurrentState.$property | Should -Be $ConfigurationData.AdfsServerApplication.$property
                }
            }

            It 'Should return $true when Test-DscConfiguration is run' {
                Test-DscConfiguration  | Should -Be 'True'
            }
        }
    }
    #endregion
}
finally
{
    Restore-TestEnvironment -TestEnvironment $script:testEnvironment
}
