<#
    .SYNOPSIS
        DSC module for the ADFS Certificate resource

    .DESCRIPTION
        The AdfsCertificate Dsc resource manages certificate that AD FS uses to sign, decrypt, or secure
        communications.

    .PARAMETER CertificateType
        Key - String
        Allowed values: Service-Communications, Token-Decrypting, Token-Signing
        Specifies the certificate type (that is, how the Federation Service uses the certificate).

    .PARAMETER Thumbprint
        Required - String
        Specifies the thumbprint of the certificate to use.
#>

Set-StrictMode -Version 2.0

$script:dscModuleName = 'AdfsDsc'
$script:psModuleName = 'ADFS'
$script:dscResourceName = [System.IO.Path]::GetFileNameWithoutExtension($MyInvocation.MyCommand.Name)

$script:resourceModulePath = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent
$script:modulesFolderPath = Join-Path -Path $script:resourceModulePath -ChildPath 'Modules'

$script:localizationModulePath = Join-Path -Path $script:modulesFolderPath -ChildPath "$($script:DSCModuleName).Common"
Import-Module -Name (Join-Path -Path $script:localizationModulePath -ChildPath "$($script:dscModuleName).Common.psm1")

$script:localizedData = Get-LocalizedData -ResourceName $script:dscResourceName

function Get-TargetResource
{
    <#
    .SYNOPSIS
        Get-TargetResource

    .NOTES
        Used Resource PowerShell Cmdlets:
        - Get-AdfsCertificate - https://docs.microsoft.com/en-us/powershell/module/adfs/get-adfscertificate
    #>

    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateSet('Service-Communications', 'Token-Decrypting', 'Token-Signing')]
        [System.String]
        $CertificateType,

        [Parameter(Mandatory = $true)]
        [System.String]
        $Thumbprint
    )

    # Check of the Resource PowerShell module is installed
    Assert-Module -ModuleName $script:psModuleName

    # Check if the ADFS Service is present and running
    Assert-AdfsService -Verbose

    Write-Verbose -Message ($script:localizedData.GettingResourceMessage -f $CertificateType)

    try
    {
        $targetResource = (Get-AdfsCertificate -CertificateType $CertificateType |
                Where-Object -Property IsPrimary -eq $true | Select-Object -First 1)
    }
    catch
    {
        $errorMessage = $script:localizedData.GettingResourceError -f $CertificateType
        New-InvalidOperationException -Message $errorMessage -Error $_
    }

    $returnValue = @{
        CertificateType = $targetResource.CertificateType
        Thumbprint      = $targetResource.Thumbprint
    }

    $returnValue
}

function Set-TargetResource
{
    <#
    .SYNOPSIS
        Set-TargetResource

    .NOTES
        Used Resource PowerShell Cmdlets:
        - Set-AdfsCertificate - https://docs.microsoft.com/en-us/powershell/module/adfs/set-adfscertificate
    #>

    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateSet('Service-Communications', 'Token-Decrypting', 'Token-Signing')]
        [System.String]
        $CertificateType,

        [Parameter(Mandatory = $true)]
        [System.String]
        $Thumbprint
    )

    [HashTable]$Parameters = $PSBoundParameters

    $getTargetResourceParms = @{
        CertificateType = $CertificateType
        Thumbprint      = $Thumbprint
    }
    $targetResource = Get-TargetResource @getTargetResourceParms

    $propertiesNotInDesiredState = (
        Compare-ResourcePropertyState -CurrentValues $targetResource -DesiredValues $Parameters |
            Where-Object -Property InDesiredState -eq $false)

    $setParameters = @{ }
    foreach ($property in $propertiesNotInDesiredState)
    {
        Write-Verbose -Message (
            $script:localizedData.SettingResourceMessage -f
            $CertificateType, $property.ParameterName, ($property.Expected -join ', '))
        $setParameters.add($property.ParameterName, $property.Expected)
    }

    if ($setParameters.Count -gt 0)
    {
        try
        {
            Set-AdfsCertificate -CertificateType $CertificateType @setParameters
        }
        catch
        {
            $errorMessage = $script:localizedData.SettingResourceError -f $CertificateType
            New-InvalidOperationException -Message $errorMessage -Error $_
        }
    }
}

function Test-TargetResource
{
    <#
    .SYNOPSIS
        Test-TargetResource
    #>

    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateSet('Service-Communications', 'Token-Decrypting', 'Token-Signing')]
        [System.String]
        $CertificateType,

        [Parameter(Mandatory = $true)]
        [System.String]
        $Thumbprint
    )

    $getTargetResourceParms = @{
        CertificateType = $CertificateType
        Thumbprint      = $Thumbprint
    }
    $targetResource = Get-TargetResource @getTargetResourceParms

    $propertiesNotInDesiredState = (
        Compare-ResourcePropertyState -CurrentValues $targetResource -DesiredValues $PSBoundParameters |
            Where-Object -Property InDesiredState -eq $false)

    if ($propertiesNotInDesiredState)
    {
        # Resource is not in desired state
        foreach ($property in $propertiesNotInDesiredState)
        {
            Write-Verbose -Message (
                $script:localizedData.ResourcePropertyNotInDesiredStateMessage -f
                $targetResource.CertificateType, $property.ParameterName,
                $property.Expected, $property.Actual)
        }
        $inDesiredState = $false
    }
    else
    {
        # Resource is in desired state
        Write-Verbose -Message (
            $script:localizedData.ResourceInDesiredStateMessage -f $CertificateType)
        $inDesiredState = $true
    }

    $inDesiredState
}

Export-ModuleMember -Function *-TargetResource
