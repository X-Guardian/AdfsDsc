<#
    .SYNOPSIS
        DSC module for the ADFS SSL Certificate resource

    .DESCRIPTION
        The AdfsSslCertificate Dsc resource manages the SSL certificate used for HTTPS binding for Active Directory
        Federation Services

        On Server 2016 and above, this is a multi-node resource, meaning it only has to run on the primary and all
        nodes in the farm will be updated. On Server 2012R2, run the command on each ADFS server in the ADFS farm.

        Note: in order to succesfully update the certificate binding on all farm members, WinRM must be configured on
        all remote nodes and using the standard HTTP listener.

    .PARAMETER CertificateType
        Key - String
        Allowed values: Https-Binding
        Specifies the certificate type, must be 'Https-Binding'.

    .PARAMETER Thumbprint
        Required - String
        Specifies the thumbprint of the certificate to use.

    .PARAMETER RemoteCredential
        Write - String
        Specifies the credential to use to connect to WinRM on all the members of the ADFS farm.
#>

Set-StrictMode -Version 2.0

$script:dscModuleName = 'AdfsDsc'
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
        - Get-AdfsSslCertificate - https://docs.microsoft.com/en-us/powershell/module/adfs/get-adfssslcertificate
    #>

    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateSet("Https-Binding")]
        [System.String]
        $CertificateType,

        [Parameter(Mandatory = $true)]
        [System.String]
        $Thumbprint
    )

    # Check of the ADFS PowerShell module is installed
    Assert-Module -ModuleName 'ADFS'

    # Check if the ADFS Service is present and running
    Assert-AdfsService -Verbose

    Write-Verbose -Message ($script:localizedData.GettingResourceMessage -f $CertificateType)

    try
    {
        $targetResource = Get-AdfsSslCertificate | Select-Object -First 1
    }
    catch
    {
        $errorMessage = $script:localizedData.GettingResourceError -f $CertificateType
        New-InvalidOperationException -Message $errorMessage -Error $_
    }
    $returnValue = @{
        CertificateType = $CertificateType
        Thumbprint      = $targetResource.CertificateHash
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
        - Set-AdfsSslCertificate - https://docs.microsoft.com/en-us/powershell/module/adfs/set-adfssslcertificate
    #>

    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateSet("Https-Binding")]
        [System.String]
        $CertificateType,

        [Parameter(Mandatory = $true)]
        [System.String]
        $Thumbprint,

        [Parameter()]
        [System.Management.Automation.PSCredential]
        $RemoteCredential
    )

    [HashTable]$Parameters = $PSBoundParameters
    $Parameters.Remove('CertificateType')
    $Parameters.Remove('RemoteCredential')

    $GetTargetResourceParms = @{
        CertificateType = $CertificateType
        Thumbprint      = $Thumbprint
    }
    $targetResource = Get-TargetResource @GetTargetResourceParms

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

    if ($PSBoundParameters.ContainsKey('RemoteCredential'))
    {
        $setParameters.Add('RemoteCredential', $RemoteCredential)
    }

    try
    {
        Set-AdfsSslCertificate @setParameters
    }
    catch
    {
        $errorMessage = $script:localizedData.SettingResourceError -f $CertificateType
        New-InvalidOperationException -Message $errorMessage -Error $_
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
        [ValidateSet("Https-Binding")]
        [System.String]
        $CertificateType,

        [Parameter(Mandatory = $true)]
        [System.String]
        $Thumbprint,

        [Parameter()]
        [System.Management.Automation.PSCredential]
        $RemoteCredential
    )

    [HashTable]$parameters = $PSBoundParameters
    $parameters.Remove('CertificateType')
    $parameters.Remove('RemoteCredential')

    $GetTargetResourceParms = @{
        CertificateType = $CertificateType
        Thumbprint      = $Thumbprint
    }
    $targetResource = Get-TargetResource @GetTargetResourceParms

    $propertiesNotInDesiredState = (
        Compare-ResourcePropertyState -CurrentValues $targetResource -DesiredValues $parameters |
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
