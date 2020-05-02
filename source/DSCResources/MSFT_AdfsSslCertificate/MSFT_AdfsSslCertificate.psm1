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
        Used Cmdlets/Functions:

        Name                   | Module
        -----------------------|----------------
        Get-AdfsSslCertificate | Adfs
        Assert-Module          | AdfsDsc.Common
        Assert-AdfsService     | AdfsDsc.Common
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

    # Set Verbose and Debug parameters
    $commonParms = @{
        Verbose = $VerbosePreference
        Debug   = $DebugPreference
    }

    Write-Verbose -Message ($script:localizedData.GettingResourceMessage -f $CertificateType)

    # Check of the Resource PowerShell module is installed
    Assert-Module -ModuleName $script:psModuleName

    # Check if the ADFS Service is present and running
    Assert-AdfsService @commonParms

    try
    {
        $targetResource = Get-AdfsSslCertificate | Select-Object -First 1
    }
    catch
    {
        $errorMessage = $script:localizedData.GettingResourceErrorMessage -f $CertificateType
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
        Used Cmdlets/Functions:

        Name                          | Module
        ------------------------------|----------------
        Set-AdfsSslCertificate        | Adfs
        Compare-ResourcePropertyState | AdfsDsc.Common
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

    # Set Verbose and Debug parameters
    $commonParms = @{
        Verbose = $VerbosePreference
        Debug   = $DebugPreference
    }

    Write-Verbose -Message ($script:localizedData.SettingResourceMessage -f $CertificateType)

    # Remove any parameters not used in Splats
    [HashTable]$parameters = $PSBoundParameters
    $parameters.Remove('CertificateType')
    $parameters.Remove('RemoteCredential')

    $GetTargetResourceParms = @{
        CertificateType = $CertificateType
        Thumbprint      = $Thumbprint
    }
    $targetResource = Get-TargetResource @GetTargetResourceParms

    $propertiesNotInDesiredState = (
        Compare-ResourcePropertyState -CurrentValues $targetResource -DesiredValues $parameters `
            @commonParms | Where-Object -Property InDesiredState -eq $false)

    $setParameters = @{ }
    foreach ($property in $propertiesNotInDesiredState)
    {
        Write-Verbose -Message ($script:localizedData.SettingResourcePropertyMessage -f
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
        $errorMessage = $script:localizedData.SettingResourceErrorMessage -f $CertificateType
        New-InvalidOperationException -Message $errorMessage -Error $_
    }
}

function Test-TargetResource
{
    <#
    .SYNOPSIS
        Test-TargetResource

    .NOTES
        Used Cmdlets/Functions:

        Name                          | Module
        ------------------------------|------------------
        Compare-ResourcePropertyState | AdfsDsc.Common
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

    # Set Verbose and Debug parameters
    $commonParms = @{
        Verbose = $VerbosePreference
        Debug   = $DebugPreference
    }

    # Remove any parameters not used in Splats
    [HashTable]$parameters = $PSBoundParameters
    $parameters.Remove('RemoteCredential')

    Write-Verbose -Message ($script:localizedData.TestingResourceMessage -f $CertificateType)

    $getTargetResourceParms = @{
        CertificateType = $CertificateType
        Thumbprint      = $Thumbprint
    }
    $targetResource = Get-TargetResource @getTargetResourceParms

    $propertiesNotInDesiredState = (
        Compare-ResourcePropertyState -CurrentValues $targetResource -DesiredValues $parameters `
            @commonParms | Where-Object -Property InDesiredState -eq $false)

    if ($propertiesNotInDesiredState)
    {
        # Resource is not in desired state
        Write-Verbose -Message ($script:localizedData.ResourceNotInDesiredStateMessage -f $CertificateType)

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
