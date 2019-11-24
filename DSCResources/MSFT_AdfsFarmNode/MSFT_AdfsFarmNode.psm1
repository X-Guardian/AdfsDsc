<#
    .SYNOPSIS
        DSC module for the ADFS Farm Node resource

    .DESCRIPTION
        The AdfsFarmNode DSC resource manages an additional node in a pre-existing Active Directory Federation Service
        server farm.

        ## Requirements

        - The `SQLConnectionString` parameter should be the same as was specified for the ADFS Farm.
        - The `ServiceAccountCredential` or `GroupServiceAccountIdentifier` should be the same as was specified for the
        ADFS farm.

    .PARAMETER FederationServiceName
        Key - String
        Specifies the DNS name of the federation service.

    .PARAMETER CertificateThumbprint
        Required - String
        Specifies the value of the certificate thumbprint of the certificate that should be used in the SSL binding of
        the Default Web Site in IIS. This value should match the thumbprint of a valid certificate in the Local
        Computer certificate store.

    .PARAMETER Credential
        Required - String
        Specifies a PSCredential object that must have domain administrator privileges.

    .PARAMETER GroupServiceAccountIdentifier
        Write - String
        Specifies the Group Managed Service Account under which the Active Directory Federation Services (AD FS)
        service runs.

    .PARAMETER OverwriteConfiguration
        Write - Boolean
        This parameter must be used to remove an existing AD FS configuration database and overwrite it with a new
        database.

    .PARAMETER PrimaryComputerName
        Write - String
        Specifies the name of the primary in a farm. The cmdlet adds the computer to the farm that has the primary that
        you specify.

    .PARAMETER PrimaryComputerPort
        Write - Sint32
        Specifies the primary computer port. The computer uses the HTTP port that you specify to connect with the
        primary computer in order to synchronize configuration settings. Specify a value of 80 for this parameter, or
        specify an alternate value if the HTTP port on the primary computer is not 80. If this parameter is not
        specified, a default port value of 80 is assumed.

    .PARAMETER ServiceAccountCredential
        Write - String
        Specifies the Active Directory account under which the AD FS service runs. All nodes in the farm must use the
        same service account.

    .PARAMETER SQLConnectionString
        Write - String
        Specifies the SQL Server database that will store the AD FS configuration settings. If not specified, AD FS
        uses Windows Internal Database to store configuration settings.

    .PARAMETER Ensure
        Write - String
        Allowed values: Present, Absent
        Specifies whether the ADFS Farm Node should be present or absent. Default value is 'Present'.
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

$script:adfsServiceName = 'adfssrv'
$script:syncPropertiesTypeName = 'Microsoft.IdentityServer.Management.Resources.SyncProperties'
$script:syncPropertiesBaseTypeName = 'Microsoft.IdentityServer.Management.Resources.SyncPropertiesBase'

function Get-TargetResource
{
    <#
    .SYNOPSIS
        Get-TargetResource

    .NOTES
        Used Cmdlets/Functions:

        Name                        | Module
        ----------------------------|----------------
        Get-AdfsSslCertificate      | Adfs
        Get-AdfsSyncProperties      | Adfs
        Assert-Module               | AdfsDsc.Common
        Assert-DomainMember         | AdfsDsc.Common
        Get-AdfsConfigurationStatus | AdfsDsc.Common
        Assert-AdfsService          | AdfsDsc.Common
        Assert-GroupServiceAccount  | AdfsDsc.Common
        New-CimCredentialInstance   | AdfsDsc.Common
    #>

    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $FederationServiceName,

        [Parameter(Mandatory = $true)]
        [System.String]
        $CertificateThumbprint,

        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]
        $Credential
    )

    # Set Verbose and Debug parameters
    $commonParms = @{
        Verbose = $VerbosePreference
        Debug   = $DebugPreference
    }

    Write-Verbose -Message ($script:localizedData.GettingResourceMessage -f $FederationServiceName)

    # Check of the Resource PowerShell module is installed
    Assert-Module -ModuleName $script:psModuleName

    # Test if the computer is a domain member
    Assert-DomainMember

    # Check if the ADFS service has been configured
    if ((Get-AdfsConfigurationStatus) -eq 'Configured')
    {
        # Resource is Present
        Write-Debug -Message ($script:localizedData.TargetResourcePresentDebugMessage -f $FederationServiceName)

        # Assert if the ADFS service exists and is running
        Assert-AdfsService @commonParms

        try
        {
            $adfsSslCertificate = Get-AdfsSslCertificate
        }
        catch
        {
            $errorMessage = $script:localizedData.GettingAdfsSslCertificateErrorMessage -f $FederationServiceName
            New-InvalidOperationException -Message $errorMessage -ErrorRecord $_
        }

        $sslCertificate = $adfsSslCertificate | Select-Object -First 1
        if ($sslCertificate)
        {
            $certificateThumbprint = $sslCertificate.CertificateHash
        }
        else
        {
            $errorMessage = $script:localizedData.GettingAdfsSslCertificateErrorMessage -f $FederationServiceName
            New-InvalidOperationException -Message $errorMessage
        }

        # Get ADFS service StartName (log on as) property
        $adfsService = Get-CimInstance -ClassName Win32_Service `
            -Filter "Name='$script:AdfsServiceName'" `
            -Verbose:$false

        if ($adfsService)
        {
            $ServiceAccountName = $adfsService.StartName
        }
        else
        {
            $errorMessage = $script:localizedData.GettingAdfsServiceErrorMessage -f $FederationServiceName
            New-InvalidOperationException -Message $errorMessage
        }

        # Test if service account is a group managed service account
        if (Assert-GroupServiceAccount -Name $ServiceAccountName)
        {
            $groupServiceAccountIdentifier = $adfsService.StartName
            $serviceAccountCredential = $null
        }
        else
        {
            $serviceAccountCredential = New-CimCredentialInstance -UserName $adfsService.StartName
            $groupServiceAccountIdentifier = $null
        }

        try
        {
            $adfsSyncProperties = Get-AdfsSyncProperties
        }
        catch
        {
            $errorMessage = $script:localizedData.GettingAdfsSyncPropertiesErrorMessage -f $FederationServiceName
            New-InvalidOperationException -Message $errorMessage -ErrorRecord $_
        }

        # If using WID, object returned is of type 'SyncProperties' with PrimaryComputerName/Port properties
        $adfsSyncPropertiesObjectTypeName = Get-ObjectType -Object $adfsSyncProperties
        if ($adfsSyncPropertiesObjectTypeName -eq $script:SyncPropertiesTypeName)
        {
            $primaryComputerName = $adfsSyncProperties.PrimaryComputerName
            $primaryComputerPort = $adfsSyncProperties.PrimaryComputerPort
        }
        # If using SQL, object returned is of type 'SyncPropertiesBase', with no PrimaryComputerName/Port properties
        elseif ($adfsSyncPropertiesObjectTypeName -eq $script:syncPropertiesBaseTypeName)
        {
            $primaryComputerName = $null
            $primaryComputerPort = $null
        }
        else
        {
            $errorMessage = ($script:localizedData.UnknownAdfsSyncPropertiesObjectTypeErrorMessage -f
                $adfsSyncPropertiesObjectTypeName)
            New-InvalidOperationException -Message $errorMessage
        }

        # Get ADFS SQL Connection String
        try
        {
            $adfsSecurityTokenService = Get-CimInstance -Namespace 'root/ADFS' `
                -ClassName 'SecurityTokenService' -Verbose:$false
        }
        catch
        {
            $errorMessage = $script:localizedData.GettingAdfsSecurityTokenServiceErrorMessage -f $FederationServiceName
            New-InvalidOperationException -Message $errorMessage -ErrorRecord $_
        }

        $sqlConnectionString = $adfsSecurityTokenService.ConfigurationDatabaseConnectionString

        $returnValue = @{
            FederationServiceName         = $FederationServiceName
            CertificateThumbprint         = $certificateThumbprint
            GroupServiceAccountIdentifier = $groupServiceAccountIdentifier
            ServiceAccountCredential      = $serviceAccountCredential
            PrimaryComputerName           = $primaryComputerName
            PrimaryComputerPort           = $primaryComputerPort
            SQLConnectionString           = $sqlConnectionString
            Ensure                        = 'Present'
        }
    }
    else
    {
        # Resource is Absent
        Write-Debug -Message ($script:localizedData.TargetResourceAbsentDebugMessage -f $FederationServiceName)

        $returnValue = @{
            FederationServiceName         = $FederationServiceName
            CertificateThumbprint         = $null
            GroupServiceAccountIdentifier = $null
            ServiceAccountCredential      = $null
            PrimaryComputerName           = $null
            PrimaryComputerPort           = $null
            SQLConnectionString           = $null
            Ensure                        = 'Absent'
        }
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

        Name                | Module
        --------------------|----------------
        Add-AdfsFarmNode    | AdfsDsc
        Remove-AdfsFarmNode | AdfsDsc

    #>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidGlobalVars', '',
        Justification = 'Set LCM DSCMachineStatus to indicate reboot required')]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $FederationServiceName,

        [Parameter(Mandatory = $true)]
        [System.String]
        $CertificateThumbprint,

        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]
        $Credential,

        [Parameter()]
        [System.String]
        $GroupServiceAccountIdentifier,

        [Parameter()]
        [System.Boolean]
        $OverwriteConfiguration,

        [Parameter()]
        [System.String]
        $PrimaryComputerName,

        [Parameter()]
        [System.Int32]
        $PrimaryComputerPort,

        [Parameter()]
        [System.Management.Automation.PSCredential]
        $ServiceAccountCredential,

        [Parameter()]
        [System.String]
        $SQLConnectionString,

        [Parameter()]
        [ValidateSet('Present', 'Absent')]
        [System.String]
        $Ensure = 'Present'
    )

    Write-Verbose -Message ($script:localizedData.SettingResourceMessage -f $FederationServiceName)

    # Remove any parameters not used in Splats
    [HashTable]$parameters = $PSBoundParameters
    $parameters.Remove('Ensure')
    $parameters.Remove('FederationServiceName')
    $parameters.Remove('Verbose')

    # Check whether both credential parameters have been specified
    if ($PSBoundParameters.ContainsKey('ServiceAccountCredential') -and
        $PSBoundParameters.ContainsKey('GroupServiceAccountIdentifier'))
    {
        $errorMessage = $script:localizedData.ResourceDuplicateCredentialErrorMessage -f $FederationServiceName
        New-InvalidArgumentException -Message $errorMessage -ArgumentName 'ServiceAccountCredential'
    }

    # Check whether no credential parameters have been specified
    if (-not $PSBoundParameters.ContainsKey('ServiceAccountCredential') -and
        -not $PSBoundParameters.ContainsKey('GroupServiceAccountIdentifier'))
    {
        $errorMessage = $script:localizedData.ResourceMissingCredentialErrorMessage -f $FederationServiceName
        New-InvalidArgumentException -Message $errorMessage -ArgumentName 'ServiceAccountCredential'
    }

    $GetTargetResourceParms = @{
        FederationServiceName = $FederationServiceName
        CertificateThumbprint = $CertificateThumbprint
        Credential            = $Credential
    }
    $targetResource = Get-TargetResource @GetTargetResourceParms

    if ($Ensure -eq 'Present')
    {
        # Resource should be Present
        Write-Debug -Message ($script:localizedData.TargetResourceShouldBePresentDebugMessage -f $FederationServiceName)

        if ($targetResource.Ensure -eq 'Absent')
        {
            # Resource is Absent
            Write-Debug -Message ($script:localizedData.TargetResourceAbsentDebugMessage -f $FederationServiceName)

            Write-Verbose -Message ($script:localizedData.InstallingResourceMessage -f $FederationServiceName)

            try
            {
                $Result = Add-AdfsFarmNode @parameters -ErrorAction SilentlyContinue
            }
            catch [System.IO.FileNotFoundException]
            {
                Write-Verbose -Message ($script:localizedData.MissingAdfsAssembliesMessage)

                # Set DSC Reboot required flag
                [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseDeclaredVarsMoreThanAssignments", "",
                    Justification = 'Set LCM DSCMachineStatus to indicate reboot required')]
                $global:DSCMachineStatus = 1
                return
            }
            catch
            {
                $errorMessage = $script:localizedData.InstallationErrorMessage -f $FederationServiceName
                New-InvalidOperationException -Message $errorMessage -ErrorRecord $_
            }

            if ($Result.Status -eq 'Success')
            {
                Write-Verbose -Message ($script:localizedData.ResourceInstallSuccessMessage -f $FederationServiceName)

                [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseDeclaredVarsMoreThanAssignments", "",
                    Justification = 'Set LCM DSCMachineStatus to indicate reboot required')]
                $global:DSCMachineStatus = 1
                return
            }
            else
            {
                New-InvalidOperationException -Message $Result.Message
            }
        }
        else
        {
            # Resource is Present
            Write-Debug -Message ($script:localizedData.TargetResourcePresentDebugMessage -f $FederationServiceName)

            Write-Verbose -Message ($script:localizedData.ResourceInDesiredStateMessage -f $FederationServiceName)
        }
    }
    else
    {
        # Resource should be Absent
        Write-Debug -Message ($script:localizedData.TargetResourceShouldBeAbsentDebugMessage -f $FederationServiceName)

        if ($targetResource.Ensure -eq 'Present')
        {
            # Resource is Present
            Write-Debug -Message ($script:localizedData.TargetResourcePresentDebugMessage -f $FederationServiceName)

            $parameters.Remove('CertificateThumbprint')
            $parameters.Remove('OverwriteConfiguration')
            $parameters.Remove('SqlConnectionString')
            $parameters.Remove('PrimaryComputerName')
            $parameters.Remove('PrimaryComputerPort')

            Write-Verbose -Message ($script:localizedData.RemovingResourceMessage -f $FederationServiceName)

            try
            {
                Remove-AdfsFarmNode @parameters
            }
            catch
            {
                $errorMessage = $script:localizedData.RemovalErrorMessage -f $FederationServiceName
                New-InvalidOperationException -Message $errorMessage -ErrorRecord $_
            }
        }
        else
        {
            # Resource is Absent
            Write-Debug -Message ($script:localizedData.TargetResourceAbsentDebugMessage -f $FederationServiceName)

            Write-Verbose -Message ($script:localizedData.ResourceInDesiredStateMessage -f $FederationServiceName)
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
        [System.String]
        $FederationServiceName,

        [Parameter(Mandatory = $true)]
        [System.String]
        $CertificateThumbprint,

        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]
        $Credential,

        [Parameter()]
        [System.String]
        $GroupServiceAccountIdentifier,

        [Parameter()]
        [System.Boolean]
        $OverwriteConfiguration,

        [Parameter()]
        [System.String]
        $PrimaryComputerName,

        [Parameter()]
        [System.Int32]
        $PrimaryComputerPort,

        [Parameter()]
        [System.Management.Automation.PSCredential]
        $ServiceAccountCredential,

        [Parameter()]
        [System.String]
        $SQLConnectionString,

        [Parameter()]
        [ValidateSet('Present', 'Absent')]
        [System.String]
        $Ensure = 'Present'
    )

    Write-Verbose -Message ($script:localizedData.TestingResourceMessage -f $FederationServiceName)

    $getTargetResourceParms = @{
        FederationServiceName = $FederationServiceName
        CertificateThumbprint = $CertificateThumbprint
        Credential            = $Credential
    }
    $targetResource = Get-TargetResource @getTargetResourceParms

    if ($targetResource.Ensure -eq 'Present')
    {
        # Resource exists
        if ($Ensure -eq 'Present')
        {
            # Resource should be Present
            Write-Debug -Message ($script:localizedData.TargetResourceShouldBePresentDebugMessage -f
                $FederationServiceName)

            Write-Verbose -Message ($script:localizedData.ResourceInDesiredStateMessage -f $FederationServiceName)

            $inDesiredState = $true
        }
        else
        {
            # Resource should be Absent
            Write-Debug -Message ($script:localizedData.TargetResourceShouldBeAbsentDebugMessage -f
                $FederationServiceName)

            Write-Verbose -Message ($script:localizedData.ResourceIsPresentButShouldBeAbsentMessage -f
                $FederationServiceName)

            $inDesiredState = $false
        }
    }
    else
    {
        # Resource is Absent
        if ($Ensure -eq 'Present')
        {
            # Resource should be Present
            Write-Debug -Message ($script:localizedData.TargetResourceShouldBePresentDebugMessage -f
                $FederationServiceName)

            Write-Verbose -Message ($script:localizedData.ResourceIsAbsentButShouldBePresentMessage -f
                $FederationServiceName)

            $inDesiredState = $false
        }
        else
        {
            # Resource should be Absent
            Write-Debug -Message ($script:localizedData.TargetResourceShouldBeAbsentDebugMessage -f
                $FederationServiceName)

            Write-Verbose -Message ($script:localizedData.ResourceInDesiredStateMessage -f $FederationServiceName)

            $inDesiredState = $true
        }
    }

    if ($inDesiredState)
    {
        Write-Verbose -Message ($script:localizedData.ResourceInDesiredStateMessage -f $FederationServiceName)
    }

    $inDesiredState
}

Export-ModuleMember -Function *-TargetResource
