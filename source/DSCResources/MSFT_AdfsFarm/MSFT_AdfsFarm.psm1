<#
    .SYNOPSIS
        DSC module for the ADFS Farm resource

    .DESCRIPTION
        The AdfsFarm DSC resource installs an Active Directory Federation Services server farm, and the primary node of
        the farm. To further manage the configuration of ADFS, the ADFSProperties DSC resource should be used.

        Note: removal of the ADFS server farm using this resource is not supported. Remove the Adfs-Federation role
        from the server instead.

    .PARAMETER FederationServiceName
        Key - String
        Specifies the DNS name of the federation service. This value must match the subject name of the specified
        certificate.

    .PARAMETER CertificateThumbprint
        Required - String
        Specifies the thumbprint of the certificate to use for HTTPS bindings and service communication for ADFS. This
        value should match the thumbprint of a valid certificate in the Local Computer certificate store.

    .PARAMETER Credential
        Required - String
        Specifies a PSCredential object that must have domain administrator privileges.

    .PARAMETER FederationServiceDisplayName
        Write - String
        Specifies the display name of the Federation Service.

    .PARAMETER GroupServiceAccountIdentifier
        Write - String
        Specifies the Group Managed Service Account under which the Active Directory Federation Services (AD FS)
        service runs.

    .PARAMETER OverwriteConfiguration
        Write - Boolean
        This parameter must be used to remove an existing Active Directory Federation Services (AD FS) configuration
        database and overwrite it with a new database.

    .PARAMETER ServiceAccountCredential
        Write - String
        Specifies the Active Directory account under which the AD FS service runs in the form: <domain name>\\<user
        name>.

    .PARAMETER SQLConnectionString
        Write - String
        Specifies the SQL Server database that will store the AD FS configuration settings. If not specified, the AD FS
        installer uses the Windows Internal Database to store configuration settings.

    .PARAMETER Ensure
        Read - String
        The state of the ADFS Farm.
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
        Get-AdfsProperties          | Adfs
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
            $adfsProperties = Get-AdfsProperties
        }
        catch
        {
            $errorMessage = $script:localizedData.GettingAdfsPropertiesErrorMessage -f $FederationServiceName
            New-InvalidOperationException -Message $errorMessage -ErrorRecord $_
        }

        try
        {
            $adfsSslCertificate = Get-AdfsSslCertificate | Select-Object -First 1
        }
        catch
        {
            $errorMessage = $script:localizedData.GettingAdfsSslCertificateErrorMessage -f $FederationServiceName
            New-InvalidOperationException -Message $errorMessage -ErrorRecord $_
        }

        if ($adfsSslCertificate)
        {
            $certificateThumbprint = $adfsSslCertificate.CertificateHash
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
            FederationServiceName         = $adfsProperties.HostName
            CertificateThumbprint         = $certificateThumbprint
            FederationServiceDisplayName  = $adfsProperties.DisplayName
            GroupServiceAccountIdentifier = $groupServiceAccountIdentifier
            ServiceAccountCredential      = $serviceAccountCredential
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
            CertificateThumbprint         = $CertificateThumbprint
            FederationServiceDisplayName  = $null
            GroupServiceAccountIdentifier = $null
            ServiceAccountCredential      = $null
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

        Name             | Module
        -----------------|----------------
        Install-AdfsFarm | Adfs

        Install-AdfsFarm returns a [Microsoft.IdentityServer.Deployment.Core.Result] object with
        the following properties:

            Context - string
            Message - string
            Status  - Microsoft.IdentityServer.Deployment.Core.ResultStatus

        Examples:

            Message : The configuration completed successfully.
            Context : DeploymentSucceeded
            Status  : Success

            Message : The AD FS Windows Service could not be started. Cannot start service adfssrv
                      on computer '.'.
            Context : DeploymentTask
            Status  : Error
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
        $FederationServiceDisplayName,

        [Parameter()]
        [System.String]
        $GroupServiceAccountIdentifier,

        [Parameter()]
        [System.Boolean]
        $OverwriteConfiguration,

        [Parameter()]
        [System.Management.Automation.PSCredential]
        $ServiceAccountCredential,

        [Parameter()]
        [System.String]
        $SQLConnectionString
    )

    Write-Verbose -Message ($script:localizedData.SettingResourceMessage -f $FederationServiceName)

    # Remove any parameters not used in Splats
    [HashTable]$parameters = $PSBoundParameters
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

    if ($targetResource.Ensure -eq 'Absent')
    {
        # Resource is Absent
        Write-Debug -Message ($script:localizedData.TargetResourceAbsentDebugMessage -f $FederationServiceName)

        Write-Verbose -Message ($script:localizedData.InstallingResourceMessage -f $FederationServiceName)

        try
        {
            $Result = Install-AdfsFarm @parameters -ErrorAction SilentlyContinue
        }
        catch [System.IO.FileNotFoundException]
        {
            Write-Verbose -Message ($script:localizedData.MissingAdfsAssembliesMessage)

            # Set DSC Reboot required flag
            [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '',
                Justification = 'Set LCM DSCMachineStatus to indicate reboot required')]
            $global:DSCMachineStatus = 1
            return
        }
        catch
        {
            $errorMessage = $script:localizedData.InstallationErrorMessage -f $FederationServiceName
            New-InvalidOperationException -Message $errorMessage -ErrorRecord $_
        }

        # Check if a group managed service account is specified and the service won't start.
        if ($Result.Status -eq 'Error' -and $Result.Message -like '*Cannot start service adfssrv*' -and
            $PSBoundParameters.ContainsKey('GroupServiceAccountIdentifier'))
        {
            # Check the Kerberos Encryption types
        }

        if ($Result.Status -eq 'Success')
        {
            Write-Verbose -Message ($script:localizedData.ResourceInstallSuccessMessage -f $FederationServiceName)

            # Set DSC Reboot required flag
            [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseDeclaredVarsMoreThanAssignments", "",
                Justification = 'Set LCM DSCMachineStatus to indicate reboot required')]
            $global:DSCMachineStatus = 1
        }
        else
        {
            New-InvalidOperationException -Message $Result.Message
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
        $FederationServiceDisplayName,

        [Parameter()]
        [System.String]
        $GroupServiceAccountIdentifier,

        [Parameter()]
        [System.Boolean]
        $OverwriteConfiguration,

        [Parameter()]
        [System.Management.Automation.PSCredential]
        $ServiceAccountCredential,

        [Parameter()]
        [System.String]
        $SQLConnectionString
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
        # Resource is Present
        Write-Debug -Message ($script:localizedData.TargetResourcePresentDebugMessage -f $FederationServiceName)

        Write-Verbose -Message ($script:localizedData.ResourceInDesiredStateMessage -f $FederationServiceName)

        $inDesiredState = $true
    }
    else
    {
        # Resource is Absent
        Write-Debug -Message ($script:localizedData.TargetResourceAbsentDebugMessage -f $FederationServiceName)

        Write-Verbose -Message ($script:localizedData.ResourceIsAbsentButShouldBePresentMessage -f
            $FederationServiceName)

        $inDesiredState = $false
    }

    $inDesiredState
}

Export-ModuleMember -Function *-TargetResource
