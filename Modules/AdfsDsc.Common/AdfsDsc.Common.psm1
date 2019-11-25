Set-StrictMode -Version 2.0

function Get-LocalizedData
{
    <#
    .SYNOPSIS
        Retrieves the localized string data based on the machine's culture.
        Falls back to en-US strings if the machine's culture is not supported.

    .PARAMETER ResourceName
        The name of the resource as it appears before '.strings.psd1' of the localized string file.
        For example:
            For WindowsOptionalFeature: MSFT_WindowsOptionalFeature
            For Service: MSFT_ServiceResource
            For Registry: MSFT_RegistryResource
            For Helper: SqlServerDscHelper

    .PARAMETER ScriptRoot
        Optional. The root path where to expect to find the culture folder. This is only needed
        for localization in helper modules. This should not normally be used for resources.

    .NOTES
        To be able to use localization in the helper function, this function must
        be first in the file, before Get-LocalizedData is used by itself to load
        localized data for this helper module (see directly after this function).
    #>

    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $ResourceName,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $ScriptRoot
    )

    if (-not $ScriptRoot)
    {
        $dscResourcesFolder = Join-Path -Path (Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent) -ChildPath 'DSCResources'
        $resourceDirectory = Join-Path -Path $dscResourcesFolder -ChildPath $ResourceName
    }
    else
    {
        $resourceDirectory = $ScriptRoot
    }

    $localizedStringFileLocation = Join-Path -Path $resourceDirectory -ChildPath $PSUICulture

    if (-not (Test-Path -Path $localizedStringFileLocation))
    {
        # Fallback to en-US
        $localizedStringFileLocation = Join-Path -Path $resourceDirectory -ChildPath 'en-US'
    }

    Import-LocalizedData `
        -BindingVariable 'localizedData' `
        -FileName "$ResourceName.strings.psd1" `
        -BaseDirectory $localizedStringFileLocation

    return $localizedData
}

function New-InvalidArgumentException
{
    <#
    .SYNOPSIS
        Creates and throws an invalid argument exception.

    .PARAMETER Message
        The message explaining why this error is being thrown.

    .PARAMETER ArgumentName
        The name of the invalid argument that is causing this error to be thrown.
    #>

    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Message,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $ArgumentName
    )

    $argumentException = New-Object -TypeName 'ArgumentException' -ArgumentList @($Message, $ArgumentName)

    $newObjectParameters = @{
        TypeName     = 'System.Management.Automation.ErrorRecord'
        ArgumentList = @($argumentException, $ArgumentName, 'InvalidArgument', $null)
    }

    $errorRecord = New-Object @newObjectParameters

    throw $errorRecord
}

function New-InvalidOperationException
{
    <#
    .SYNOPSIS
        Creates and throws an invalid operation exception.

    .PARAMETER Message
        The message explaining why this error is being thrown.

    .PARAMETER ErrorRecord
        The error record containing the exception that is causing this terminating error.
    #>

    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Message,

        [Parameter()]
        [ValidateNotNull()]
        [System.Management.Automation.ErrorRecord]
        $ErrorRecord
    )

    if ($null -eq $ErrorRecord)
    {
        $invalidOperationException = New-Object -TypeName 'InvalidOperationException' `
            -ArgumentList @($Message)
    }
    else
    {
        $invalidOperationException = New-Object -TypeName 'InvalidOperationException' `
            -ArgumentList @($Message, $ErrorRecord.Exception)
    }

    $newObjectParameters = @{
        TypeName     = 'System.Management.Automation.ErrorRecord'
        ArgumentList = @(
            $invalidOperationException.ToString(),
            'MachineStateIncorrect',
            'InvalidOperation',
            $null
        )
    }

    $errorRecordToThrow = New-Object @newObjectParameters

    throw $errorRecordToThrow
}

function New-ObjectNotFoundException
{
    <#
    .SYNOPSIS
        Creates and throws an object not found exception.

    .PARAMETER Message
        The message explaining why this error is being thrown.

    .PARAMETER ErrorRecord
        The error record containing the exception that is causing this terminating error.
    #>

    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Message,

        [Parameter()]
        [ValidateNotNull()]
        [System.Management.Automation.ErrorRecord]
        $ErrorRecord
    )

    if ($null -eq $ErrorRecord)
    {
        $exception = New-Object -TypeName 'System.Exception' -ArgumentList @($Message)
    }
    else
    {
        $exception = New-Object -TypeName 'System.Exception' -ArgumentList @($Message, $ErrorRecord.Exception)
    }

    $newObjectParameters = @{
        TypeName     = 'System.Management.Automation.ErrorRecord'
        ArgumentList = @(
            $exception.ToString(),
            'MachineStateIncorrect',
            'ObjectNotFound',
            $null
        )
    }

    $errorRecordToThrow = New-Object @newObjectParameters

    throw $errorRecordToThrow
}

function New-InvalidResultException
{
    <#
    .SYNOPSIS
        Creates and throws an invalid result exception.

    .PARAMETER Message
        The message explaining why this error is being thrown.

    .PARAMETER ErrorRecord
        The error record containing the exception that is causing this terminating error.
    #>

    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Message,

        [Parameter()]
        [ValidateNotNull()]
        [System.Management.Automation.ErrorRecord]
        $ErrorRecord
    )

    if ($null -eq $ErrorRecord)
    {
        $exception = New-Object -TypeName 'System.Exception' -ArgumentList @($Message)
    }
    else
    {
        $exception = New-Object -TypeName 'System.Exception' -ArgumentList @($Message, $ErrorRecord.Exception)
    }

    $newObjectParameters = @{
        TypeName     = 'System.Management.Automation.ErrorRecord'
        ArgumentList = @(
            $exception.ToString(),
            'MachineStateIncorrect',
            'InvalidResult',
            $null
        )
    }

    $errorRecordToThrow = New-Object @newObjectParameters

    throw $errorRecordToThrow
}

function New-NotImplementedException
{
    <#
    .SYNOPSIS
        Creates and throws a not implemented exception.

    .PARAMETER Message
        The message explaining why this error is being thrown.

    .PARAMETER ErrorRecord
        The error record containing the exception that is causing this terminating error.
    #>

    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Message,

        [Parameter()]
        [ValidateNotNull()]
        [System.Management.Automation.ErrorRecord]
        $ErrorRecord
    )

    if ($null -eq $ErrorRecord)
    {
        $exception = New-Object -TypeName 'System.NotImplementedException' `
            -ArgumentList @($Message)
    }
    else
    {
        $exception = New-Object -TypeName 'System.NotImplementedException' `
            -ArgumentList @($Message, $ErrorRecord.Exception)
    }

    $newObjectParameters = @{
        TypeName     = 'System.Management.Automation.ErrorRecord'
        ArgumentList = @(
            $exception.ToString(),
            'MachineStateIncorrect',
            'NotImplemented',
            $null
        )
    }

    $errorRecordToThrow = New-Object @newObjectParameters

    throw $errorRecordToThrow
}

function ConvertTo-TimeSpan
{
    <#
    .SYNOPSIS
        Convert a specified time period in seconds, minutes, hours or days into
        a time span object.

    .PARAMETER TimeSpan
        The length of time to use for the time span.

    .PARAMETER TimeSpanType
        The units of measure in the TimeSpan parameter.
    #>

    [CmdletBinding()]
    [OutputType([System.TimeSpan])]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.UInt32]
        $TimeSpan,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Seconds', 'Minutes', 'Hours', 'Days')]
        [System.String]
        $TimeSpanType
    )

    $newTimeSpanParams = @{ }

    switch ($TimeSpanType)
    {
        'Seconds'
        {
            $newTimeSpanParams['Seconds'] = $TimeSpan
        }

        'Minutes'
        {
            $newTimeSpanParams['Minutes'] = $TimeSpan
        }

        'Hours'
        {
            $newTimeSpanParams['Hours'] = $TimeSpan
        }

        'Days'
        {
            $newTimeSpanParams['Days'] = $TimeSpan
        }
    }
    return (New-TimeSpan @newTimeSpanParams)
}

function ConvertFrom-TimeSpan
{
    <#
    .SYNOPSIS
        Converts a System.TimeSpan into the number of seconds, minutes, hours or days.

    .PARAMETER TimeSpan
        TimeSpan to convert into an integer

    .PARAMETER TimeSpanType
        Convert timespan into the total number of seconds, minutes, hours or days.

    .EXAMPLE
        ConvertFrom-TimeSpan -TimeSpan (New-TimeSpan -Days 15) -TimeSpanType Seconds

        Returns the number of seconds in 15 days.
    #>

    [CmdletBinding()]
    [OutputType([System.Int32])]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.TimeSpan]
        $TimeSpan,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Seconds', 'Minutes', 'Hours', 'Days')]
        [System.String]
        $TimeSpanType
    )

    switch ($TimeSpanType)
    {
        'Seconds'
        {
            return $TimeSpan.TotalSeconds -as [System.UInt32]
        }
        'Minutes'
        {
            return $TimeSpan.TotalMinutes -as [System.UInt32]
        }
        'Hours'
        {
            return $TimeSpan.TotalHours -as [System.UInt32]
        }
        'Days'
        {
            return $TimeSpan.TotalDays -as [System.UInt32]
        }
    }
}

function Compare-ResourcePropertyState
{
    <#
    .SYNOPSIS
        This function is used to compare current and desired values for any DSC
        resource, and return a hashtable with the result from the comparison.

    .PARAMETER CurrentValues
        The current values that should be compared to to desired values. Normally
        the values returned from Get-TargetResource.

    .PARAMETER DesiredValues
        The values set in the configuration and is provided in the call to the
        functions *-TargetResource, and that will be compared against current
        values. Normally set to $PSBoundParameters.

    .PARAMETER Properties
        An array of property names, from the keys provided in DesiredValues, that
        will be compared. If this parameter is left out, all the keys in the
        DesiredValues will be compared.

    .PARAMETER IgnoreProperties
        An array of property names, from the keys provided in DesiredValues, that
        will be ignored.
    #>

    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable[]])]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.Collections.Hashtable]
        $CurrentValues,

        [Parameter(Mandatory = $true)]
        [System.Collections.Hashtable]
        $DesiredValues,

        [Parameter()]
        [System.String[]]
        $Properties,

        [Parameter()]
        [System.String[]]
        $IgnoreProperties
    )

    if ($PSBoundParameters.ContainsKey('Properties'))
    {
        # Filter out the parameters (keys) not specified in Properties
        $desiredValuesToRemove = $DesiredValues.Keys |
        Where-Object -FilterScript {
            $_ -notin $Properties
        }

        $desiredValuesToRemove |
        ForEach-Object -Process {
            $DesiredValues.Remove($_)
        }
    }
    else
    {
        <#
            Remove any common parameters that might be part of DesiredValues,
            if it $PSBoundParameters was used to pass the desired values.
        #>
        $commonParametersToRemove = $DesiredValues.Keys |
        Where-Object -FilterScript {
            $_ -in [System.Management.Automation.PSCmdlet]::CommonParameters `
                -or $_ -in [System.Management.Automation.PSCmdlet]::OptionalCommonParameters
        }

        $commonParametersToRemove |
        ForEach-Object -Process {
            $DesiredValues.Remove($_)
        }
    }

    # Remove any properties that should be ignored.
    if ($PSBoundParameters.ContainsKey('IgnoreProperties'))
    {
        $IgnoreProperties |
        ForEach-Object -Process {
            if ($DesiredValues.ContainsKey($_))
            {
                $DesiredValues.Remove($_)
            }
        }
    }

    $compareTargetResourceStateReturnValue = @()
    foreach ($parameterName in $DesiredValues.Keys)
    {
        Write-Debug -Message ($script:localizedData.EvaluatePropertyState -f $parameterName)

        $parameterState = @{
            ParameterName = $parameterName
            Expected      = $DesiredValues.$parameterName
            Actual        = $CurrentValues.$parameterName
        }

        # Check if the parameter is in compliance.
        $isPropertyInDesiredState = Test-DscPropertyState -Values @{
            CurrentValue = $CurrentValues.$parameterName
            DesiredValue = $DesiredValues.$parameterName
        }

        if ($isPropertyInDesiredState)
        {
            Write-Debug -Message ($script:localizedData.PropertyInDesiredState -f $parameterName)

            $parameterState['InDesiredState'] = $true
        }
        else
        {
            Write-Verbose -Message ($script:localizedData.PropertyNotInDesiredState -f
                $parameterName, ($DesiredValues.$parameterName -join ', '), ($CurrentValues.$parameterName -join ', '))

            $parameterState['InDesiredState'] = $false
        }

        $compareTargetResourceStateReturnValue += $parameterState
    }

    return $compareTargetResourceStateReturnValue
}

function Test-DscPropertyState
{
    <#
    .SYNOPSIS
        This function is used to compare the current and the desired value of a
        property.

    .PARAMETER Values
        This is set to a hash table with the current value (the CurrentValue key)
        and desired value (the DesiredValue key).

    .EXAMPLE
        Test-DscPropertyState -Values @{
            CurrentValue = 'John'
            DesiredValue = 'Alice'
        }
    .EXAMPLE
        Test-DscPropertyState -Values @{
            CurrentValue = 1
            DesiredValue = 2
        }
    #>

    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.Collections.Hashtable]
        $Values
    )

    if ($null -eq $Values.CurrentValue -and $null -eq $Values.DesiredValue)
    {
        # Both values are $null so return $true
        $returnValue = $true
    }
    elseif ($null -eq $Values.CurrentValue -or $null -eq $Values.DesiredValue)
    {
        # Either CurrentValue or DesiredValue are $null so return $false
        $returnValue = $false
    }
    elseif ($Values.DesiredValue.GetType().IsArray -or $Values.CurrentValue.GetType().IsArray)
    {
        $compareObjectParameters = @{
            ReferenceObject  = $Values.CurrentValue
            DifferenceObject = $Values.DesiredValue
        }

        $arrayCompare = Compare-Object @compareObjectParameters -SyncWindow 0

        if ($null -ne $arrayCompare)
        {
            Write-Debug -Message $script:localizedData.ArrayDoesNotMatch

            $arrayCompare |
            ForEach-Object -Process {
                Write-Debug -Message ($script:localizedData.ArrayValueThatDoesNotMatch -f
                    $_.InputObject, $_.SideIndicator)
            }

            $returnValue = $false
        }
        else
        {
            $returnValue = $true
        }
    }
    elseif ($Values.CurrentValue -ne $Values.DesiredValue)
    {
        $desiredType = $Values.DesiredValue.GetType()

        $returnValue = $false

        $supportedTypes = @(
            'String'
            'Int16'
            'UInt16'
            'Int32'
            'UInt32'
            'Single'
            'Boolean'
            'DateTime'
        )

        if ($desiredType.Name -notin $supportedTypes)
        {
            Write-Warning -Message ($script:localizedData.UnableToCompareType -f
                $desiredType.Name)
        }
        else
        {
            Write-Debug -Message ($script:localizedData.PropertyValueOfTypeDoesNotMatch -f
                $desiredType.Name, $Values.CurrentValue, $Values.DesiredValue)
        }
    }
    else
    {
        $returnValue = $true
    }

    return $returnValue
}

function New-CimCredentialInstance
{
    <#
    .SYNOPSIS
        This returns a new MSFT_Credential CIM instance credential object to be
        used when returning credential objects from Get-TargetResource.
        This returns a credential object without the password.

    .PARAMETER Credential
        The PSCredential object to return as an MSFT_Credential CIM instance
        credential object.

    .PARAMETER UserName
        The Username to return as an MSFT_Credential CIM instance credential
        object.

    .NOTES
        When returning a PSCredential object from Get-TargetResource, the
        credential object does not contain the username. The object is empty.

        Password UserName PSComputerName
        -------- -------- --------------
                          localhost

        When the MSFT_Credential CIM instance credential object is returned by
        the Get-TargetResource then the credential object contains the values
        provided in the object.

        Password UserName             PSComputerName
        -------- --------             --------------
                 COMPANY\TestAccount  localhost
    #>

    [CmdletBinding()]
    [OutputType([Microsoft.Management.Infrastructure.CimInstance])]
    param
    (
        [Parameter(Mandatory = $true, ParameterSetName = 'Credential')]
        [System.Management.Automation.PSCredential]
        $Credential,

        [Parameter(Mandatory = $true, ParameterSetName = 'Username')]
        [System.String]
        $UserName
    )

    if ($PSCmdlet.ParameterSetName -eq 'Credential')
    {
        $MSFT_UserName = $Credential.UserName
    }
    else
    {
        $MSFT_UserName = $UserName
    }

    $newCimInstanceParameters = @{
        ClassName  = 'MSFT_Credential'
        ClientOnly = $true
        Namespace  = 'root/microsoft/windows/desiredstateconfiguration'
        Property   = @{
            UserName = [System.String] $MSFT_UserName
            Password = [System.String] $null
        }
    }

    return New-CimInstance @newCimInstanceParameters
}

function Assert-Module
{
    <#
    .SYNOPSIS
        Assert if the role specific module is installed or not and optionally
        import it.

    .PARAMETER ModuleName
        The name of the module to assert is installed.

    .PARAMETER ImportModule
        This switch causes the module to be imported if it is installed.
    #>

    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $ModuleName,

        [Parameter()]
        [System.Management.Automation.SwitchParameter]
        $ImportModule
    )

    if (-not (Get-Module -Name $ModuleName -ListAvailable))
    {
        $errorMessage = $script:localizedData.ModuleNotFoundError -f $moduleName
        New-ObjectNotFoundException -Message $errorMessage
    }

    if ($ImportModule)
    {
        Import-Module -Name $ModuleName
    }
}

function Assert-DomainMember
{
    <#
    .SYNOPSIS
        Asserts if the computer is a member of a domain.
    #>

    [CmdletBinding()]
    param ()

    If (-not ((Get-CimInstance -ClassName Win32_ComputerSystem -Verbose:$false).PartOfDomain))
    {
        New-InvalidOperationException -Message $script:localizedData.NotDomainMemberError
    }
}

function Assert-AdfsService
{
    <#
        .SYNOPSIS
            Assert that the ADFS Service exists and is running.

        .DESCRIPTION
            The ADFS service is configured to have a startup type of 'Automatic (Delayed Start)' which
            means that it will be one or two minutes after the server has started before the ADFS service
            will start. Because of this, we need to wait and retry the ADFS service running check if we
            are within a bootup retry window.

        .PARAMETER RetryInterval
            Specified the time in seconds to wait between each check of the service.

        .PARAMETER MaxRetries
            Specifies the maximum number of times to retry before raising an exception.

        .PARAMETER RetryWindow
            Specifies the window in minutes after bootup to retry checking the service.
    #>

    [CmdletBinding()]
    param (
        [Parameter()]
        [Int16]
        $RetryInterval = 30,
        [Parameter()]
        [Int16]
        $MaxRetries = 10,
        [Parameter()]
        [Int16]
        $RetryWindow = 30
    )

    $lastBootUpTime = (Get-CimInstance -ClassName Win32_OperatingSystem -Verbose:$false).LastBootUpTime

    $retryCount = 0
    do
    {
        $upTime = (Get-Date) - $lastBootUpTime
        $insideRetryWindow = $upTime.TotalMinutes -lt $RetryWindow

        try
        {
            # Check ADFS service is running
            $adfsService = Get-Service -Name $script:adfsServiceName
        }
        catch
        {
            New-InvalidOperationException -Message $script:localizedData.GetAdfsServiceError -ErrorRecord $_
        }

        if ($adfsService.Status -ne 'Running' -and $insideRetryWindow)
        {
            $retryCount++
            Write-Verbose -Message ($script:localizedData.WaitingForAdfsServiceMessage -f
                $RetryInterval, $retryCount, $MaxRetries)
            Start-Sleep -Seconds $RetryInterval
        }
    }
    until ($adfsService.Status -eq 'Running' -or $retryCount -ge $MaxRetries -or $insideRetryWindow -eq $false)

    if ($adfsService.Status -ne 'Running')
    {
        New-InvalidOperationException -Message $script:localizedData.AdfsServiceNotRunningError
    }
}

function Assert-Command
{
    <#
        .SYNOPSIS
            Assert that the specified command exists in the specified module.

        .PARAMETER Module
            Specifies the module name.

        .PARAMETER Command
            Specifies the command name.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.String]
        $Command,

        [Parameter(Mandatory = $true)]
        [System.String]
        $Module
    )

    if (!(Get-Command -Name $Command -Module $Module -ErrorAction SilentlyContinue))
    {
        $errorMessage = $script:localizedData.ResourceNotImplementedError -f $Module, $Command
        New-NotImplementedException -Message $errorMessage
    }
}

function Get-ADObjectByQualifiedName
{
    <#
        .SYNOPSIS
            Gets an Active Directory object by qualified name.

        .PARAMETER Name
            Specifies the qualified name to search for.
    #>

    [CmdletBinding()]
    [OutputType([System.DirectoryServices.SearchResult])]
    param (
        [Parameter(Mandatory = $true)]
        [System.String]
        $Name
    )

    $root = [System.DirectoryServices.DirectoryEntry]::new('LDAP://RootDSE')
    $searchRoot = [System.DirectoryServices.DirectoryEntry]::new(
        "LDAP://CN=Partitions," + $root.configurationNamingContext)

    if ($Name -like '*\*')
    {
        # Legacy name format
        $netBiosName = ($Name.Split('\'))[0]
        $samAccountName = ($Name.Split('\'))[1]
        $domain = [System.DirectoryServices.DirectorySearcher]::new(
            $searchRoot, "(&(objectcategory=crossRef)(nETBIOSName=$netBiosName))").FindOne()
        if ($domain)
        {
            $searchResult = [System.DirectoryServices.DirectorySearcher]::new(
                "LDAP://$($domain.Properties.ncname)", "SamAccountName=$samAccountName", 'ObjectCategory').FindOne()
        }
        else
        {
            $errorMessage = $script:localizedData.UnknownNetBiosNameError
            New-InvalidArgumentException -Message $errorMessage -ArgumentName $netBiosName
        }
    }
    elseif ($Name -like '*@*')
    {
        # UPN format
        $searchResult = [System.DirectoryServices.DirectorySearcher]::new(
            "userPrincipalName=$Name", 'ObjectCategory').FindOne()
    }
    else
    {
        $errorMessage = $script:localizedData.UnknownNameFormatError
        New-InvalidArgumentException -Message $errorMessage -ArgumentName $Name
    }

    $searchResult
}

function Assert-GroupServiceAccount
{
    <#
        .SYNOPSIS
            Assert if the service account is a Group Managed Service Account.

        .PARAMETER Name
            Specifies the service account name.
    #>

    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param (
        [Parameter(Mandatory = $true)]
        [System.String]
        $Name
    )

    $adObject = Get-ADObjectbyQualifiedName -Name $Name

    if ($adObject)
    {
        switch -Wildcard ($adObject.Properties.objectcategory)
        {
            'CN=ms-DS-Group-Managed-Service-Account,CN=Schema,CN=Configuration*'
            {
                $isGroupServiceAccount = $true
                break
            }
            'CN=ms-DS-Managed-Service-Account*'
            {
                $isGroupServiceAccount = $false
                break
            }
            'CN=Person,CN=Schema,CN=Configuration*'
            {
                $isGroupServiceAccount = $false
                break
            }
            Default
            {
                $errorMessage = ($script:localizedData.UnexpectedServiceAccountCategoryError -f
                    $adObject.Properties.ObjectCategory, $Name)
                New-InvalidResultException -Message $errorMessage
            }
        }
    }
    else
    {
        $errorMessage = $script:localizedData.ServiceAccountNotFoundError -f $Name
        New-ObjectNotFoundException -Message $errorMessage
    }

    $isGroupServiceAccount
}

function Get-AdfsConfigurationStatus
{
    <#
        .SYNOPSIS
            Get the configuration status of the ADFS Service
    #>

    [CmdletBinding()]
    [OutputType([System.String])]
    param ()

    try
    {
        $fsConfigurationStatus = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\ADFS').FSConfigurationStatus
    }
    catch
    {
        New-InvalidResultException -Message $script:localizedData.ConfigurationStatusNotFoundError
    }

    switch ($fsConfigurationStatus)
    {
        '0'
        {
            $ReturnValue = 'NotConfigured'
        }
        '1'
        {
            $ReturnValue = 'NotConfigured'
        }
        '2'
        {
            $ReturnValue = 'Configured'
        }
        default
        {
            $errorMessage = $script:localizedData.UnknownConfigurationStatusError -f $_
            New-InvalidResultException -Message $errorMessage
        }
    }

    $ReturnValue
}

function Get-ObjectType
{
    <#
        .SYNOPSIS
            Returns the type name of the input object
    #>

    [CmdletBinding()]
    [OutputType([System.String])]
    param (
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [System.Management.Automation.PSObject]
        $Object
    )

    $Object.GetType().FullName
}

function ConvertTo-IssuanceTransformRule
{
    <#
        .SYNOPSIS
            Convert a CIMInstance MSFT_AdfsIssuanceTransformRule object to a Claims Rule string

        .NOTES

            https://blogs.technet.microsoft.com/askds/2011/10/07/ad-fs-2-0-claims-rule-language-primer/

            Example LDAPClaims Transform Claims Rule string:

                @RuleTemplate = "LdapClaims"
                @RuleName = "test"
                c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname", Issuer == "AD AUTHORITY"]
                 => issue(store = "Active Directory", types = ("test", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname"), query = ";test,mail,givenName,sn;{0}", param = c.Value);

            Example EmitGroupClaims Transform Claims Rule string:

                @RuleTemplate = "EmitGroupClaims"
                @RuleName = "IDscan Users SRV EU-West-1"
                c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/groupsid", Value == "S-1-5-21-2624039266-918686060-4041204886-1128", Issuer == "AD AUTHORITY"]
                 => issue(Type = "http://schemas.microsoft.com/ws/2008/06/identity/claims/role", Value = "IDScan User", Issuer = c.Issuer, OriginalIssuer = c.OriginalIssuer, ValueType = c.ValueType);


            IssuanceTransformRules               = @(
                @{
                    TemplateName    = 'LdapClaims'
                    Name            = 'Test'
                    AtttributeStore = 'ActiveDirectory'
                    LdapMapping     = @(
                        @{
                            LdapAttribute     = 'mail'
                            OutgoingClaimType = 'emailaddress'
                        }
                        @{
                            LdapAttribute     = 'givenName'
                            OutgoingCliamType = 'givenname'
                        }
                    )
                }
                @{
                    TemplateName         = 'EmitGroupClaims'
                    Name                 = 'Group Membership'
                    GroupName            = 'Test'
                    OutgoingClaimType    = 'http://schemas.microsoft.com/ws/2008/06/identity/claims/role'
                    OutgoingNameIDFormat = ''
                    OutgoingClaimValue   = 'App1 User'
                }
                @{
                    TemplateName = 'CustomClaims'
                    Name         = 'Test'
                    CustomRule   = ''
                }
            )
    #>

    [CmdletBinding()]
    [OutputType([System.String])]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [AllowEmptyCollection()]
        [AllowNull()]
        [Microsoft.Management.Infrastructure.CimInstance[]]
        $InputObject
    )
    begin
    {
        Write-Debug -Message ($script:LocalizedData.EnteringFunctionDebugMessage -f $MyInvocation.MyCommand)

        $ldapClaimsTransformRule = @(
            '@RuleTemplate = "LdapClaims"'
            '@RuleName = "{1}"'
            'c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname", Issuer == "AD AUTHORITY"]'
            '=> issue(store = "{2}", types = ({3}), query = ";{4};{0}", param = c.Value);'
        ) | Out-String

        $emitGroupClaimsTransformRule = @(
            '@RuleTemplate = "EmitGroupClaims"'
            '@RuleName = "{0}"'
            'c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/groupsid", Value == "{1}", Issuer == "AD AUTHORITY"]'
            '=> issue(Type = "{2}", Value = "{3}", Issuer = c.Issuer, OriginalIssuer = c.OriginalIssuer, ValueType = c.ValueType);'
        ) | Out-String

        $customTransformRule = @(
            '@RuleName = "{0}"'
            '{1}'
        ) | Out-String

        $output = ''
    }
    process
    {
        foreach ($rule in $InputObject)
        {
            if ($rule.TemplateName -eq 'LdapClaims')
            {
                Write-Debug -Message ($script:LocalizedData.ProcessingPropertyDebugMessage -f
                    'LdapClaims Template Rule')

                $claimTypes = '"' + ($rule.LdapMapping.OutGoingClaimType -join '", "') + '"'
                $ldapAttributes = $rule.LdapMapping.LdapAttribute -join ','
                $output += ($ldapClaimsTransformRule -f '{0}', $rule.Name, $rule.AttributeStore,
                    $claimTypes, $ldapAttributes)
            }
            elseif ($rule.TemplateName -eq 'EmitGroupClaims')
            {
                Write-Debug -Message ($script:LocalizedData.ProcessingPropertyDebugMessage -f
                    'EmitGroupClaims Template Rule')

                $groupSid = Get-AdGroupSid -GroupName $rule.GroupName
                $output += ($emitGroupClaimsTransformRule -f $rule.Name, $groupSid, $rule.OutgoingClaimType,
                    $rule.OutgoingClaimValue)
            }
            elseif ($rule.TemplateName -eq 'CustomClaims')
            {
                Write-Debug -Message ($script:LocalizedData.ProcessingPropertyDebugMessage -f
                    'CustomClaims Template Rule')

                $output += $customTransformRule -f $rule.Name, $rule.CustomRule
            }
            else
            {
                $errorMessage = $script:localizedData.UnknownIssuanceTransformRuleTemplateError -f $rule.TemplateName
                New-InvalidOperationException -Message $errorMessage
            }
        }
    }
    end
    {
        return $output
    }
}

function ConvertFrom-IssuanceTransformRule
{
    <#
        .SYNOPSIS
            Convert a Claims Rule string to a CIMInstance MSFT_AdfsIssuanceTransformRule object

        .NOTES

            IssuanceTransformRules = @(
            MSFT_AdfsIssuanceTransformRule
            {
                TemplateName    = 'LdapClaims'
                Name            = 'Test'
                AtttributeStore = 'ActiveDirectory'
                LdapMapping     = @(
                    MSFT_AdfsLdapMapping
                    {
                        LdapAttribute     = 'emailaddress'
                        OutgoingClaimType = 'mail'
                    }
                )
            }
    #>

    [CmdletBinding()]
    [OutputType([Microsoft.Management.Infrastructure.CimInstance[]])]
    param
    (
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [System.String[]]
        $Rule
    )

    Write-Debug -Message ($script:LocalizedData.EnteringFunctionDebugMessage -f $MyInvocation.MyCommand)

    $ruleLines = $Rule -split '\r?\n'
    $individualRules = [System.Collections.ArrayList]@()
    $individualRule = @()
    foreach ($ruleLine in $ruleLines)
    {
        if ($ruleLine -eq '')
        {
            if ($individualRule)
            {
                $individualRules.Add($individualRule) | Out-Null
                $individualRule = @()
            }
        }
        else
        {
            $individualRule += $ruleLine
        }
    }

    $MSFTAdfsIssuanceTransformRule = @()
    if ($individualRules)
    {
        foreach ($individualRule in $individualRules)
        {
            if ($individualRule[0] -eq '@RuleTemplate = "LdapClaims"')
            {
                Write-Debug -Message ($script:LocalizedData.ProcessingPropertyDebugMessage -f
                    'LdapClaims Template Rule')

                $outgoingClaimTypes = @(($individualRule[3].Split('(').Split(')')[2]).Split(',').Trim().Trim('"'))
                $ldapAttributes = @(($individualRule[3].Split(';')[1]).Split(','))

                $MSFTAdfsLdapMapping = @()
                for ($index = 0; $index -lt $ldapAttributes.Count; $index++)
                {
                    $ldapMapping = @{
                        LdapAttribute     = $ldapAttributes[$index]
                        OutgoingClaimType = $outgoingClaimTypes[$index]
                    }
                    $MSFTAdfsLdapMapping += New-CimInstance -ClassName MSFT_AdfsLdapMapping `
                        -Namespace root/microsoft/Windows/DesiredStateConfiguration `
                        -Property $ldapMapping -ClientOnly
                }
                $issuanceTransformRule = @{
                    TemplateName   = 'LdapClaims'
                    Name           = $individualRule[1].split('"')[1]
                    AttributeStore = $individualRule[3].split('"')[1]
                    LdapMapping    = [CimInstance[]]$MSFTAdfsLdapMapping
                }
            }
            elseif ($individualRule[0] -eq '@RuleTemplate = "EmitGroupClaims"')
            {
                Write-Debug -Message ($script:LocalizedData.ProcessingPropertyDebugMessage -f
                    'EmitGroupClaims Template Rule')

                $groupSid = $individualRule[2].Split('"')[3]
                $issuanceTransformRule = @{
                    TemplateName       = 'EmitGroupClaims'
                    Name               = $individualRule[1].split('"')[1]
                    GroupName          = Get-AdGroupNameFromSid -Sid $groupSid
                    OutgoingClaimType  = $individualRule[3].split('"')[1]
                    OutgoingClaimValue = $individualRule[3].split('"')[3]
                }
            }
            else
            {
                Write-Debug -Message ($script:LocalizedData.ProcessingPropertyDebugMessage -f
                    'CustomClaims Template Rule')

                $issuanceTransformRule = @{
                    TemplateName = 'CustomClaims'
                    Name         = $individualRule[0].split('"')[1]
                    CustomRule   = $individualRule[1..($individualRule.count)] | Out-String
                }
            }

            $MSFTAdfsIssuanceTransformRule += New-CimInstance -ClassName MSFT_AdfsIssuanceTransformRule `
                -Namespace root/microsoft/Windows/DesiredStateConfiguration `
                -Property $issuanceTransformRule -ClientOnly
        }

        return $MSFTAdfsIssuanceTransformRule
    }
}

function Compare-IssuanceTransformRule
{
    <#
        .SYNOPSIS
            Compare two Issuance Transform Rules
    #>

    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param
    (
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [Microsoft.Management.Infrastructure.CimInstance[]]
        $CurrentValue,

        [Parameter(Mandatory = $true)]
        [Microsoft.Management.Infrastructure.CimInstance[]]
        $DesiredValue,

        [Parameter(Mandatory = $true)]
        [System.String]
        $ParameterName
    )

    Write-Debug -Message ($script:LocalizedData.EnteringFunctionDebugMessage -f $MyInvocation.MyCommand)

    $parameterState = @{
        ParameterName  = $ParameterName
        Expected       = $DesiredValue
        Actual         = $CurrentValue
        InDesiredState = $true
    }

    if ([System.String]::IsNullOrEmpty($CurrentValue) -or $CurrentValue.Count -ne $DesiredValue.Count)
    {
        $parameterState.InDesiredState = $false
    }
    else
    {
        for ($index = 0; $index -lt $DesiredValue.Count; $index++)
        {
            if ($DesiredValue[$index].TemplateName -eq $CurrentValue[$index].TemplateName)
            {
                if ($DesiredValue[$index].TemplateName -eq 'LdapClaims')
                {
                    Write-Debug -Message ($script:LocalizedData.ComparingPropertiesWithNameDebugMessage -f
                        'LdapClaims', $CurrentValue[$index].Name)

                    if (Compare-Object -ReferenceObject $CurrentValue[$index] -DifferenceObject $DesiredValue[$index] `
                            -Property $CurrentValue[$index].CimInstanceProperties.Name)
                    {
                        $parameterState.InDesiredState = $false
                        break
                    }

                    if (Compare-Object -ReferenceObject $CurrentValue[$index].LdapMapping `
                            -DifferenceObject $DesiredValue[$index].LdapMapping `
                            -Property $CurrentValue[$index].LdapMapping.CimInstanceProperties.Name)
                    {
                        $parameterState.InDesiredState = $false
                        break
                    }

                }
                elseif ($DesiredValue[$index].TemplateName -eq 'EmitGroupClaims')
                {
                    Write-Debug -Message ($script:LocalizedData.ComparingPropertiesWithNameDebugMessage -f
                        'EmitGroupClaims', $CurrentValue[$index].Name)

                    if (Compare-Object -ReferenceObject $CurrentValue[$index] -DifferenceObject $DesiredValue[$index] `
                            -Property $CurrentValue[$index].CimInstanceProperties.Name)
                    {
                        $parameterState.InDesiredState = $false
                        break
                    }
                }
                elseif ($DesiredValue[$index].TemplateName -eq 'CustomClaims')
                {
                    Write-Debug -Message ($script:LocalizedData.ComparingPropertiesWithNameDebugMessage -f
                        'CustomClaims', $CurrentValue[$index].Name)

                    $CurrentCustomRule = ($CurrentValue[$index].CustomRule -split '\r?\n' | Out-String).Trim()
                    $DesiredCustomRule = ($DesiredValue[$index].CustomRule -split '\r?\n' | Out-String).Trim()
                    if ($CurrentCustomRule -ne $DesiredCustomRule -or
                        $CurrentValue[$index].Name -ne $DesiredValue[$index].Name)
                    {
                        $parameterState.InDesiredState = $false
                        break
                    }
                }
                else
                {
                    $errorMessage = ($script:LocalizedData.UnknownIssuanceTransformRuleTemplateError -f
                        $DesiredValue[$index].TemplateName)
                    New-InvalidOperationException -Message $errorMessage
                }
            }
            else
            {
                $parameterState.InDesiredState = $false
                break
            }
        }
    }

    return $parameterState
}

function ConvertTo-AccessControlPolicyParameter
{
    <#
    .SYNOPSIS
        Converts a CIMInstance MSFT_AdfsAccessControlPolicyParameter object to an AccessControlPolicyParameter
        Hashtable
    #>

    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [AllowEmptyCollection()]
        [AllowNull()]
        [Microsoft.Management.Infrastructure.CimInstance]
        $InputObject
    )
    begin
    {
        Write-Debug -Message ($script:LocalizedData.EnteringFunctionDebugMessage -f $MyInvocation.MyCommand)
    }
    process
    {
        $accessControlPolicyParameter = @{ }
        foreach ($property in $InputObject.CIMInstanceProperties.Name)
        {
            switch ($property)
            {
                'GroupParameter'
                {
                    Write-Debug -Message ($script:LocalizedData.ProcessingPropertyWithValueDebugMessage -f
                        $property, ($InputObject.GroupParameter -join ', '))

                    $accessControlPolicyParameter += @{
                        GroupParameter = $InputObject.GroupParameter
                    }
                    break
                }
            }
        }

        return $accessControlPolicyParameter
    }
}

function ConvertFrom-AccessControlPolicyParameter
{
    <#
        .SYNOPSIS
            Converts an AccessControlPolicyParameter Hashtable to a CIMInstance
            MSFT_AdfsAccessControlPolicyParameter object

        .NOTES

        AccessControlPolicyParameters = MSFT_AdfsAccessControlPolicyParameter
            @{
                GroupParameter = @(
                    'CONTOSO\AppGroup1 Users'
                    'CONTOSO\AppGroup1 Admins'
                )
            }
    #>

    [CmdletBinding()]
    [OutputType([Microsoft.Management.Infrastructure.CimInstance])]
    param
    (
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [System.Collections.Hashtable]
        $Policy
    )

    Write-Debug -Message ($script:LocalizedData.EnteringFunctionDebugMessage -f $MyInvocation.MyCommand)

    if ($Policy)
    {
        $policyParameter = @{ }

        foreach ($parameter in $Policy.GetEnumerator().Name)
        {
            Write-Debug -Message ($script:LocalizedData.ProcessingPropertyDebugMessage -f "$parameter Parameter")

            switch -WildCard ($parameter)
            {
                'GroupParameter*'
                {
                    Write-Debug -Message ($script:LocalizedData.ProcessingPropertyWithValueDebugMessage -f
                        $parameter, ($Policy.$parameter -join ', '))

                    $GroupParameter = @()
                    foreach ($parameter in $Policy.$parameter)
                    {
                        $groupParameter += $parameter
                    }

                    $policyParameter += @{
                        GroupParameter = $groupParameter
                    }
                }
            }
        }

        $MSFTAdfsAccessControlPolicyParameter = New-CimInstance -ClassName MSFT_AdfsAccessControlPolicyParameters `
            -Namespace root/microsoft/Windows/DesiredStateConfiguration `
            -Property $policyParameter -ClientOnly
    }
    else
    {
        $MSFTAdfsAccessControlPolicyParameter = $null
    }
    return $MSFTAdfsAccessControlPolicyParameter
}

function Compare-AccessControlPolicyParameter
{
    <#
        .SYNOPSIS
            Compare two access control policy parameters
    #>

    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param
    (
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [Microsoft.Management.Infrastructure.CimInstance]
        $CurrentValue,

        [Parameter(Mandatory = $true)]
        [Microsoft.Management.Infrastructure.CimInstance]

        $DesiredValue,

        [Parameter(Mandatory = $true)]
        [System.String]
        $ParameterName
    )

    Write-Debug -Message ($script:LocalizedData.EnteringFunctionDebugMessage -f $MyInvocation.MyCommand)

    $parameterState = @{
        ParameterName  = $ParameterName
        Expected       = $DesiredValue
        Actual         = $CurrentValue
        InDesiredState = $true
    }

    if ([System.String]::IsNullOrEmpty($CurrentValue))
    {
        $parameterState.InDesiredState = $false
    }
    else
    {
        if (Compare-Object -ReferenceObject $CurrentValue.CimInstanceProperties.Name `
                -DifferenceObject $DesiredValue.CimInstanceProperties.Name)
        {
            Write-Verbose -Message ($script:localizedData.PolicyParameterNotInDesiredState -f
                $DesiredValue.CimInstanceProperties.Name, $CurrentValue.CimInstanceProperties.Name)

            $parameterState.InDesiredState = $false
        }
        else
        {
            foreach ($property in $CurrentValue.CimInstanceProperties.Name)
            {
                Write-Debug -Message ($script:LocalizedData.ComparingPropertiesWithValueDebugMessage -f
                    $property, $CurrentValue.$property, $DesiredValue.$property)

                if (Compare-Object -ReferenceObject $CurrentValue.$property -DifferenceObject $DesiredValue.$property)
                {
                    Write-Verbose -Message ($script:localizedData.PropertyNotInDesiredState -f
                        $property, ($DesiredValue.$property -join ', '), ($CurrentValue.$property -join ', '))

                    $parameterState.InDesiredState = $false
                    break
                }
            }
        }
    }

    return $parameterState
}

function Get-AdGroupNameFromSid
{
    <#
        .SYNOPSIS
            Get an Active Directory group name from a SID
    #>

    [CmdletBinding()]
    [OutputType([System.String])]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $Sid
    )


    $groupObject = ([System.DirectoryServices.DirectorySearcher]"(&(objectClass=group)(objectSid=$sid))").FindOne()

    if ($groupObject)
    {
        return $groupObject.GetDirectoryEntry().Name
    }
    else
    {
        $errorMessage = $script:localizedData.ActiveDirectoryGroupNotFoundFromSidError -f $Sid
        New-ObjectNotFoundException -Message $errorMessage
    }
}

function Get-AdGroupSid
{
    <#
        .SYNOPSIS
            Get the SID of an Active Directory group
    #>

    [CmdletBinding()]
    [OutputType([System.String])]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $GroupName
    )

    $adGroup = ([System.DirectoryServices.DirectorySearcher]"(&(objectClass=group)(name=$GroupName))").FindOne()

    if ($adGroup)
    {
        $binarySid = $adGroup.GetDirectoryEntry().ObjectSid.Value
        $stringSid = ([System.Security.Principal.SecurityIdentifier]::new($binarysid, 0)).Value

        return $stringSid
    }
    else
    {
        $errorMessage = $script:localizedData.ActiveDirectoryGroupNotFoundError -f $GroupName
        New-ObjectNotFoundException -Message $errorMessage
    }
}

function ConvertTo-SamlEndpoint
{
    <#
    .SYNOPSIS
        Converts a CIMInstance MSFT_AdfsSamlEndpoint object to an array of
        Microsoft.IdentityServer.Management.Resources.SamlEndpoint objects.
    #>

    [CmdletBinding()]
    [OutputType([Microsoft.IdentityServer.Management.Resources.SamlEndpoint[]])]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [AllowEmptyCollection()]
        [AllowNull()]
        [Microsoft.Management.Infrastructure.CimInstance[]]
        $InputObject
    )
    begin
    {
        Write-Debug -Message ($script:LocalizedData.EnteringFunctionDebugMessage -f $MyInvocation.MyCommand)

        $samlEndpoint = @()
    }
    process
    {
        foreach ($endpoint in $InputObject)
        {
            $newAdfsSamlEndpointParms = @{
                Binding  = $endpoint.Binding
                Protocol = $endpoint.Protocol
                Uri      = $endpoint.Uri
            }

            if ($endpoint.CimInstanceProperties.Name -contains 'IsDefault')
            {
                $newAdfsSamlEndpointParms += @{
                    ISDefault = $endpoint.IsDefault
                }
            }

            if ($endpoint.CimInstanceProperties.Name -contains 'Index')
            {
                $newAdfsSamlEndpointParms += @{
                    Index = $endpoint.Index
                }
            }

            if ($endpoint.CimInstanceProperties.Name -contains 'ResponseUri')
            {
                $newAdfsSamlEndpointParms += @{
                    ResponseUri = $endpoint.ResponseUri
                }
            }

            $samlEndpoint += New-AdfsSamlEndpoint @newAdfsSamlEndpointParms
        }
    }
    end
    {
        return $samlEndpoint
    }
}

function ConvertFrom-SamlEndpoint
{
    <#
        .SYNOPSIS
            Converts an array of Microsoft.IdentityServer.Management.Resources.SamlEndpoint objects to an array of
            CIMInstance MSFT_AdfsSamlEndpoint objects.
    #>

    [CmdletBinding()]
    [OutputType([Microsoft.Management.Infrastructure.CimInstance[]])]
    param
    (
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [AllowEmptyCollection()]
        [Microsoft.IdentityServer.Management.Resources.SamlEndpoint[]]
        $SamlEndpoint
    )

    Write-Debug -Message ($script:LocalizedData.EnteringFunctionDebugMessage -f $MyInvocation.MyCommand)

    $MSFTAdfsSamlEndpoint = @()

    foreach ($endpoint in $SamlEndpoint)
    {
        if ($endpoint.ResponseLocation)
        {
            $ResponseUri = $endpoint.ResponseLocation.OriginalString
        }
        else
        {
            $ResponseUri = ''
        }

        $mSFTAdfsSamlEndpointProperties = @{
            Binding     = $endpoint.Binding
            Protocol    = $endpoint.Protocol
            Uri         = $endpoint.Location.OriginalString
            IsDefault   = $endpoint.IsDefault
            Index       = $endpoint.Index
            ResponseUri = $ResponseUri
        }

        $MSFTADfsSamlEndpoint += New-CimInstance -ClassName MSFT_AdfsSamlEndpoint `
            -Namespace root/microsoft/Windows/DesiredStateConfiguration `
            -Property $mSFTAdfsSamlEndpointProperties -ClientOnly
    }

    return $MSFTAdfsSamlEndpoint
}

function Compare-SamlEndpoint
{
    <#
        .SYNOPSIS
            Compare two CIMInstance MSFT_AdfsSamlEndpoint object arrays
    #>

    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param
    (
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [Microsoft.Management.Infrastructure.CimInstance[]]
        $CurrentValue,

        [Parameter(Mandatory = $true)]
        [Microsoft.Management.Infrastructure.CimInstance[]]
        $DesiredValue,

        [Parameter(Mandatory = $true)]
        [System.String]
        $ParameterName
    )

    Write-Debug -Message ($script:LocalizedData.EnteringFunctionDebugMessage -f $MyInvocation.MyCommand)

    $parameterState = @{
        ParameterName  = $ParameterName
        Expected       = $DesiredValue
        Actual         = $CurrentValue
        InDesiredState = $true
    }

    if ([System.String]::IsNullOrEmpty($CurrentValue) -or $CurrentValue.Count -ne $DesiredValue.Count)
    {
        $parameterState.InDesiredState = $false
    }
    else
    {
        $samlEndpointProperties = 'Binding', 'Protocol', 'Uri', 'IsDefault', 'Index', 'ResponseUri'

        for ($index = 0; $index -lt $DesiredValue.Count; $index++)
        {
            if ($null -eq $DesiredValue[$index].ResponseUri)
            {
                $DesiredValue[$index].ResponseUri = ''
            }

            if (Compare-Object -ReferenceObject $CurrentValue[$index] -DifferenceObject $DesiredValue[$index] `
                    -Property $samlEndpointProperties -Debug:$false)
            {
                $parameterState.InDesiredState = $false
                break
            }
        }
    }

    Write-Debug -Message "Returning parameter state InDesiredState $($parameterState.InDesiredState)"

    return $parameterState
}

$script:localizedData = Get-LocalizedData -ResourceName 'AdfsDsc.Common' -ScriptRoot $PSScriptRoot
$script:adfsServiceName = 'adfssrv'

Export-ModuleMember -Function @(
    'Get-LocalizedData'
    'New-InvalidArgumentException'
    'New-InvalidOperationException'
    'New-ObjectNotFoundException'
    'New-InvalidResultException'
    'New-NotImplementedException'
    'ConvertTo-TimeSpan'
    'ConvertFrom-TimeSpan'
    'Compare-ResourcePropertyState'
    'New-CimCredentialInstance'
    'Assert-Module'
    'Assert-DomainMember'
    'Assert-AdfsService'
    'Assert-Command'
    'Assert-GroupServiceAccount'
    'Get-AdfsConfigurationStatus'
    'Get-ObjectType'
    'ConvertTo-IssuanceTransformRule'
    'ConvertFrom-IssuanceTransformRule'
    'Compare-IssuanceTransformRule'
    'ConvertFrom-AccessControlPolicyParameter'
    'ConvertTo-AccessControlPolicyParameter'
    'Compare-AccessControlPolicyParameter'
    'ConvertFrom-SamlEndpoint'
    'ConvertTo-SamlEndpoint'
    'Compare-SamlEndpoint'
)
