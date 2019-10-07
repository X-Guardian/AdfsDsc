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

    $argumentException = New-Object -TypeName 'ArgumentException' `
        -ArgumentList @($Message, $ArgumentName)

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
        $exception = New-Object -TypeName 'System.Exception' `
            -ArgumentList @($Message)
    }
    else
    {
        $exception = New-Object -TypeName 'System.Exception' `
            -ArgumentList @($Message, $ErrorRecord.Exception)
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
        $exception = New-Object -TypeName 'System.Exception' `
            -ArgumentList @($Message)
    }
    else
    {
        $exception = New-Object -TypeName 'System.Exception' `
            -ArgumentList @($Message, $ErrorRecord.Exception)
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
        Write-Verbose -Message ($script:localizedData.EvaluatePropertyState -f $parameterName)

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
            Write-Verbose -Message ($script:localizedData.PropertyInDesiredState -f $parameterName)

            $parameterState['InDesiredState'] = $true
        }
        else
        {
            Write-Verbose -Message ($script:localizedData.PropertyNotInDesiredState -f $parameterName)

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
            Write-Verbose -Message $script:localizedData.ArrayDoesNotMatch -Verbose:$VerbosePreference

            $arrayCompare |
                ForEach-Object -Process {
                    Write-Verbose -Message ($script:localizedData.ArrayValueThatDoesNotMatch -f `
                            $_.InputObject, $_.SideIndicator) -Verbose:$VerbosePreference
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
            'Int32'
            'UInt32'
            'Int16'
            'UInt16'
            'Single'
            'Boolean'
            'DateTime'
        )

        if ($desiredType.Name -notin $supportedTypes)
        {
            Write-Warning -Message ($script:localizedData.UnableToCompareType `
                    -f $fieldName, $desiredType.Name)
        }
        else
        {
            Write-Verbose -Message (
                $script:localizedData.PropertyValueOfTypeDoesNotMatch `
                    -f $desiredType.Name, $Values.CurrentValue, $Values.DesiredValue
            ) -Verbose:$VerbosePreference
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
    param()

    if (-not ((Get-CimInstance -ClassName Win32_ComputerSystem -Verbose:$false).PartOfDomain))
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
            Write-Verbose -Message ($script:localizedData.WaitingForAdfsServiceMessage -f `
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
        $Module,

        [Parameter(Mandatory = $true)]
        [System.String]
        $Command
    )

    if (!(Get-Command $Command -Module $Module -ErrorAction SilentlyContinue))
    {
        New-NotImplementedException -Message (
            $script:localizedData.ResourceNotImplementedError -f $Module, $Command)
    }
}

function Assert-GroupServiceAccount
{
    <#
        .SYNOPSIS
            Assert if the service account is a Group Managed Service Account

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

    $adObject = [System.DirectoryServices.DirectorySearcher]::new($null, "SamAccountName=$Name*", `
            'ObjectCategory').FindOne()

    if ($adObject)
    {
        switch -Wildcard ($adObject.Properties.objectcategory)
        {
            'CN=ms-DS-Group-Managed-Service-Account,CN=Schema,CN=Configuration*'
            {
                $isGroupServiceAccount = $true
                Break
            }
            'CN=Person,CN=Schema,CN=Configuration*'
            {
                $isGroupServiceAccount = $false
                Break
            }
            Default
            {
                New-InvalidResultException -Message ( `
                        $script:localizedData.UnexpectedServiceAccountCategoryError -f `
                        $adObject.Properties.ObjectCategory, $Name)
            }
        }
    }
    else
    {
        New-ObjectNotFoundException -Message ( `
                $script:localizedData.ServiceAccountNotFoundError -f $UserName)
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
        { $ReturnValue = 'NotConfigured'
        }
        '1'
        { $ReturnValue = 'NotConfigured'
        }
        '2'
        { $ReturnValue = 'Configured'
        }
        default
        {
            New-InvalidResultException -Message ($script:localizedData.UnknownConfigurationStatusError -f $_)
        }
    }

    $ReturnValue
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
)
