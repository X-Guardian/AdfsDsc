<#
    .SYNOPSIS
        DSC module for the Web API Application resource

    .DESCRIPTION
        The AdfsWebApiApplication DSC resource manages Web API Applications within Active Directory Federation
        Services. Web Api Applications are a construct that represents a web API secured by ADFS.

        ## Requirements

        * Target machine must be running ADFS on Windows Server 2016 or above to use this resource.

    .PARAMETER Name
        Key - String
        Specifies a name for the Web API application.

    .PARAMETER ApplicationGroupIdentifier
        Required - String
        Specifies the ID of an application group for the Web API application.

    .PARAMETER Identifier
        Required - String
        Specifies an identifier for the Web API application.

    .PARAMETER Description
        Write - String
        Specifies a description for the Web API application.

    .PARAMETER Ensure
        Write - String
        Allowed values: Present, Absent
        Specifies whether the Web API application should be present or absent. Default value is 'Present'.

    .PARAMETER AllowedAuthenticationClassReferences
        Write - String
        Specifies an array of allow authentication class references.

    .PARAMETER ClaimsProviderName
        Write - String
        Specifies an array of claims provider names that you can configure for a relying party trust for Home Realm
        Discovery (HRD) scenario.

    .PARAMETER IssuanceAuthorizationRules
        Write - String
        Specifies the issuance authorization rules.

    .PARAMETER DelegationAuthorizationRules
        Write - String
        Specifies delegation authorization rules.

    .PARAMETER ImpersonationAuthorizationRules
        Write - String
        Specifies the impersonation authorization rules.

    .PARAMETER IssuanceTransformRules
        Write - String
        Specifies the issuance transform rules.

    .PARAMETER AdditionalAuthenticationRules
        Write - String
        Specifies additional authentication rules.

    .PARAMETER AccessControlPolicyName
        Write - String
        Specifies the name of an access control policy.

    .PARAMETER NotBeforeSkew
        Write - Sint32
        Specifies the not before skew value.

    .PARAMETER TokenLifetime
        Write - Sint32
        Specifies the token lifetime.

    .PARAMETER AlwaysRequireAuthentication
        Write - Boolean
        Indicates that this Web API application role always requires authentication, even if it previously
        authenticated credentials for access. Specify this parameter to require users to always supply credentials to
        access sensitive resources.

    .PARAMETER AllowedClientTypes
        Write - String
        Allowed values: None, Public, Confidential
        Specifies allowed client types.

    .PARAMETER IssueOAuthRefreshTokensTo
        Write - String
        Allowed values: NoDevice, WorkplaceJoinedDevices, AllDevices
        Specifies the refresh token issuance device types.

    .PARAMETER RefreshTokenProtectionEnabled
        Write - Boolean
        Indicates whether refresh token protection is enabled.

    .PARAMETER RequestMFAFromClaimsProviders
        Write - Boolean
        Indicates that the request MFA from claims providers option is used.
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
        - Get-AdfsWebApiApplication - https://docs.microsoft.com/en-us/powershell/module/adfs/get-adfswebApiapplication
    #>

    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $Name,

        [Parameter(Mandatory = $true)]
        [System.String]
        $ApplicationGroupIdentifier,

        [Parameter(Mandatory = $true)]
        [System.String[]]
        $Identifier
    )

    # Check of the Resource PowerShell module is installed
    Assert-Module -ModuleName $script:psModuleName

    # Check if the Get-AdfsWebApiApplication command is available
    Assert-Command -Module $script:psModuleName -Command 'Get-AdfsWebApiApplication'

    # Check if the ADFS Service is present and running
    Assert-AdfsService -Verbose

    Write-Verbose -Message ($script:localizedData.GettingResourceMessage -f $Name)

    $targetResource = Get-AdfsWebApiApplication -Name $Name

    if ($targetResource)
    {
        # Resource exists
        Write-Debug "Target resource $Name exists"
        $returnValue = @{
            Name                                 = $targetResource.Name
            ApplicationGroupIdentifier           = $targetResource.ApplicationGroupIdentifier
            Identifier                           = @($targetResource.Identifier)
            Description                          = $targetResource.Description
            AllowedAuthenticationClassReferences = @($targetResource.AllowedAuthenticationClassReferences)
            ClaimsProviderName                   = @($targetResource.ClaimsProviderName)
            IssuanceAuthorizationRules           = $targetResource.IssuanceAuthorizationRules
            DelegationAuthorizationRules         = $targetResource.DelegationAuthorizationRules
            ImpersonationAuthorizationRules      = $targetResource.ImpersonationAuthorizationRules
            IssuanceTransformRules               = @(ConvertFrom-IssuanceTransformRule -Rule $targetResource.IssuanceTransformRules)
            AdditionalAuthenticationRules        = $targetResource.AdditionalAuthenticationRules
            AccessControlPolicyName              = $targetResource.AccessControlPolicyName
            NotBeforeSkew                        = $targetResource.NotBeforeSkew
            TokenLifetime                        = $targetResource.TokenLifetime
            AlwaysRequireAuthentication          = $targetResource.AlwaysRequireAuthentication
            AllowedClientTypes                   = $targetResource.AllowedClientTypes
            IssueOAuthRefreshTokensTo            = $targetResource.IssueOAuthRefreshTokensTo
            RefreshTokenProtectionEnabled        = $targetResource.RefreshTokenProtectionEnabled
            RequestMFAFromClaimsProviders        = $targetResource.RequestMFAFromClaimsProviders
            Ensure                               = 'Present'
        }
    }
    else
    {
        # Resource does not exist
        Write-Debug "Target resource $Name does not exist"
        $returnValue = @{
            Name                                 = $Name
            ApplicationGroupIdentifier           = $ApplicationGroupIdentifier
            Identifier                           = @($Identifier)
            Description                          = $null
            AllowedAuthenticationClassReferences = @()
            ClaimsProviderName                   = @()
            IssuanceAuthorizationRules           = $null
            DelegationAuthorizationRules         = $null
            ImpersonationAuthorizationRules      = $null
            IssuanceTransformRules               = @()
            AdditionalAuthenticationRules        = $null
            AccessControlPolicyName              = $null
            NotBeforeSkew                        = 0
            TokenLifetime                        = 0
            AlwaysRequireAuthentication          = $null
            AllowedClientTypes                   = 'None'
            IssueOAuthRefreshTokensTo            = 'NoDevice'
            RefreshTokenProtectionEnabled        = $false
            RequestMFAFromClaimsProviders        = $false
            Ensure                               = 'Absent'
        }
    }

    Write-Debug "Returning Value"
    $returnValue
}


function Set-TargetResource
{
    <#
    .SYNOPSIS
        Set-TargetResource

    .NOTES
        Used Resource PowerShell Cmdlets:
        - Add-AdfsWebApiApplication    - https://docs.microsoft.com/en-us/powershell/module/adfs/add-adfswebApiapplication
        - Remove-AdfsWebApiApplication - https://docs.microsoft.com/en-us/powershell/module/adfs/remove-adfswebApiapplication
        - Set-AdfsWebApiApplication    - https://docs.microsoft.com/en-us/powershell/module/adfs/set-adfswebApiapplication
    #>

    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $Name,

        [Parameter(Mandatory = $true)]
        [System.String]
        $ApplicationGroupIdentifier,

        [Parameter(Mandatory = $true)]
        [System.String[]]
        $Identifier,

        [Parameter()]
        [System.String]
        $Description,

        [Parameter()]
        [ValidateSet('Present', 'Absent')]
        [System.String]
        $Ensure = 'Present',

        [Parameter()]
        [System.String[]]
        $AllowedAuthenticationClassReferences,

        [Parameter()]
        [System.String[]]
        $ClaimsProviderName,

        [Parameter()]
        [System.String]
        $IssuanceAuthorizationRules,

        [Parameter()]
        [System.String]
        $DelegationAuthorizationRules,

        [Parameter()]
        [System.String]
        $ImpersonationAuthorizationRules,

        [Parameter()]
        [Microsoft.Management.Infrastructure.CimInstance[]]
        $IssuanceTransformRules,

        [Parameter()]
        [System.String]
        $AdditionalAuthenticationRules,

        [Parameter()]
        [System.String]
        $AccessControlPolicyName,

        [Parameter()]
        [System.Int32]
        $NotBeforeSkew,

        [Parameter()]
        [System.Int32]
        $TokenLifetime,

        [Parameter()]
        [System.Boolean]
        $AlwaysRequireAuthentication,

        [Parameter()]
        [ValidateSet('None', 'Public', 'Confidential')]
        [System.String]
        $AllowedClientTypes,

        [Parameter()]
        [ValidateSet('NoDevice', 'WorkplaceJoinedDevices', 'AllDevices')]
        [System.String]
        $IssueOAuthRefreshTokensTo,

        [Parameter()]
        [System.Boolean]
        $RefreshTokenProtectionEnabled,

        [Parameter()]
        [System.Boolean]
        $RequestMFAFromClaimsProviders
    )

    # Remove any parameters not used in Splats
    [HashTable]$parameters = $PSBoundParameters
    $parameters.Remove('Ensure')
    $parameters.Remove('Verbose')

    $GetTargetResourceParms = @{
        ApplicationGroupIdentifier = $ApplicationGroupIdentifier
        Name                       = $Name
        Identifier                 = $Identifier
    }
    $targetResource = Get-TargetResource @GetTargetResourceParms

    if ($Ensure -eq 'Present')
    {
        # Resource should exist
        $parameters.IssuanceTransformRules = $IssuanceTransformRules | ConvertTo-IssuanceTransformRule
        write-verbose $parameters.IssuanceTransformRules

        if ($TargetResource.Ensure -eq 'Present')
        {
            # Resource exists
            $propertiesNotInDesiredState = (
                Compare-ResourcePropertyState -CurrentValues $targetResource -DesiredValues $parameters |
                    Where-Object -Property InDesiredState -eq $false)

            if ($propertiesNotInDesiredState |
                    Where-Object -Property ParameterName -eq 'ApplicationGroupIdentifier')
            {
                Write-Verbose -Message ($script:localizedData.RemovingResourceMessage -f
                    $Name, $targetResource.ApplicationGroupIdentifier)
                Remove-AdfsWebApiApplication -TargetName $Name
                Write-Verbose -Message ($script:localizedData.AddingResourceMessage -f
                    $Name, $ApplicationGroupIdentifier)
                Add-AdfsWebApiApplication @parameters -Verbose:$false
                break
            }
            $setParameters = @{ }
            foreach ($property in $propertiesNotInDesiredState)
            {
                Write-Verbose -Message ($script:localizedData.SettingResourceMessage -f
                    $Name, $property.ParameterName, ($property.Expected -join ', '))
                $setParameters.add($property.ParameterName, $property.Expected)
            }
            Set-AdfsWebApiApplication -TargetName $Name @setParameters
        }
        else
        {
            # Resource does not exist
            Write-Verbose -Message ($script:localizedData.AddingResourceMessage -f
                $Name, $ApplicationGroupIdentifier)
            Add-AdfsWebApiApplication @parameters -Verbose:$false
        }
    }
    else
    {
        # Resource should not exist
        if ($TargetResource.Ensure -eq 'Present')
        {
            # Resource exists
            Write-Verbose -Message ($script:localizedData.RemovingResourceMessage -f
                $Name, $ApplicationGroupIdentifier)
            Remove-AdfsWebApiApplication -TargetName $Name
        }
        else
        {
            # Resource does not exist
            Write-Verbose -Message ($script:localizedData.ResourceInDesiredStateMessage -f $Name)
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
        $Name,

        [Parameter(Mandatory = $true)]
        [System.String]
        $ApplicationGroupIdentifier,

        [Parameter(Mandatory = $true)]
        [System.String[]]
        $Identifier,

        [Parameter()]
        [System.String]
        $Description,

        [Parameter()]
        [ValidateSet('Present', 'Absent')]
        [System.String]
        $Ensure = 'Present',

        [Parameter()]
        [System.String[]]
        $AllowedAuthenticationClassReferences,

        [Parameter()]
        [System.String[]]
        $ClaimsProviderName,

        [Parameter()]
        [System.String]
        $IssuanceAuthorizationRules,

        [Parameter()]
        [System.String]
        $DelegationAuthorizationRules,

        [Parameter()]
        [System.String]
        $ImpersonationAuthorizationRules,

        [Parameter()]
        [Microsoft.Management.Infrastructure.CimInstance[]]
        $IssuanceTransformRules,

        [Parameter()]
        [System.String]
        $AdditionalAuthenticationRules,

        [Parameter()]
        [System.String]
        $AccessControlPolicyName,

        [Parameter()]
        [System.Int32]
        $NotBeforeSkew,

        [Parameter()]
        [System.Int32]
        $TokenLifetime,

        [Parameter()]
        [System.Boolean]
        $AlwaysRequireAuthentication,

        [Parameter()]
        [ValidateSet('None', 'Public', 'Confidential')]
        [System.String]
        $AllowedClientTypes,

        [Parameter()]
        [ValidateSet('NoDevice', 'WorkplaceJoinedDevices', 'AllDevices')]
        [System.String]
        $IssueOAuthRefreshTokensTo,

        [Parameter()]
        [System.Boolean]
        $RefreshTokenProtectionEnabled,

        [Parameter()]
        [System.Boolean]
        $RequestMFAFromClaimsProviders
    )

    $getTargetResourceParms = @{
        Name                       = $Name
        ApplicationGroupIdentifier = $ApplicationGroupIdentifier
        Identifier                 = $Identifier
    }
    $targetResource = Get-TargetResource @getTargetResourceParms

    if ($targetResource.Ensure -eq 'Present')
    {
        # Resource exists
        if ($Ensure -eq 'Present')
        {
            # Resource should exist
            $propertiesNotInDesiredState = @()
            if ($PSBoundParameters.Keys.Contains('IssuanceTransformRules'))
            {
                $propertiesNotInDesiredState += (
                    Compare-IssuanceTransformRules -CurrentValue $targetResource.IssuanceTransformRules `
                        -DesiredValue $IssuanceTransformRules -Debug:$true |
                        Where-Object -Property InDesiredState -eq $false)
            }

            $propertiesNotInDesiredState += (
                Compare-ResourcePropertyState -CurrentValues $targetResource -DesiredValues $PSBoundParameters |
                    Where-Object -Property InDesiredState -eq $false)

            if ($propertiesNotInDesiredState)
            {
                # Resource is not in desired state
                foreach ($property in $propertiesNotInDesiredState)
                {
                    Write-Verbose -Message (
                        $script:localizedData.ResourcePropertyNotInDesiredStateMessage -f
                        $targetResource.Name, $property.ParameterName, `
                            $property.Expected, $property.Actual)
                }
                $inDesiredState = $false
            }
            else
            {
                # Resource is in desired state
                Write-Verbose -Message ($script:localizedData.ResourceInDesiredStateMessage -f
                    $targetResource.Name)
                $inDesiredState = $true
            }
        }
        else
        {
            # Resource should not exist
            Write-Verbose -Message ($script:localizedData.ResourceExistsButShouldNotMessage -f
                $targetResource.Name)
            $inDesiredState = $false
        }
    }
    else
    {
        # Resource does not exist
        if ($Ensure -eq 'Present')
        {
            # Resource should exist
            Write-Verbose -Message ($script:localizedData.ResourceDoesNotExistButShouldMessage -f
                $targetResource.Name)
            $inDesiredState = $false
        }
        else
        {
            # Resource should not exist
            Write-Verbose -Message ($script:localizedData.ResourceDoesNotExistAndShouldNotMessage -f
                $targetResource.Name)
            $inDesiredState = $true
        }
    }

    $inDesiredState
}

function ConvertTo-IssuanceTransformRule
{
    <#
        $LdapClaimsTransformRule = @'
@RuleTemplate = "LdapClaims"
@RuleName = "test"
c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname", Issuer == "AD AUTHORITY"]
 => issue(store = "Active Directory", types = ("test", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname"), query = ";test,mail,givenName,sn;{0}", param = c.Value);
'@

    $EmitGroupClaimsTransformRule = @'
@RuleTemplate = "EmitGroupClaims"
@RuleName = "IDscan Users SRV EU-West-1"
c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/groupsid", Value == "S-1-5-21-2624039266-918686060-4041204886-1128", Issuer == "AD AUTHORITY"]
 => issue(Type = "http://schemas.microsoft.com/ws/2008/06/identity/claims/role", Value = "IDScan User", Issuer = c.Issuer, OriginalIssuer = c.OriginalIssuer, ValueType = c.ValueType);
'@

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
                Write-Debug "Processing LdapClaims Template Rule"
                $claimTypes = '"' + ($rule.LdapMapping.OutGoingClaimType -join '", "') + '"'
                $ldapAttributes = $rule.LdapMapping.LdapAttribute -join ','
                $output += ($ldapClaimsTransformRule -f '{0}', $rule.Name, $rule.AttributeStore,
                    $claimTypes, $ldapAttributes)
            }
            elseif ($rule.TemplateName -eq 'EmitGroupClaims')
            {
                Write-Debug "Processing EmitGroupClaims Template Rule"
                $groupSid = Get-AdGroupSid -GroupName $rule.GroupName
                $output += ($emitGroupClaimsTransformRule -f $rule.Name, $groupSid, $rule.OutgoingClaimType,
                    $rule.OutgoingClaimValue)
            }
            elseif ($rule.TemplateName -eq 'CustomClaims')
            {
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
        Write-Debug "ConvertTo-IssuanceTransformRule output: $output"
        $output
    }
}

function ConvertFrom-IssuanceTransformRule
{
    <#
        IssuanceTransformRules               = @(
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
    [OutputType([Microsoft.Management.Infrastructure.CimInstance])]
    param
    (
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [System.String[]]
        $Rule
    )

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

    $MSFT_AdfsIssuanceTransformRule = @()
    if ($individualRules)
    {
        foreach ($individualRule in $individualRules)
        {
            if ($individualRule[0] -eq '@RuleTemplate = "LdapClaims"')
            {
                # Process LdapClaims Rule Template
                $ldapAttributes = ($individualRule[3].Split('(').Split(')')[2]).Split(',')
                $outgoingClaimTypes = ($individualRule[3].Split(';')[1]).Split(',')

                $MSFT_AdfsLdapMapping = @()
                for ($index = 0; $index -lt $ldapAttributes.Count; $index++)
                {
                    $ldapMapping = @{
                        LdapAttribute     = $ldapAttributes[$index]
                        OutgoingClaimType = $outgoingClaimTypes[$index]
                    }
                    $MSFT_AdfsLdapMapping += New-CimInstance -ClassName MSFT_AdfsLdapMapping `
                        -Namespace root/microsoft/Windows/DesiredStateConfiguration `
                        -Property $ldapMapping -ClientOnly
                }
                $issuanceTransformRule = @{
                    TemplateName   = 'LdapClaims'
                    Name           = $individualRule[1].split('"')[1]
                    AttributeStore = $individualRule[3].split('"')[1]
                    LdapMapping    = [CimInstance[]]$MSFT_AdfsLdapMapping
                }
            }
            elseif ($individualRule[0] -eq '@RuleTemplate = "EmitGroupClaims"')
            {
                # Process EmitGroupClaims Rule Template
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
                # Process Custom Claim Rule
                $issuanceTransformRule = @{
                    TemplateName = 'CustomClaims'
                    Name         = $individualRule[0].split('"')[1]
                    CustomRule   = $individualRule[1..($individualRule.count)] | Out-String
                }
            }

            $MSFT_AdfsIssuanceTransformRule += New-CimInstance -ClassName MSFT_AdfsIssuanceTransformRule `
                -Namespace root/microsoft/Windows/DesiredStateConfiguration `
                -Property $issuanceTransformRule -ClientOnly
        }

        $MSFT_AdfsIssuanceTransformRule
    }
}

function Get-AdGroupSid
{
    [CmdletBinding()]
    [OutputType([System.String])]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $GroupName
    )

    Write-Debug "Getting SID for Active Directory group $GroupName"
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

function Get-AdGroupNameFromSid
{
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

function Compare-IssuanceTransformRules
{
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param
    (
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [System.Object[]]
        $CurrentValue,

        [Parameter(Mandatory = $true)]
        [System.Object[]]
        $DesiredValue
    )


    $parameterState = @{
        ParameterName  = 'IssuanceTransformRules'
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
        for ($index = 0; $index -lt $DesiredValue.Count; $index++)
        {
            if ($DesiredValue[$index].TemplateName -eq $CurrentValue[$index].TemplateName)
            {
                if ($DesiredValue[$index].TemplateName -eq 'LdapClaims')
                {
                    Write-Verbose -Message "Comparing LdapClaims Rule $($CurrentValue[$index].Name)"
                    if (Compare-Object -ReferenceObject $CurrentValue[$index] -DifferenceObject $DesiredValue[$index] `
                            -Property $CurrentValue[$index].CimInstanceProperties.Name)
                    {
                        Write-Verbose -Message "Comparing LdapClaims False"
                        $parameterState.InDesiredState = $false
                        break
                    }
                }
                elseif ($DesiredValue[$index].TemplateName -eq 'EmitGroupClaims')
                {
                    Write-Verbose -Message "Comparing EmitGroupClaims Rule $($CurrentValue[$index].Name)"
                    if (Compare-Object -ReferenceObject $CurrentValue[$index] -DifferenceObject $DesiredValue[$index] `
                            -Property $CurrentValue[$index].CimInstanceProperties.Name)
                    {
                        Write-Verbose -Message "Comparing EmitGroupClaims False"
                        $parameterState.InDesiredState = $false
                        break
                    }
                }
                elseif ($DesiredValue[$index].TemplateName -eq 'CustomClaims')
                {
                    Write-Verbose -Message "Comparing CustomClaims Rule $($CurrentValue[$index].Name)"
                    $CurrentCustomRule = ($CurrentValue[$index].CustomRule -split '\r?\n' | Out-String).Trim()
                    $DesiredCustomRule = ($DesiredValue[$index].CustomRule -split '\r?\n' | Out-String).Trim()
                    if ($CurrentCustomRule -ne $DesiredCustomRule)
                    {
                        Write-Verbose -Message "Comparing CustomClaims False"
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
                Write-Verbose -Message "TemplateName Changed"
                $parameterState.InDesiredState = $false
                break
            }
        }
    }

    Write-Verbose -Message "Returning Parameter State"
    return $parameterState
}

Export-ModuleMember -Function *-TargetResource
