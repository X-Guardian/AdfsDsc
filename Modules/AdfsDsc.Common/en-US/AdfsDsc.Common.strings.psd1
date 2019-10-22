# Localized resources for helper module AdfsDsc.Common.

ConvertFrom-StringData @'
    EvaluatePropertyState                  = Evaluating the state of the property '{0}'. (ADFSCOMMON0001)
    PropertyInDesiredState                 = The parameter '{0}' is in desired state. (ADFSCOMMON0002)
    PropertyNotInDesiredState              = The parameter '{0}' is not in desired state. (ADFSCOMMON0003)
    ArrayDoesNotMatch                      = One or more values in an array does not match the desired state. Details of the changes are below. (ADFSCOMMON0004)
    ArrayValueThatDoesNotMatch             = {0} - {1} (ADFSCOMMON0005)
    PropertyValueOfTypeDoesNotMatch        = {0} value does not match. Current value is '{1}', but expected the value '{2}'. (ADFSCOMMON0006)
    WaitingForAdfsServiceMessage           = Waiting {0} seconds for ADFS service to start. Retry number {1} of {2}. (ADFSCOMMON0007)
    UnableToCompareType                    = Unable to compare the type {0} as it is not handled by the Test-DscPropertyState cmdlet. (ADFSCOMMON0008)
    ModuleNotFoundError                    = Please ensure that the PowerShell module for role '{0}' is installed. (ADFSCOMMON0009)
    ResourceNotImplementedError            = {0} {1} not implemented. (ADFSCOMMON0010)
    NotDomainMemberError                   = The computer must be an Active Directory domain member to use this resource. (ADFSCOMMON0011)
    UnexpectedServiceAccountCategoryError  = Unexpected object type of {0} for service account {1}. (ADFSCOMMON0012)
    GetAdfsServiceError                    = Error while getting ADFS Service status. (ADFSCOMMON0013)
    AdfsServiceNotRunningError             = The ADFS Service is not running. (ADFSCOMMON0014)
    ServiceAccountNotFoundError            = Service account {0} not found. (ADFSCOMMON0015)
    ConfigurationStatusNotFoundError       = The ADFS configuration status registry entry does not exist. (ADFSCOMMON0016)
    UnknownConfigurationStatusError        = The ADFS configuration status registry entry contains an unknown value {0}. (ADFSCOMMON0017)
    UnknownNameFormatError                 = The Active Directory account name is in an unknown format. (ADFSCOMMON0018)
'@
