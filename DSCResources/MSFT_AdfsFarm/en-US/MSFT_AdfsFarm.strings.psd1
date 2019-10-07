# culture="en-US"
ConvertFrom-StringData @'
    GettingResourceMessage               = Getting details for ADFS Farm '{0}'. (FRM0001)
    TestingResourceMessage               = Testing ADFS Farm '{0}'. (FRM0002)
    ResourceNotFoundMessage              = ADFS Farm '{0}' not found. (FRM0003)
    InstallationError                    = ADFS Farm '{0}' installation error. (FRM0004)
    InstallingResourceMessage            = Installing ADFS Farm '{0}'. (FRM0005)
    ResourceInstallSuccessMessage        = The ADFS Farm '{0}' has been installed successfully. A reboot is now required. (FRM0006)
    ResourceInDesiredStateMessage        = '{0}' is in the desired state. (FRM0007)
    MissingAdfsAssembliesMessage         = Required ADFS assemblies can't be found. Reboot required. (FRM0008)

    ResourceDuplicateCredentialError     = Only one of the credential parameters 'ServiceAccountCredential' or 'GroupServiceAccountIdentifier' should be specified for ADFS Farm '{0}'. (FRM0009)
    ResourceMissingCredentialError       = One of the credential parameters 'ServiceAccountCredential' or 'GroupServiceAccountIdentifier' must be specified for ADFS Farm '{0}'. (FRM0010)
    GettingAdfsSslCertificateError       = Error getting the ADFS SSL Certificate for '{0}'. (FRM0011)
    GettingAdfsServiceError              = Error getting the ADFS service details for '{0}'. (FRM0012)
    GettingAdfsSecurityTokenServiceError = Error getting the ADFS Security Token Service details for '{0}'. (FRM0013)
    GettingAdfsPropertiesError           = Error getting the ADFS properties for '{0}'. (FRM0014)
'@
