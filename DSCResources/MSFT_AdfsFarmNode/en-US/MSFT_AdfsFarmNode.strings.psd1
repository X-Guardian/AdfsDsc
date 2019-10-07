# culture="en-US"
ConvertFrom-StringData @'
    GettingResourceMessage                   = Getting details for '{0}'. (NDE0001)
    TestingResourceMessage                   = Testing '{0}'. (NDE0002)
    ResourceNotFoundMessage                  = '{0}' not found. (NDE0003)
    InstallationError                        = '{0}' installation error. (NDE0004)
    InstallingResourceMessage                = Installing '{0}'. (NDE0005)
    ResourceInstallSuccessMessage            = '{0}' has been installed successfully. A reboot is now required. (NDE0006)
    ResourceInDesiredStateMessage            = '{0}' is in the desired state. (NDE0007)
    ResourceExistsButShouldNotMessage        = '{0}' exists but should not. (NDE0008)
    ResourceDoesNotExistButShouldMessage     = '{0}' does not exist but should. (NDE0009)
    ResourceDoesNotExistAndShouldNotMessage  = '{0}' does not exist and should not. (NDE0010)
    MissingAdfsAssembliesMessage             = Required ADFS assemblies can't be found. Reboot required. (NDE0011)
    RemovingResourceMessage                  = Removing '{0}'. (NDE0012)

    ResourceDuplicateCredentialError         = Only one of the credential parameters 'ServiceAccountCredential' or 'GroupServiceAccountIdentifier' should be specified for '{0}'. (NDE0013)
    ResourceMissingCredentialError           = One of the credential parameters 'ServiceAccountCredential' or 'GroupServiceAccountIdentifier' must be specified for '{0}'. (NDE0014)
    GettingAdfsSslCertificateError           = Error getting the ADFS SSL Certificate for '{0}'. (NDE0015)
    GettingAdfsServiceError                  = Error getting the ADFS service details for '{0}'. (NDE0016)
    GettingAdfsSecurityTokenServiceError     = Error getting the ADFS Security Token Service details for '{0}'. (NDE0017)
    GettingAdfsSyncPropertiesError           = Error getting the ADFS sync properties for '{0}'. (NDE0018)
'@
