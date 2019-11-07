# culture="en-US"
ConvertFrom-StringData @'
    GettingResourceMessage                   = Getting details for '{0}'. (NDE0001)
    TestingResourceMessage                   = Testing '{0}'. (NDE0002)
    ResourceNotFoundMessage                  = '{0}' not found. (NDE0003)
    InstallingResourceMessage                = Installing '{0}'. (NDE0004)
    ResourceInstallSuccessMessage            = '{0}' has been installed successfully. A reboot is now required. (NDE0005)
    ResourceInDesiredStateMessage            = '{0}' is in the desired state. (NDE0006)
    ResourceExistsButShouldNotMessage        = '{0}' exists but should not. (NDE0007)
    ResourceDoesNotExistButShouldMessage     = '{0}' does not exist but should. (NDE0008)
    ResourceDoesNotExistAndShouldNotMessage  = '{0}' does not exist and should not. (NDE0009)
    MissingAdfsAssembliesMessage             = Required ADFS assemblies can't be found. Reboot required. (NDE0010)
    RemovingResourceMessage                  = Removing '{0}'. (NDE0011)

    InstallationError                        = '{0}' installation error. (NDE0012)
    RemovalError                             = '{0}' removal error. (NDE0013)
    ResourceDuplicateCredentialError         = Only one of the credential parameters 'ServiceAccountCredential' or 'GroupServiceAccountIdentifier' should be specified for '{0}'. (NDE0014)
    ResourceMissingCredentialError           = One of the credential parameters 'ServiceAccountCredential' or 'GroupServiceAccountIdentifier' must be specified for '{0}'. (NDE0015)
    GettingAdfsSslCertificateError           = Error getting the ADFS SSL Certificate for '{0}'. (NDE0016)
    GettingAdfsServiceError                  = Error getting the ADFS service details for '{0}'. (NDE0017)
    GettingAdfsSecurityTokenServiceError     = Error getting the ADFS Security Token Service details for '{0}'. (NDE0018)
    GettingAdfsSyncPropertiesError           = Error getting the ADFS sync properties for '{0}'. (NDE0019)
    UnknownAdfsSyncPropertiesObjectTypeError = Error unknown AdfsSyncProperties object type '{0}. (NDE0020)
'@
