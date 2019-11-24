# culture="en-US"
ConvertFrom-StringData @'
    GettingResourceMessage                      = Getting '{0}'. (FRM001)
    TestingResourceMessage                      = Testing '{0}'. (FRM002)
    SettingResourceMessage                      = Setting '{0}'. (FRM003)
    InstallingResourceMessage                   = Installing '{0}'. (FRM004)
    ResourceInstallSuccessMessage               = '{0}' has been installed successfully. A reboot is now required. (FRM005)
    ResourceInDesiredStateMessage               = '{0}' is in the desired state. (FRM006)
    ResourceIsAbsentButShouldBePresentMessage   = '{0}' is absent but should be present. (FRM007)
    MissingAdfsAssembliesMessage                = Required ADFS assemblies can't be found. Reboot required. (FRM008)

    InstallationErrorMessage                    = '{0}' installation error. (FRMERR001)
    ResourceDuplicateCredentialErrorMessage     = Only one of the credential parameters 'ServiceAccountCredential' or 'GroupServiceAccountIdentifier' should be specified for '{0}'. (FRMERR002)
    ResourceMissingCredentialErrorMessage       = One of the credential parameters 'ServiceAccountCredential' or 'GroupServiceAccountIdentifier' must be specified for '{0}'. (FRMERR003)
    GettingAdfsSslCertificateErrorMessage       = Error getting the ADFS SSL Certificate for '{0}'. (FRMERR004)
    GettingAdfsServiceErrorMessage              = Error getting the ADFS service details for '{0}'. (FRMERR005)
    GettingAdfsSecurityTokenServiceErrorMessage = Error getting the ADFS Security Token Service details for '{0}'. (FRMERR006)
    GettingAdfsPropertiesErrorMessage           = Error getting the ADFS properties for '{0}'. (FRMERR007)

    TargetResourcePresentDebugMessage         = '{0}' is Present. (FRMDBG001)
    TargetResourceAbsentDebugMessage          = '{0}' is Absent. (FRMDBG002)
'@
