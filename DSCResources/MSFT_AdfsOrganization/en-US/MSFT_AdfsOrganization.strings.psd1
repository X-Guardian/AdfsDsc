# culture="en-US"
ConvertFrom-StringData @'
    GettingResourceMessage           = Getting '{0}'. (ORG001)
    TestingResourceMessage           = Testing '{0}'. (ORG002)
    SettingResourceMessage           = Setting '{0}'. (ORG003)
    SettingResourcePropertyMessage   = Setting '{0}' property '{1}' to '{2}'. (ORG004)
    ResourceInDesiredStateMessage    = '{0}' is in the desired state. (ORG005)
    ResourceNotInDesiredStateMessage = '{0}' is not in the desired state. (ORG006)

    GettingResourceErrorMessage      = Error getting '{0}'. (ORGERR001)
    SettingResourceErrorMessage      = Error setting '{0}'. (ORGERR002)
    NewAdfsOrganizationErrorMessage  = Error creating the ADFS Organization for '{0}'. (ORGERR003)
'@
