# culture="en-US"
ConvertFrom-StringData @'
    TestingResourceMessage           = Testing '{0}'. (ORG001)
    SettingResourceMessage           = Setting '{0}'. (ORG002)
    SettingResourcePropertyMessage   = Setting '{0}' property '{1}' to '{2}'. (ORG003)
    ResourceInDesiredStateMessage    = '{0}' is in the desired state. (ORG004)
    ResourceNotInDesiredStateMessage = '{0}' is not in the desired state. (ORG005)

    GettingResourceErrorMessage      = Error getting '{0}'. (ORGERR001)
    SettingResourceErrorMessage      = Error setting '{0}'. (ORGERR002)
    NewAdfsOrganizationErrorMessage  = Error creating the ADFS Organization for '{0}'. (ORGERR003)
'@
