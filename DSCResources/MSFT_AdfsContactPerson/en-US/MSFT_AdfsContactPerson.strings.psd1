# culture="en-US"
ConvertFrom-StringData @'
    TestingResourceMessage           = Testing '{0}'. (CP001)
    SettingResourceMessage           = Setting '{0}'. (CP002)
    SettingResourcePropertyMessage   = Setting '{0}' property '{1}' to '{2}'. (CP003)
    ResourceInDesiredStateMessage    = '{0}' is in the desired state. (CP004)
    ResourceNotInDesiredStateMessage = '{0}' is not in the desired state. (CP005)

    GettingResourceErrorMessage      = Error getting '{0}'. (CPERR001)
    SettingResourceErrorMessage      = Error setting '{0}'. (CPERR002)
    NewAdfsContactPersonErrorMessage = Error creating a contact person for '{0}'. (CPERR003)
'@
