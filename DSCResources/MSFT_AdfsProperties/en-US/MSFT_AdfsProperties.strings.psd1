# culture="en-US"
ConvertFrom-StringData @'
    TestingResourceMessage           = Testing '{0}'. (PRO001)
    SettingResourceMessage           = Setting '{0}'. (PRO002)
    SettingResourcePropertyMessage   = Setting '{0}' property '{1}' to '{2}'. (PRO003)
    ResourceInDesiredStateMessage    = '{0}' is in the desired state. (PRO004)
    ResourceNotInDesiredStateMessage = '{0}' is notin the desired state. (PRO005)

    GettingResourceErrorMessage      = Error getting '{0}'. (PROERR001)
    SettingResourceErrorMessage      = Error setting '{0}'. (PROERR002)
'@
