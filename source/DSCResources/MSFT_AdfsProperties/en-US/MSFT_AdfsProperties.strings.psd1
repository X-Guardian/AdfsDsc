# culture="en-US"
ConvertFrom-StringData @'
    GettingResourceMessage           = Getting '{0}'. (PRO001)
    TestingResourceMessage           = Testing '{0}'. (PRO002)
    SettingResourceMessage           = Setting '{0}'. (PRO003)
    SettingResourcePropertyMessage   = Setting '{0}' property '{1}' to '{2}'. (PRO004)
    ResourceInDesiredStateMessage    = '{0}' is in the desired state. (PRO005)
    ResourceNotInDesiredStateMessage = '{0}' is not in the desired state. (PRO006)

    GettingResourceErrorMessage      = Error getting '{0}'. (PROERR001)
    SettingResourceErrorMessage      = Error setting '{0}'. (PROERR002)
    UnsupportedParameterErrorMessage = Parameter not supported on the {0} edition of ADFS. (PROERR003)
'@
