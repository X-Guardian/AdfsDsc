# culture="en-US"
ConvertFrom-StringData @'
    TestingResourceMessage           = Testing '{0}'. (GAP001)
    SettingResourceMessage           = Setting '{0}'. (GAP002)
    SettingResourcePropertyMessage   = Setting '{0}' property '{1}' to '{2}'. (GAP003)
    ResourceInDesiredStateMessage    = '{0}' is in the desired state. (GAP004)
    ResourceNotInDesiredStateMessage = '{0}' is in the desired state. (GAP005)

    GettingResourceErrorMessage      = Error getting '{0}'. (GAPERR001)
    SettingResourceErrorMessage      = Error setting '{0}'. (GAPERR002)
'@
