# culture="en-US"
ConvertFrom-StringData @'
    TestingResourceMessage           = Testing '{0}'. (CER001)
    SettingResourceMessage           = Setting '{0}'. (CER002)
    SettingResourcePropertyMessage   = Setting '{0}' property '{1}' to '{2}'. (CER003)
    ResourceInDesiredStateMessage    = '{0}' is in the desired state. (CER004)
    ResourceNotInDesiredStateMessage = '{0}' is not in the desired state. (CER005)

    GettingResourceErrorMessage      = Error getting '{0}'. (CERERR001)
    SettingResourceErrorMessage      = Error setting '{0}'. (CERERR002)
'@
