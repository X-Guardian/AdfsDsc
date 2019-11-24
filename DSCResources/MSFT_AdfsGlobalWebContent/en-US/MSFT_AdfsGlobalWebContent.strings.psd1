# culture="en-US"
ConvertFrom-StringData @'
    TestingResourceMessage           = Testing '{0}' locale '{1}'. (GWC001)
    SettingResourceMessage           = Setting '{0}' locale '{1}' property '{2}' to '{3}'. (GWC002)
    ResourceInDesiredStateMessage    = '{0}' locale '{1}' is in the desired state. (GWC003)
    ResourceNotInDesiredStateMessage = '{0}' locale '{1}' is notin the desired state. (GWC004)

    GettingResourceErrorMessage      = Error getting '{0}' locale '{1}'. (GWCERR001)
    SettingResourceErrorMessage      = Error setting '{0}' locale '{1}'. (GWCERR002)
'@
