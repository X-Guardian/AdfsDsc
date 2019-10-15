# culture="en-US"
ConvertFrom-StringData @'
    GettingResourceMessage                   = Getting '{0}'. (SSL0001)
    SettingResourceMessage                   = Setting '{0}' property '{1}' to '{2}'. (SSL0002)
    ResourceInDesiredStateMessage            = '{0}' is in the desired state. (SSL0003)
    ResourcePropertyNotInDesiredStateMessage = '{0}' Property '{1}' is not in the desired state. Expected: '{2}', Actual: '{3}'. (SSL0004)
    GettingResourceError                     = Error getting '{0}'. (SSL0005)
    SettingResourceError                     = Error setting '{0}'. (SSL0006)
'@
