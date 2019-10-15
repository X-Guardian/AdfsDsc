# culture="en-US"
ConvertFrom-StringData @'
    GettingResourceMessage                   = Getting '{0}'. (CER0001)
    SettingResourceMessage                   = Setting '{0}' property '{1}' to '{2}'. (CER0002)
    ResourceInDesiredStateMessage            = '{0}' is in the desired state. (CER0003)
    ResourcePropertyNotInDesiredStateMessage = '{0}' Property '{1}' is not in the desired state. Expected: '{2}', Actual: '{3}'. (CER0004)
    GettingResourceError                     = Error getting '{0}'. (CER0005)
    SettingResourceError                     = Error setting '{0}'. (CER0006)
'@

