# culture="en-US"
ConvertFrom-StringData @'
    GettingResourceMessage                   = Getting '{0}'. (ORG0001)
    SettingResourceMessage                   = Setting '{0}' property '{1}' to '{2}'. (ORG0002)
    ResourceInDesiredStateMessage            = '{0}' is in the desired state. (ORG0003)
    ResourcePropertyNotInDesiredStateMessage = '{0}' Property '{1}' is not in the desired state. Expected: '{2}', Actual: '{3}'. (ORG0004)
    GettingResourceError                     = Error getting '{0}'. (ORG0005)
    SettingResourceError                     = Error setting '{0}'. (ORG0006)
    NewAdfsOrganizationError                 = Error creating the ADFS Organization for '{0}. (ORG0007)
'@
