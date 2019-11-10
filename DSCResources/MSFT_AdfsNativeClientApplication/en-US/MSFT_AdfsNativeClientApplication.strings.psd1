# culture="en-US"
ConvertFrom-StringData @'
    GettingResourceMessage                    = Getting '{0}'. (NCA0001)
    SettingResourceMessage                    = Setting '{0}' property '{1}' to '{2}'. (NCA0002)
    AddingResourceMessage                     = Adding '{0}' to Application Group '{1}'. (NCA0003)
    RemovingResourceMessage                   = Removing '{0}' from Application Group '{1}'. (NCA0004)
    ResourceInDesiredStateMessage             = '{0}' in the desired state. (NCA0005)
    ResourcePropertyNotInDesiredStateMessage  = '{0}' Property '{1}' is not in the desired state. Expected: '{2}', Actual: '{3}'. (NCA0006)
    ResourceIsPresentButShouldBeAbsentMessage = '{0}' exists but should not. (NCA0007)
    ResourceIsAbsentButShouldBePresentMessage = '{0}' is absent but should be present. (NCA0008)
'@
