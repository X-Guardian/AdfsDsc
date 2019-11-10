# culture="en-US"
ConvertFrom-StringData @'
    GettingResourceMessage                    = Getting '{0}'. (AG0001)
    SettingResourceMessage                    = Setting '{0}' property '{1}' to '{2}'. (AG0002)
    AddingResourceMessage                     = Adding '{0}'. (AG0003)
    RemovingResourceMessage                   = Removing '{0}'. (AG0004)
    ResourceInDesiredStateMessage             = '{0}' is in the desired state. (AG0005)
    ResourcePropertyNotInDesiredStateMessage  = '{0}' Property '{1}' is not in the desired state. Expected: '{2}', Actual: '{3}'. (AG0006)
    ResourceIsPresentButShouldBeAbsentMessage = '{0}' is present but should be absent. (AG0007)
    ResourceIsAbsentButShouldBePresentMessage = '{0}' is absent but should be present. (AG0008)
'@
