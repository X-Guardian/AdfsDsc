# culture="en-US"
ConvertFrom-StringData @'
    GettingResourceMessage                    = Getting client role '{0}', server role '{1}'. (AP0001)
    SettingResourceMessage                    = Setting client role '{0}', server role '{1}' property '{2}' to '{3}'. (AP0002)
    AddingResourceMessage                     = Adding client role '{0}' server role '{1}'. (AP0003)
    RemovingResourceMessage                   = Removing client role '{0}' server role '{1}'. (AP0004)
    ResourceInDesiredStateMessage             = client role '{0}' server role '{1}' is in the desired state. (AP0005)
    ResourcePropertyNotInDesiredStateMessage  = client role '{0}' server role '{1}' Property '{2}' is not in the desired state. Expected: '{2}', Actual: '{3}'. (AP0006)
    ResourceIsPresentButShouldBeAbsentMessage = client role '{0}' server role '{1}' is present but should be absent. (AP0007)
    ResourceIsAbsentButShouldBePresentMessage = client role '{0}' server role '{1}' is absent but should be present. (AP0008)
'@
