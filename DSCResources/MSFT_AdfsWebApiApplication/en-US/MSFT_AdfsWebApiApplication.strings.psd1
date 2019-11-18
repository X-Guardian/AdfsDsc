# culture="en-US"
ConvertFrom-StringData @'
    GettingResourceMessage                    = Getting '{0}'. (WEB0001)
    SettingResourceMessage                    = Setting '{0}' property '{1}' to '{2}'. (WEB0002)
    AddingResourceMessage                     = Adding '{0}' to Application Group '{1}'. (WEB0003)
    RemovingResourceMessage                   = Removing '{0}' from Application Group '{1}'. (WEB0004)
    ResourceInDesiredStateMessage             = '{0}' in the desired state. (WEB0005)
    ResourcePropertyNotInDesiredStateMessage  = '{0}' Property '{1}' is not in the desired state. Expected: '{2}', Actual: '{3}'. (WEB0006)
    ResourceIsPresentButShouldBeAbsentMessage = '{0}' is present but should be absent. (WEB0007)
    ResourceIsAbsentButShouldBePresentMessage = '{0}' is absent but should be present. (WEB0008)

    TargetResourcePresentDebugMessage         = Target resource '{0}' is Present (WEBDBG001)
    TargetResourceAbsentDebugMessage          = Target resource '{0}' is Absent (WEBDBG002)
    TargetResourceShouldBePresentDebugMessage = Target resource '{0}' should be Present (WEBDBG003)
    TargetResourceShouldBeAbsentDebugMessage  = Target resource '{0}' should be Absent (WEBDBG004)
'@
