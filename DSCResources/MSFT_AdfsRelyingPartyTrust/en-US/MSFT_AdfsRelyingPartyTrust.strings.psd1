# culture="en-US"
ConvertFrom-StringData @'
    GettingResourceMessage                    = Getting '{0}'. (RPT0001)
    SettingResourceMessage                    = Setting '{0}' property '{1}' to '{2}'. (RPT0002)
    AddingResourceMessage                     = Adding '{0}'. (RPT0003)
    RemovingResourceMessage                   = Removing '{0}'. (RPT0004)
    ResourceInDesiredStateMessage             = '{0}' is in the desired state. (RPT0005)
    ResourcePropertyNotInDesiredStateMessage  = '{0}' Property '{1}' is not in the desired state. Expected: '{2}', Actual: '{3}'. (RPT0006)
    ResourceIsPresentButShouldBeAbsentMessage = '{0}' is present but should be absent. (RPT0007)
    ResourceIsAbsentButShouldBePresentMessage = '{0}' is absent but should be present. (RPT0008)

    TargetResourcePresentDebugMessage         = Target resource '{0}' is Present (RPTDBG001)
    TargetResourceAbsentDebugMessage          = Target resource '{0}' is Absent (RPTDBG002)
    TargetResourceShouldBePresentDebugMessage = Target resource '{0}' should be Present (RPTDBG003)
    TargetResourceShouldBeAbsentDebugMessage  = Target resource '{0}' should be Absent (RPTDBG004)
'@
