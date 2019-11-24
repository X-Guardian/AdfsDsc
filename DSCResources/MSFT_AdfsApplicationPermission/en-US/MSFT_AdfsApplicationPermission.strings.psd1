# culture="en-US"
ConvertFrom-StringData @'
    TestingResourceMessage                    = Testing client role '{0}', server role '{1}'. (AP0001)
    SettingResourceMessage                    = Setting client role '{0}', server role '{1}'. (AP0002)
    SettingResourcePropertyMessage            = Setting client role '{0}', server role '{1}' property '{2}' to '{3}'. (AP0003)
    AddingResourceMessage                     = Adding client role '{0}' server role '{1}'. (AP0004)
    RemovingResourceMessage                   = Removing client role '{0}' server role '{1}'. (AP0005)
    ResourceInDesiredStateMessage             = client role '{0}' server role '{1}' is in the desired state. (AP0006)
    ResourceNotInDesiredStateMessage          = client role '{0}' server role '{1}' is not in the desired state. (AG0007)
    ResourceIsPresentButShouldBeAbsentMessage = client role '{0}' server role '{1}' is present but should be absent. (AP0008)
    ResourceIsAbsentButShouldBePresentMessage = client role '{0}' server role '{1}' is absent but should be present. (AP0009)

    GettingResourceErrorMessage               = Error getting '{0}'. (APERR001)
    SettingResourceErrorMessage               = Error setting '{0}'. (APERR002)
    RemovingResourceErrorMessage              = Error removing '{0}'. (APERR003)
    AddingResourceErrorMessage                = Error adding '{0}'. (APERR004)

    TargetResourcePresentDebugMessage         = client role '{0}' server role '{1}' is Present (APDBG001)
    TargetResourceAbsentDebugMessage          = client role '{0}' server role '{1}' is Absent (APDBG002)
    TargetResourceShouldBePresentDebugMessage = client role '{0}' server role '{1}' should be Present (APDBG003)
    TargetResourceShouldBeAbsentDebugMessage  = client role '{0}' server role '{1}' should be Absent (APDBG004)
'@
