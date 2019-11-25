# culture="en-US"
ConvertFrom-StringData @'
    GettingResourceMessage                    = Getting '{0}'. (AG001)
    TestingResourceMessage                    = Testing '{0}'. (AG002)
    SettingResourceMessage                    = Setting '{0}'. (AG003)
    SettingResourcePropertyMessage            = Setting '{0}' property '{1}' to '{2}'. (AG004)
    AddingResourceMessage                     = Adding '{0}'. (AG005)
    RemovingResourceMessage                   = Removing '{0}'. (AG006)
    ResourceInDesiredStateMessage             = '{0}' is in the desired state. (AG007)
    ResourceNotInDesiredStateMessage          = '{0}' is not in the desired state. (AG008)
    ResourceIsPresentButShouldBeAbsentMessage = '{0}' is present but should be absent. (AG009)
    ResourceIsAbsentButShouldBePresentMessage = '{0}' is absent but should be present. (AG010)

    GettingResourceErrorMessage               = Error getting '{0}'. (AGERR001)
    SettingResourceErrorMessage               = Error setting '{0}'. (AGERR002)
    RemovingResourceErrorMessage              = Error removing '{0}'. (AGERR003)
    AddingResourceErrorMessage                = Error adding '{0}'. (AGERR004)

    TargetResourcePresentDebugMessage         = '{0}' is Present. (AGDBG001)
    TargetResourceAbsentDebugMessage          = '{0}' is Absent. (AGDBG002)
    TargetResourceShouldBePresentDebugMessage = '{0}' should be Present. (AGDBG003)
    TargetResourceShouldBeAbsentDebugMessage  = '{0}' should be Absent. (AGDBG004)
'@
