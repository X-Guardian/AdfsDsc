# culture="en-US"
ConvertFrom-StringData @'
    GettingResourceMessage                    = Getting '{0}'. (SA001)
    TestingResourceMessage                    = Testing '{0}'. (SA002)
    SettingResourceMessage                    = Setting '{0}'. (SA003)
    SettingResourcePropertyMessage            = Setting '{0}' property '{1}' to '{2}'. (SA004)
    AddingResourceMessage                     = Adding '{0}' to Application Group '{1}'. (SA005)
    RemovingResourceMessage                   = Removing '{0}' from Application Group '{1}'. (SA006)
    ResourceInDesiredStateMessage             = '{0}' in the desired state. (SA007)
    ResourceNotInDesiredStateMessage          = '{0}' is not in the desired state. (SA008)
    ResourceIsPresentButShouldBeAbsentMessage = '{0}' exists but should not. (SA009)
    ResourceIsAbsentButShouldBePresentMessage = '{0}' is absent but should be present. (SA010)

    GettingResourceErrorMessage               = Error getting '{0}'. (SAERR001)
    SettingResourceErrorMessage               = Error setting '{0}'. (SAERR002)
    RemovingResourceErrorMessage              = Error removing '{0}'. (SAERR003)
    AddingResourceErrorMessage                = Error adding '{0}'. (SAERR004)

    TargetResourcePresentDebugMessage         = '{0}' is Present. (SADBG001)
    TargetResourceAbsentDebugMessage          = '{0}' is Absent. (SADBG002)
    TargetResourceShouldBePresentDebugMessage = '{0}' should be Present. (SADBG003)
    TargetResourceShouldBeAbsentDebugMessage  = '{0}' should be Absent. (SADBG004)
'@
