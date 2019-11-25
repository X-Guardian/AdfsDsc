# culture="en-US"
ConvertFrom-StringData @'
    GettingResourceMessage                    = Getting '{0}'. (NCA001)
    TestingResourceMessage                    = Testing '{0}'. (NCA002)
    SettingResourceMessage                    = Setting '{0}'. (NCA003)
    SettingResourcePropertyMessage            = Setting '{0}' property '{1}' to '{2}'. (NCA004)
    AddingResourceMessage                     = Adding '{0}' to Application Group '{1}'. (NCA005)
    RemovingResourceMessage                   = Removing '{0}' from Application Group '{1}'. (NCA006)
    ResourceInDesiredStateMessage             = '{0}' in the desired state. (NCA007)
    ResourceNotInDesiredStateMessage          = '{0}' is not in the desired state. (NCA008)
    ResourceIsPresentButShouldBeAbsentMessage = '{0}' exists but should not. (NCA009)
    ResourceIsAbsentButShouldBePresentMessage = '{0}' is absent but should be present. (NCA010)

    GettingResourceErrorMessage               = Error getting '{0}'. (NCAERR001)
    SettingResourceErrorMessage               = Error setting '{0}'. (NCAERR002)
    RemovingResourceErrorMessage              = Error removing '{0}'. (NCAERR003)
    AddingResourceErrorMessage                = Error adding '{0}'. (NCAERR004)

    TargetResourcePresentDebugMessage         = '{0}' is Present. (NCADBG001)
    TargetResourceAbsentDebugMessage          = '{0}' is Absent. (NCADBG002)
    TargetResourceShouldBePresentDebugMessage = '{0}' should be Present. (NCADBG003)
    TargetResourceShouldBeAbsentDebugMessage  = '{0}' should be Absent. (NCADBG004)
'@
