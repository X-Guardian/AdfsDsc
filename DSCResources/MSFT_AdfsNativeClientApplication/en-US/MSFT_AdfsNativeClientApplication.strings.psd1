# culture="en-US"
ConvertFrom-StringData @'
    TestingResourceMessage                    = Testing '{0}'. (NCA001)
    SettingResourceMessage                    = Setting '{0}'. (NCA002)
    SettingResourcePropertyMessage            = Setting '{0}' property '{1}' to '{2}'. (NCA003)
    AddingResourceMessage                     = Adding '{0}' to Application Group '{1}'. (NCA004)
    RemovingResourceMessage                   = Removing '{0}' from Application Group '{1}'. (NCA005)
    ResourceInDesiredStateMessage             = '{0}' in the desired state. (NCA006)
    ResourceNotInDesiredStateMessage          = '{0}' is not in the desired state. (NCA007)
    ResourceIsPresentButShouldBeAbsentMessage = '{0}' exists but should not. (NCA008)
    ResourceIsAbsentButShouldBePresentMessage = '{0}' is absent but should be present. (NCA009)

    GettingResourceErrorMessage               = Error getting '{0}'. (NCAERR001)
    SettingResourceErrorMessage               = Error setting '{0}'. (NCAERR002)
    RemovingResourceErrorMessage              = Error removing '{0}'. (NCAERR003)
    AddingResourceErrorMessage                = Error adding '{0}'. (NCAERR004)

    TargetResourcePresentDebugMessage         = '{0}' is Present (NCADBG001)
    TargetResourceAbsentDebugMessage          = '{0}' is Absent (NCADBG002)
    TargetResourceShouldBePresentDebugMessage = '{0}' should be Present (NCADBG003)
    TargetResourceShouldBeAbsentDebugMessage  = '{0}' should be Absent (NCADBG004)
'@
