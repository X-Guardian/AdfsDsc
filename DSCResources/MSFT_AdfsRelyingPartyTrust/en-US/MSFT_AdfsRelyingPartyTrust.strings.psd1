# culture="en-US"
ConvertFrom-StringData @'
    GettingResourceMessage                    = Getting '{0}'. (RPT001)
    TestingResourceMessage                    = Testing '{0}'. (RPT002)
    SettingResourceMessage                    = Setting '{0}'. (RPT003)
    SettingResourcePropertyMessage            = Setting '{0}' property '{1}' to '{2}'. (RPT004)
    AddingResourceMessage                     = Adding '{0}'. (RPT005)
    RemovingResourceMessage                   = Removing '{0}'. (RPT006)
    ResourceInDesiredStateMessage             = '{0}' is in the desired state. (RPT007)
    ResourceNotInDesiredStateMessage          = '{0}' is not in the desired state. (RPT008)
    ResourceIsPresentButShouldBeAbsentMessage = '{0}' is present but should be absent. (RPT009)
    ResourceIsAbsentButShouldBePresentMessage = '{0}' is absent but should be present. (RPT010)

    GettingResourceErrorMessage               = Error getting '{0}'. (RPTERR001)
    SettingResourceErrorMessage               = Error setting '{0}'. (RPTERR002)
    RemovingResourceErrorMessage              = Error removing '{0}'. (RPTERR003)
    AddingResourceErrorMessage                = Error adding '{0}'. (RPTERR004)
    GettingClaimDescriptionErrorMessage       = Error getting claim description '{0}' for '{1}'. (RPTERR005)
    EnablingResourceErrorMessage              = Error enabling '{0}'. (RPTERR006)
    DisablingResourceErrorMessage             = Error disabling '{0}'. (RPTERR007)

    TargetResourcePresentDebugMessage         = '{0}' is Present. (RPTDBG001)
    TargetResourceAbsentDebugMessage          = '{0}' is Absent. (RPTDBG002)
    TargetResourceShouldBePresentDebugMessage = '{0}' should be Present. (RPTDBG003)
    TargetResourceShouldBeAbsentDebugMessage  = '{0}' should be Absent. (RPTDBG004)
'@
