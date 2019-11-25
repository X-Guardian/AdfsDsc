# culture="en-US"
ConvertFrom-StringData @'
    GettingResourceMessage                    = Getting '{0}'. (WEB001)
    TestingResourceMessage                    = Testing '{0}'. (WEB002)
    SettingResourceMessage                    = Setting '{0}'. (WEB003)
    SettingResourcePropertyMessage            = Setting '{0}' property '{1}' to '{2}'. (WEB004)
    AddingResourceMessage                     = Adding '{0}' to Application Group '{1}'. (WEB005)
    RemovingResourceMessage                   = Removing '{0}' from Application Group '{1}'. (WEB006)
    ResourceInDesiredStateMessage             = '{0}' is in the desired state. (WEB007)
    ResourceNotInDesiredStateMessage          = '{0}' is not in the desired state. (WEB008)
    ResourceIsPresentButShouldBeAbsentMessage = '{0}' is present but should be absent. (WEB009)
    ResourceIsAbsentButShouldBePresentMessage = '{0}' is absent but should be present. (WEB010)

    GettingResourceErrorMessage               = Error getting '{0}'. (WEBERR001)
    SettingResourceErrorMessage               = Error setting '{0}'. (WEBERR002)
    RemovingResourceErrorMessage              = Error removing '{0}'. (WEBERR003)
    AddingResourceErrorMessage                = Error adding '{0}'. (WEBERR004)

    TargetResourcePresentDebugMessage         = '{0}' is Present. (WEBDBG001)
    TargetResourceAbsentDebugMessage          = '{0}' is Absent. (WEBDBG002)
    TargetResourceShouldBePresentDebugMessage = '{0}' should be Present. (WEBDBG003)
    TargetResourceShouldBeAbsentDebugMessage  = '{0}' should be Absent. (WEBDBG004)
'@
