# culture="en-US"
ConvertFrom-StringData @'
    GettingResourceMessage                   = Getting '{0}'. (RPT0001)
    SettingResourceMessage                   = Setting '{0}' property '{1}' to '{2}'. (RPT0002)
    AddingResourceMessage                    = Adding '{0}'. (RPT0003)
    RemovingResourceMessage                  = Removing '{0}'. (RPT0004)
    ResourceInDesiredStateMessage            = '{0}' in the desired state. (RPT0005)
    ResourcePropertyNotInDesiredStateMessage = '{0}' Property '{1}' is not in the desired state. Expected: '{2}', Actual: '{3}'. (RPT0006)
    ResourceExistsButShouldNotMessage        = '{0}' exists but should not. (RPT0007)
    ResourceDoesNotExistButShouldMessage     = '{0}' does not exist but should. (RPT0008)
    ResourceDoesNotExistAndShouldNotMessage  = '{0}' does not exist and should not. (RPT0009)
'@
