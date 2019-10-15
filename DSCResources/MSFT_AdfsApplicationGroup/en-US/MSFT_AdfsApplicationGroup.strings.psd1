# culture="en-US"
ConvertFrom-StringData @'
    GettingResourceMessage                   = Getting '{0}'. (AG0001)
    SettingResourceMessage                   = Setting '{0}' property '{1}' to '{2}'. (AG0002)
    AddingResourceMessage                    = Adding '{0}'. (AG0003)
    RemovingResourceMessage                  = Removing '{0}'. (AG0004)
    ResourceInDesiredStateMessage            = '{0}' is in the desired state. (AG0005)
    ResourcePropertyNotInDesiredStateMessage = '{0}' Property '{1}' is not in the desired state. Expected: '{2}', Actual: '{3}'. (AG0006)
    ResourceExistsButShouldNotMessage        = '{0}' exists but should not. (AG0007)
    ResourceDoesNotExistButShouldMessage     = '{0}' does not exist but should. (AG0008)
    ResourceDoesNotExistAndShouldNotMessage  = '{0}' does not exist and should not. (AG0009)
'@
