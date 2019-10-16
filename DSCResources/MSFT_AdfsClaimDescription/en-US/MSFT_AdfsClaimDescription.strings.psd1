# culture="en-US"
ConvertFrom-StringData @'
GettingResourceMessage                   = Getting '{0}'. (CD0001)
SettingResourceMessage                   = Setting '{0}' property '{1}' to '{2}'. (CD0002)
AddingResourceMessage                    = Adding '{0}'. (CD0003)
RemovingResourceMessage                  = Removing '{0}'. (CD0004)
ResourceInDesiredStateMessage            = '{0}' is in the desired state. (CD0005)
ResourcePropertyNotInDesiredStateMessage = '{0}' Property '{1}' is not in the desired state. Expected: '{2}', Actual: '{3}'. (CD0006)
ResourceExistsButShouldNotMessage        = '{0}' exists but should not. (CD0007)
ResourceDoesNotExistButShouldMessage     = '{0}' does not exist but should. (CD0008)
ResourceDoesNotExistAndShouldNotMessage  = '{0}' does not exist and should not. (CD0009)
'@

