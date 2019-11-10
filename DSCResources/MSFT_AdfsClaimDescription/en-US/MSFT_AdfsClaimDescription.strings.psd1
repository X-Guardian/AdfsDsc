# culture="en-US"
ConvertFrom-StringData @'
GettingResourceMessage                    = Getting '{0}'. (CD0001)
SettingResourceMessage                    = Setting '{0}' property '{1}' to '{2}'. (CD0002)
AddingResourceMessage                     = Adding '{0}'. (CD0003)
RemovingResourceMessage                   = Removing '{0}'. (CD0004)
ResourceInDesiredStateMessage             = '{0}' is in the desired state. (CD0005)
ResourcePropertyNotInDesiredStateMessage  = '{0}' Property '{1}' is not in the desired state. Expected: '{2}', Actual: '{3}'. (CD0006)
ResourceIsPresentButShouldBeAbsentMessage = '{0}' is present but should be absent. (CD0007)
ResourceIsAbsentButShouldBePresentMessage = '{0}' is absent but should be present. (CD0008)
'@

