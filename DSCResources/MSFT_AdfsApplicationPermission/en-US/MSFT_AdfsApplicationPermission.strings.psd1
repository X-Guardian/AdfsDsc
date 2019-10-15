# culture="en-US"
ConvertFrom-StringData @'
    GettingResourceMessage                   = Getting client role '{0}', server role '{1}'. (AP0001)
    SettingResourceMessage                   = Setting client role '{0}', server role '{1}' property '{2}' to '{3}'. (AP0002)
    AddingResourceMessage                    = Adding client role '{0}' server role '{1}'. (AP0003)
    RemovingResourceMessage                  = Removing client role '{0}' server role '{1}'. (AP0004)
    ResourceInDesiredStateMessage            = client role '{0}' server role '{1}' is in the desired state. (AP0005)
    ResourcePropertyNotInDesiredStateMessage = client role '{0}' server role '{1}' Property '{2}' is not in the desired state. Expected: '{2}', Actual: '{3}'. (AP0006)
    ResourceExistsButShouldNotMessage        = client role '{0}' server role '{1}' exists but should not. (AP0007)
    ResourceDoesNotExistButShouldMessage     = client role '{0}' server role '{1}' does not exist but should. (AP0008)
    ResourceDoesNotExistAndShouldNotMessage  = client role '{0}' server role '{1}' does not exist and should not. (AP0009)
'@
