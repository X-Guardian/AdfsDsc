# Description

The AdfsApplicationGroup DSC resource manages Application Groups within Active Directory Federation Services.
These are a construct that combine trust and authorization elements into one resource.

The `AdfsNativeClientApplication` and `AdfsWebApiApplication` resources manage applications within an
application group.

## Requirements

* Target machine must be running ADFS on Windows Server 2016 or above to use this resource.
