# Description

The AdfsFarm DSC resource manages the installation of an Active Directory Federation Services server
farm, and the primary node of the farm. To further manage the configuration of ADFS, the
ADFSProperties DSC resource should be used.

Note: removal of the ADFS server farm using this resource is not supported. Remove the
Adfs-Federation role from the server instead.
