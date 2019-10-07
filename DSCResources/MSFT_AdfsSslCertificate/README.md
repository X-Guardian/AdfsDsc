# Description

The AdfsSslCertificate Dsc resource manages the SSL certificate used for HTTPS binding for Active Directory
Federation Services

On Server 2016 and above, this is a multi-node resource, meaning it only has to run on the primary and all
nodes in the farm will be updated. On Server 2012R2, run the command on each ADFS server in the ADFS farm.

Note: in order to succesfully update the certificate binding on all farm members, WinRM must be configured on
all remote nodes and using the standard HTTP listener.
