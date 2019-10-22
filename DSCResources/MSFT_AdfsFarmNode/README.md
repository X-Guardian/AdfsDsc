# Description

The AdfsFarmNode DSC resource manages an additional node in a pre-existing Active Directory
Federation Service server farm.

## Requirements

- The `SQLConnectionString` parameter should be the same as was specified for the ADFS Farm.
- The `ServiceAccountCredential` or `GroupServiceAccountIdentifier` should be the same as was
specified for the ADFS farm.
