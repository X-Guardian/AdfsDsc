# Welcome to the ADFSDsc wiki

Here you will find all the information you need to make use of the AdfsDsc DSC resources in the latest release (the code
that is part of the master branch). This includes details of the resources that are available, current capabilities and
known issues, and information to help plan a DSC based implementation of ADFS.

Please leave comments, feature requests, and bug reports in the
[issues section](https://github.com/X-Guardian/AdfsDsc/issues) for this module.

## Getting started

To install from the PowerShell gallery using PowerShellGet run the following command:

```powershell
Install-Module -Name AdfsDsc -Repository PSGallery
```

To confirm installation, run the below command and ensure you see the AdfsDsc DSC resources available:

```powershell
Get-DscResource -Module AdfsDsc
```
