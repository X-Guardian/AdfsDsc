# Change log for AdfsDsc

The format is based on and uses the types of changes according to [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- AdsfRelyingPartyTrust
  - Fixed issue when the `AllowedClientTypes` Property had multiple values.

### Changed

- AdfsDsc
  - Updated the Help and Example files.

## [1.3.1] - 2023-04-19

### Fixed

- AdsfWebApiApplication
  - Fixed issue when the `AllowedClientTypes` Property had multiple values ([#63](https://github.com/X-Guardian/AdfsDsc/issues/63)]).
  - Fixed issue with comparing custom Issuance Transform Rules ([#57](https://github.com/X-Guardian/AdfsDsc/issues/57)).

## [1.3.0] - 2023-03-19

### Fixed

- AdfsDsc
  - Fixed Sampler breaking change with GitHubTasks.
- AdfsProperties
  - Fixed issues with unavailable properties on Windows Server 2016
  ([issue #51](https://github.com/X-Guardian/AdfsDsc/issues/51)).

### Changed

- AdfsDsc
  - Updated gitversion configuration.
  - Updated Azure Pipeline Ubuntu image version
- AdfsFarm
  - Added parameters `CertificateDnsName`, `SigningCertificateDnsName` and `DecryptionCertificateDnsName`.

## [1.2.0] - 2023-03-01

- Unreleased

## [1.1.0] - 2020-12-22

### Added

- AdfsContactPerson
  - Added empty contact support
  ([issue #27](https://github.com/X-Guardian/AdfsDsc/issues/27)).
- AdfsFarm
  - Added `AdminConfiguration` parameter ([issue #42](https://github.com/X-Guardian/AdfsDsc/issues/42)).
- AdfsGlobalAuthenticationPolicy
  - Added integration tests.
- AdfsOrganization
  - Added empty organization support
  ([issue #30](https://github.com/X-Guardian/AdfsDsc/issues/30)).
  - Added integration tests.
- AdfsProperties
  - Added integration tests.

### Removed

- AdfsProperties
  - Removed obsolete properties `PromptLoginFederation` and `PromptLoginFallbackAuthenticationType`
  ([issue #34](https://github.com/X-Guardian/AdfsDsc/issues/34)).
- AdfsFarmNode
  - Removed `Ensure` Parameter as `Remove-AdfsFarmNode` cmdlet is deprecated
  ([issue #36](https://github.com/X-Guardian/AdfsDsc/issues/36)).

## 1.0.0

### Added

- AdfsWebApiApplication
  - Added support for access control policy parameters
  ([issue #19](https://github.com/X-Guardian/AdfsDsc/issues/19)).
- AdfsRelyingPartyTrust
  - Added missing parameters
  ([issue #15](https://github.com/X-Guardian/AdfsDsc/issues/15)).
  - Added support for access control policies and parameters
  ([issue #2](https://github.com/X-Guardian/AdfsDsc/issues/2)).
  - Added support for SAML endpoints
  ([issue #3](https://github.com/X-Guardian/AdfsDsc/issues/3)).

## 0.1.38-alpha

- Initial release
