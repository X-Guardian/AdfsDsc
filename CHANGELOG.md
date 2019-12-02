# Change log for AdfsDsc

The format is based on and uses the types of changes according to [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- AdfsContactPerson
  - Added empty contact support
  ([issue #27](https://github.com/X-Guardian/AdfsDsc/issues/27)).
- AdfsGlobalAuthenticationPolicy
  - Added integration tests.
- AdfsOrganization
  - Added empty organization support
  ([issue #30](https://github.com/X-Guardian/AdfsDsc/issues/30)).
  - Added integration tests.
- AdfsProperties
  - Added integration tests.

  ### Removed
  AdfdsProperties
  - Removed obsolete properties PromptLoginFederation and PromptLoginFallbackAuthenticationType
  ([issue #34](https://github.com/X-Guardian/AdfsDsc/issues/34)).
- AdfsFarmNode
  - Removed Ensure Parameter as Remove-AdfsFarmNode cmdlet is deprecated
  ([issue #36](https://github.com/X-Guardian/AdfsDsc/issues/36)).

- Changes to AdfsContactPerson
  - Added empty contact support ([issue #27](https://github.com/X-Guardian/AdfsDsc/issues/27)).
- Changes to AdfsGlobalAuthenticationPolicy
  - Added integration tests.

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
