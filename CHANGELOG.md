# Changelog

## [0.0.5] PKCS11, LDAP and generated sender keys (2022-05-13)


### Features

* Refactor EllipticCurve code so that EC curve is created from certificate or public key. Interface support other EC curves
  besides secp384r1. No actual support for other curves implemented yet.
* Generate sender key pair to for recipient public key. Remove option to use pre-generated sender key pair
* Support for decrypting with private decryption key from PKCS11 (support for id-kaart)
* Support to download recipient esteid certificate from 
  [SK LDAP](https://www.skidsolutions.eu/repositoorium/ldap/esteid-ldap-kataloogi-kasutamine/)
* Documentation updates
* First version server OpenAPI specification


### Bug Fixes

* Use zlib compression instead of gzip compression
* Delete all files, when decryption fails (last file was not deleted)
* EllipticCurve was incorrectly created from fmkEncryption method not Details.EccPublicKey curve 
  (no actual error as both had same byte value).


## [0.0.4] First release (2022-04-22)

### Features

* Create/decrypt Cdoc2.0 files with software generated EC keys