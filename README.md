![Public Beta banner](https://github.com/swiyu-admin-ch/swiyu-admin-ch.github.io/blob/main/assets/images/github-banner.jpg)

# DID WEBVH

[![Build and test](https://github.com/swiyu-admin-ch/did-webvh/actions/workflows/build-and-test.yml/badge.svg)](https://github.com/swiyu-admin-ch/did-webvh/actions/workflows/build-and-test.yml)
[![CodeQL Analysis](https://github.com/swiyu-admin-ch/did-webvh/actions/workflows/codeql-analyze.yml/badge.svg)](https://github.com/swiyu-admin-ch/did-webvh/actions/workflows/codeql-analyze.yml)
[![OSV-Scanner](https://github.com/swiyu-admin-ch/did-webvh/actions/workflows/osv-scanner.yml/badge.svg)](https://github.com/swiyu-admin-ch/did-webvh/actions/workflows/osv-scanner.yml)
[![rust-clippy analyze](https://github.com/swiyu-admin-ch/did-webvh/actions/workflows/clippy.yml/badge.svg)](https://github.com/swiyu-admin-ch/did-webvh/actions/workflows/clippy.yml)

An official Swiss Government project made by
the [Federal Office of Information Technology, Systems and Telecommunication FOITT](https://www.bit.admin.ch/)
as part of the electronic identity (e-ID) project.

**⚠️ PARTIAL IMPLEMENTATION ⚠️**

*Beware, this Rust library implements [DID Web + Verifiable History (did:webvh) v1.0 specification](https://identity.foundation/didwebvh/v1.0/)
only partially while focusing solely on [DID resolution](https://identity.foundation/didwebvh/v1.0/#read-resolve).*

## Using the library

The library can be used directly in Rust as is.

### Rust

The library can be used directly in Rust by adding the following dependency to your `Cargo.toml`:

````toml
[dependencies]
did_webvh = { git = "https://github.com/swiyu-admin-ch/did-webvh", branch = "main" }
````

## Benchmarks

All the relevant reports will be available [here](criterion/README.md).

## License

This project is licensed under the terms of the MIT license. See the [LICENSE](LICENSE.md) file for details.
