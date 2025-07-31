![Public Beta banner](https://github.com/e-id-admin/eidch-public-beta/blob/main/assets/github-banner-publicbeta.jpg)

# DID WEBVH

An official Swiss Government project made by
the [Federal Office of Information Technology, Systems and Telecommunication FOITT](https://www.bit.admin.ch/)
as part of the electronic identity (e-ID) project.

**⚠️ PARTIAL IMPLEMENTATION ⚠️**

*Beware, this Rust library implements [DID Web + Verifiable History (did:webvh) v1.0 specification](https://identity.foundation/didwebvh/v1.0/)
only partially while focusing solely on [DID resolution](https://identity.foundation/didwebvh/v1.0/#read-resolve).*

Although the library is still required by [DID Resolver](https://github.com/swiyu-admin-ch/didresolver), it will be kept
in the future as legacy and solely for the sake of backward compatibility, as [newer version of the specifications](https://identity.foundation/didwebvh/v1.0) is currently being implemented.

## Using the library

The library can be used either directly in Rust as is.

### Rust

The library can be used directly in Rust by adding the following dependency to your `Cargo.toml`:

````toml
[dependencies]
did_webvh = { git = "https://github.com/swiyu-admin-ch/did-webvh", branch = "main" }
````

## Benchmarks

All the relevant reports are available [here](criterion/README.md).

## License

This project is licensed under the terms of the MIT license. See the [LICENSE](LICENSE.md) file for details.
