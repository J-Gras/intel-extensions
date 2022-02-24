# Intel Extensions

This package provides extensions for Zeek's intelligence framework. It implements the following functionalities:

 * Remote management of intelligence items (using [broker](https://github.com/zeek/broker)).
 * Preservation of files associated with an intel hit.
 * ~~Intelligence expiration on per item basis.~~ Per item expiration has been moved to a [separate package](https://github.com/J-Gras/intel-expire).
 * ~~Support for `<IP>:<Port>` indicators.~~ Support for `<IP>:<Port>` indicators has been moved to a [separate package](https://github.com/J-Gras/intel-seen-more).

## Installation

The scripts are available as package for the [Zeek Package Manager](https://github.com/zeek/package-manager) and can be installed using the following command: `zkg install intel-extensions`

## Usage

None of the scripts is loaded by default, i.e. `zkg load intel-extensions` does not enable any functionality. To load all scripts, add the following to your `local.zeek`:
```
@load packages
@load packages/intel-extensions/remote_control.zeek
@load packages/intel-extensions/preserve_files.zeek

```
