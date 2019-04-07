# Intel Extensions

This package provides extensions for Bro's intelligence framework. It implements the following functionalities:

 * ~~Intelligence expiration on per item basis.~~ Per item expiration has been moved to a [separate package](https://github.com/J-Gras/intel-expire).
 * Remote deletion of intelligence items (requires [broker](https://github.com/bro/broker)).
 * Preservation of files associated with an intel hit.
 * Support for `<IP>:<Port>` indicators.

**Note:** Most of the scripts require Bro version 2.5.
