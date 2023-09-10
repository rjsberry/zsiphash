# _zsiphash_

A port of the SipHash pseudo-random function [reference impl] in Zig. Unlike
the Zig standard library this library exposes a simple interface for tag
creation only.

Dual licensed under the 0BSD and MIT licenses.

[reference impl]: https://github.com/veorq/SipHash

## Usage

The files `siphash.zig` and `halfsiphash.zig` are standalone and can be copied
directly into your project.

