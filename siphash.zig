// The contents of this file is dual-licensed under the MIT or 0BSD license.

const std = @import("std");

const debug = std.debug;
const fmt = std.fmt;
const math = std.math;
const mem = std.mem;

/// An implementation of SipHash.
///
/// This is intended to be used for hash tables and is not recommended for
/// cryptographic applications.
pub fn SipHasher(
    comptime c_rounds: usize,
    comptime d_rounds: usize,
    comptime tag_type: type,
) type {
    comptime {
        if (tag_type != u64 and tag_type != u128) {
            @compileError(fmt.comptimePrint(
                "{} is not a valid tag type (must be u64 or u128)",
                .{@typeName(tag_type)},
            ));
        }
    }

    return struct {
        const Self = @This();

        k0: u64,
        k1: u64,
        state: State,

        /// Initializes the hasher with the provided keys.
        pub inline fn init(k0: u64, k1: u64) Self {
            var hasher = Self{ .k0 = k0, .k1 = k1, .state = .{
                .v0 = 0x736f6d6570736575,
                .v2 = 0x6c7967656e657261,
                .v1 = 0x646f72616e646f6d,
                .v3 = 0x7465646279746573,
            } };

            hasher.state.v3 ^= k1;
            hasher.state.v2 ^= k0;
            hasher.state.v1 ^= k1;
            hasher.state.v0 ^= k0;

            if (tag_type == u128) {
                hasher.state.v1 ^= 0xee;
            }

            return hasher;
        }

        /// Hashes the data and returns the result.
        pub fn hash(self: Self, data: []const u8) tag_type {
            var hasher = self;
            var tag: [@sizeOf(tag_type)]u8 = undefined;

            debug.assert(data.len <= @as(usize, math.maxInt(u64)));
            const len: u64 = @truncate(data.len);
            var b = (len & 0xff) << 56;

            for (0..len >> 3) |i| {
                const m = mem.readIntLittle(u64, data[i << 3 ..][0..8]);
                hasher.state.v3 ^= m;
                inline for (0..c_rounds) |_| {
                    @call(.always_inline, sipround, .{&hasher.state});
                }
                hasher.state.v0 ^= m;
            }

            const left = len & 7;
            const last = len & ~@as(u64, 7);

            if (left > 6) {
                b |= @as(u64, data[last + 6]) << 48;
            }
            if (left > 5) {
                b |= @as(u64, data[last + 5]) << 40;
            }
            if (left > 4) {
                b |= @as(u64, data[last + 4]) << 32;
            }
            if (left > 3) {
                b |= @as(u64, data[last + 3]) << 24;
            }
            if (left > 2) {
                b |= @as(u64, data[last + 2]) << 16;
            }
            if (left > 1) {
                b |= @as(u64, data[last + 1]) << 8;
            }
            if (left > 0) {
                b |= @as(u64, data[last]);
            }

            hasher.state.v3 ^= b;
            inline for (0..c_rounds) |_| {
                @call(.always_inline, sipround, .{&hasher.state});
            }
            hasher.state.v0 ^= b;

            if (tag_type == u128) {
                hasher.state.v2 ^= 0xee;
            } else {
                hasher.state.v2 ^= 0xff;
            }

            inline for (0..d_rounds) |_| {
                @call(.always_inline, sipround, .{&hasher.state});
            }

            mem.writeIntLittle(
                u64,
                tag[0..8],
                hasher.state.v0 ^
                    hasher.state.v1 ^
                    hasher.state.v2 ^
                    hasher.state.v3,
            );

            if (tag_type == u64) {
                return @bitCast(tag);
            }

            hasher.state.v1 ^= 0xdd;
            inline for (0..d_rounds) |_| {
                @call(.always_inline, sipround, .{&hasher.state});
            }

            mem.writeIntLittle(
                u64,
                tag[8..16],
                hasher.state.v0 ^
                    hasher.state.v1 ^
                    hasher.state.v2 ^
                    hasher.state.v3,
            );

            return @bitCast(tag);
        }
    };
}

/// The internal state of the hasher.
const State = struct {
    v0: u64,
    v2: u64,
    v1: u64,
    v3: u64,
};

/// Performs a compression round.
inline fn sipround(state: *State) void {
    state.v0 = @addWithOverflow(state.v0, state.v1)[0];
    state.v1 = math.rotl(u64, state.v1, 13);
    state.v1 ^= state.v0;
    state.v0 = math.rotl(u64, state.v0, 32);
    state.v2 = @addWithOverflow(state.v2, state.v3)[0];
    state.v3 = math.rotl(u64, state.v3, 16);
    state.v3 ^= state.v2;
    state.v0 = @addWithOverflow(state.v0, state.v3)[0];
    state.v3 = math.rotl(u64, state.v3, 21);
    state.v3 ^= state.v0;
    state.v2 = @addWithOverflow(state.v2, state.v1)[0];
    state.v1 = math.rotl(u64, state.v1, 17);
    state.v1 ^= state.v2;
    state.v2 = math.rotl(u64, state.v2, 32);
}
