// The contents of this file is dual-licensed under the MIT or 0BSD license.

const std = @import("std");

const debug = std.debug;
const fmt = std.fmt;
const math = std.math;
const mem = std.mem;

/// An implementation of HalfSipHash.
///
/// This is intended to be used for hash tables and is not recommended for
/// cryptographic applications.
pub fn HalfSipHasher(
    comptime c_rounds: usize,
    comptime d_rounds: usize,
    comptime tag_type: type,
) type {
    comptime {
        if (tag_type != u32 and tag_type != u64) {
            @compileError(fmt.comptimePrint(
                "{} is not a valid tag type (must be u32 or u64)",
                .{@typeName(tag_type)},
            ));
        }
    }

    return struct {
        const Self = @This();

        k0: u32,
        k1: u32,
        state: State,

        /// Initializes the hasher with the provided keys.
        pub inline fn init(k0: u32, k1: u32) Self {
            var hasher = Self{ .k0 = k0, .k1 = k1, .state = .{
                .v0 = 0,
                .v2 = 0x6c796765,
                .v1 = 0,
                .v3 = 0x74656462,
            } };

            hasher.state.v3 ^= k1;
            hasher.state.v2 ^= k0;
            hasher.state.v1 ^= k1;
            hasher.state.v0 ^= k0;

            if (tag_type == u64) {
                hasher.state.v1 ^= 0xee;
            }

            return hasher;
        }

        /// Hashes the data and returns the result.
        pub fn hash(self: Self, data: []const u8) tag_type {
            var hasher = self;
            var tag: [@sizeOf(tag_type)]u8 = undefined;

            debug.assert(data.len <= @as(usize, math.maxInt(u32)));
            const len: u32 = @truncate(data.len);
            var b = (len & 0xff) << 24;

            for (0..len >> 2) |i| {
                const m = mem.readIntLittle(u32, data[i << 2 ..][0..4]);
                hasher.state.v3 ^= m;
                inline for (0..c_rounds) |_| {
                    @call(.always_inline, sipround, .{&hasher.state});
                }
                hasher.state.v0 ^= m;
            }

            const left = len & 3;
            const last = len & ~@as(u32, 3);

            if (left > 2) {
                b |= @as(u32, data[last + 2]) << 16;
            }
            if (left > 1) {
                b |= @as(u32, data[last + 1]) << 8;
            }
            if (left > 0) {
                b |= @as(u32, data[last]);
            }

            hasher.state.v3 ^= b;
            inline for (0..c_rounds) |_| {
                @call(.always_inline, sipround, .{&hasher.state});
            }
            hasher.state.v0 ^= b;

            if (tag_type == u64) {
                hasher.state.v2 ^= 0xee;
            } else {
                hasher.state.v2 ^= 0xff;
            }

            inline for (0..d_rounds) |_| {
                @call(.always_inline, sipround, .{&hasher.state});
            }

            mem.writeIntLittle(
                u32,
                tag[0..4],
                hasher.state.v1 ^ hasher.state.v3,
            );

            if (tag_type == u32) {
                return @bitCast(tag);
            }

            hasher.state.v1 ^= 0xdd;
            inline for (0..d_rounds) |_| {
                @call(.always_inline, sipround, .{&hasher.state});
            }

            mem.writeIntLittle(
                u32,
                tag[4..8],
                hasher.state.v1 ^ hasher.state.v3,
            );

            return @bitCast(tag);
        }
    };
}

/// The internal state of the hasher.
const State = struct {
    v0: u32,
    v2: u32,
    v1: u32,
    v3: u32,
};

/// Performs a compression round.
inline fn sipround(state: *State) void {
    state.v0 = @addWithOverflow(state.v0, state.v1)[0];
    state.v1 = math.rotl(u32, state.v1, 5);
    state.v1 ^= state.v0;
    state.v0 = math.rotl(u32, state.v0, 16);
    state.v2 = @addWithOverflow(state.v2, state.v3)[0];
    state.v3 = math.rotl(u32, state.v3, 8);
    state.v3 ^= state.v2;
    state.v0 = @addWithOverflow(state.v0, state.v3)[0];
    state.v3 = math.rotl(u32, state.v3, 7);
    state.v3 ^= state.v0;
    state.v2 = @addWithOverflow(state.v2, state.v1)[0];
    state.v1 = math.rotl(u32, state.v1, 13);
    state.v1 ^= state.v2;
    state.v2 = math.rotl(u32, state.v2, 16);
}
