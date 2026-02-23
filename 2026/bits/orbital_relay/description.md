# Orbital Relay

An emergency relay node is still online after a key-rotation failure. The uplink accepts only framed packets with session integrity checks, and drops malformed traffic silently.

Blue team reports indicate the attacker never bypassed crypto directly, but still obtained execution in the relay process.

## Protocol Spec (Basic)
- Transport: raw TCP stream.
- Handshake: client must send exact ASCII `SYNCv3?` (7 bytes). Server replies with a 4-byte session value.
- Framing: each message is:
  - `chan` (`u8`)
  - `flags` (`u8`)
  - `len` (`u16`, little-endian)
  - `mac` (`u32`, little-endian)
  - `payload` (`len` bytes)
- Integrity: every frame must include a valid session-bound `mac`, or it is ignored.

## Channels
- `chan=3`: auth/setup channel.
- `chan=1`: diagnostics TLV channel.
- `chan=2`: ticket processing channel.
- `chan=9`: session teardown.

## TLV Format (chan=1)
- Payload is a sequence of:
  - `tag` (`u8`)
  - `size` (`u8`)
  - `value` (`size` bytes)
- Common tags:
  - `0x10`: route/config blob
  - `0x22`: level/state byte
  - `0x30`: 4-byte state token
  - `0x31`: 8-byte relay field
  - `0x40`: emit/apply action
