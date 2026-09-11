---
livekit: minor
livekit-ffi: minor
---

Report how a received data packet was encrypted: `RoomEvent::DataReceived` and the FFI `UserPacket` carry its `encryption_type`. A room with encryption enabled still delivers a packet its sender published in the clear, as `EncryptionType::None`, so a receiver that requires encryption can refuse it.
