# This fork — additional fixes and features

This is a fork of [audric/SvxReflectorDashboard](https://github.com/audric/SvxReflectorDashboard) maintained by IZ7EXI (Maurizio, MP-BAT network, Barletta, Italy).

The `production-complete` branch includes everything from upstream `main` plus the fixes/features below, verified working in production. Individual, focused patches have also been submitted upstream as pull requests — see each item for status.

## DMR bridge protocol correctness

Found by comparing our traffic byte-for-byte against real HBLink3/YSF2DMR captures on a live network. Upstream `dmr_bridge/` had never been stress-tested this way before.

- **Keepalive**: repeater never sent proactive RPTPING, causing HBLink3-family masters to drop the peer after 15-30s of silence.
- **Self-echo filter**: matched on RptID instead of the active TX StreamID, silently dropping legitimate incoming audio on some masters.
- **EMB (burst sync)**: was left all-zero for voice bursts B-F instead of the real QR(16,7,6)-encoded field.
- **AMBE frame interleave**: was bit-interleaved instead of simply concatenated, corrupting all audio.
- **Voice LC Header/Terminator**: now real BPTC(196,96) + RS(12,9) FEC encoding, verified byte-for-byte against a real capture (was a placeholder before).
- **DMRD packet format**: extended to the 55-byte format some masters/tools (e.g. YSF2DMR) require.
- **Data Sync pattern**: fixed wrong bytes that silently broke cross-mode audio (e.g. XLX bridging DMR to D-STAR/YSF) even though same-protocol relay worked fine.
- **Audio packetization**: fixed 60ms Opus chunks (should be 20ms), which made some decoders (e.g. mumble_bridge) fail with "buffer too small" and silently drop all DMR->SVX audio.
- **TX pacing**: added a proper 20ms-ticker goroutine for the SVX->DMR direction.

*(Upstream PR: "Fix DMR Homebrew protocol correctness bugs + real MD380 vocoder")*

## Real MD380 vocoder

Replaces the software AMBE+2 vocoder with the real MD380 radio firmware running under qemu-arm emulation, for noticeably better audio quality.

*(Same upstream PR as above)*

## DMR ID -> callsign lookup + RPTO options

- DMR->SVX talker announcements and the dashboard now show the real caller's callsign (via radioid.net) instead of the bridge's own static identity.
- New RPTO options string support for masters that use it for static-TG pinning (e.g. ADN's DMR peer server: `TS2=22270;TIMER=0`).

*(Upstream PR: "Add DMR ID -> callsign lookup and RPTO static-TG options support")*

## USRP / EchoLink port publishing

Both bridge types created their Docker containers without publishing the ports they actually listen on. Worked transiently via conntrack, then silently failed once the tracked connection aged out or on any new inbound connection.

*(Upstream PR: "Fix USRP and EchoLink container port publishing")*

## BrandMeister / ODMRTP: missing DMR Voice Header

SVX->BM audio produced no carrier: the bridge only sent the REWIND SuperHeader (an optional display enhancement), never the real DMR Voice Header BrandMeister's routing core needs to open/route the call. Root-caused against BrandMeister's own Open DMR Terminal Protocol spec.

*(Upstream PR: "Fix ODMRTP: BrandMeister silently ignores SVX->DMR audio")*

## Real caller identity SVX<->DMR, including relayed via Mumble

- SVX->DMR: when a real SVX-side talker (not the bridge's own fixed identity) transmits, their real DMR ID is looked up (reverse radioid.net index) and used as the DMR frame's source ID — works directly and through Mumble relay (mumble_bridge publishes the real talker's name to Redis, since the SVX reflector protocol itself can't carry it through a relay).
- **Known limitation, not yet fixed here**: entering a DMR ID with an SSID suffix (9 digits, e.g. `222727201` — a valid convention for hotspot multi-connections) silently truncates to 24 bits with no warning, producing a garbage on-air ID. Root-caused; a form-side validation fix is a good next step for anyone picking this up.

*(Not yet submitted upstream as of this writing — a good next PR.)*

---

*Questions specific to this fork: reach out to IZ7EXI directly, or via IK1JNS.*
