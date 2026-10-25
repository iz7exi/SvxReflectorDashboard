package main

import (
	"crypto/sha256"
	"encoding/binary"
)

// MMDVM Homebrew protocol constants
const (
	DMRDPort = 62030

	// Packet signatures
	SigRPTL = "RPTL" // Login request
	SigRPTK = "RPTK" // Auth response
	SigRPTC = "RPTC" // Config
	SigRPTP  = "RPTPONG"
	SigMSTP  = "MSTPING"
	SigRPTG  = "RPTPING"
	SigMSTPO = "MSTPONG"
	SigMSTA = "MSTACK"
	SigMSTC = "MSTCL"  // Master close
	SigDMRD = "DMRD"   // Voice/data frame
	SigRPTA = "RPTACK" // Acknowledgement

	// DMRD frame size
	DMRDFrameSize = 53

	// DMR burst payload size
	BurstPayloadSize = 33

	// Voice frame types
	FrameTypeVoice     byte = 0x00
	FrameTypeVoiceSync byte = 0x01
	FrameTypeDataSync  byte = 0x02
	FrameTypeData      byte = 0x03

	// Call types
	CallTypeGroup   byte = 0x00
	CallTypePrivate byte = 0x01

	// Timeslots
	Timeslot1 byte = 0x00
	Timeslot2 byte = 0x01
)

// DMR AMBE+2 silence frame (9 bytes)
var AMBESilence = [9]byte{0xB9, 0xE8, 0x81, 0x48, 0x00, 0x00, 0x00, 0x00, 0x00}

// DMR voice sync pattern (embedded in burst A)
var VoiceSyncPattern = [7]byte{0x07, 0x55, 0xFD, 0x7D, 0xF7, 0x5F, 0x70}

// Voice LC header SYNC pattern
var DataSyncBS = [6]byte{0x6D, 0x5D, 0x7F, 0x77, 0xFD, 0x75}

// Voice terminator SYNC pattern
var DataSyncMS = [6]byte{0x77, 0xD5, 0x5F, 0x7D, 0xFD, 0x77}

// DMR AMBE bit interleave table per ETSI TS 102 361-1 Table B.22
// Maps the 216 AMBE payload bits (from the 264-bit burst, excluding SYNC)
// into 3 frames of 72 bits each.
//
// The burst structure is:
//   bits 0-107:   AMBE part 1 (108 bits)
//   bits 108-155: SYNC/EMB (48 bits) - not AMBE
//   bits 156-263: AMBE part 2 (108 bits)
//
// The 216 AMBE bits are de-interleaved into 3 x 72-bit frames.

// deinterleaveDMR extracts 3 AMBE frames from a 264-bit DMR burst.
// Input: 33 bytes (264 bits) of burst payload.
// Output: 3 x 9-byte AMBE frames.
func deinterleaveDMR(burst [33]byte) [3][9]byte {
	var frames [3][9]byte

	// Extract 264 bits into a bit array
	var bits [264]byte
	for i := 0; i < 264; i++ {
		bits[i] = (burst[i/8] >> (7 - uint(i%8))) & 1
	}

	// Collect AMBE payload bits (skip SYNC at 108-155)
	var ambe [216]byte
	copy(ambe[0:108], bits[0:108])
	copy(ambe[108:216], bits[156:264])

	// The 216 AMBE bits are three contiguous 72-bit AMBE+2 codewords
	// (frame 0 = bits 0-71, frame 1 = bits 72-143, frame 2 = bits
	// 144-215) -- concatenated, not bit-interleaved across frames.
	for i := 0; i < 216; i++ {
		frameIdx := i / 72
		bitPos := i % 72
		byteIdx := bitPos / 8
		bitOffset := 7 - uint(bitPos%8)
		if ambe[i] == 1 {
			frames[frameIdx][byteIdx] |= 1 << bitOffset
		}
	}

	return frames
}

// interleaveDMR builds a 264-bit burst payload from 3 AMBE frames and SYNC/EMB data.
// syncData: 48 bits (6 bytes) for the SYNC/EMB field at positions 108-155.
func interleaveDMR(frames [3][9]byte, syncData [6]byte) [33]byte {
	// Concatenate 3 AMBE+2 frames into 216 bits (frame 0 = bits 0-71,
	// frame 1 = bits 72-143, frame 2 = bits 144-215), not
	// bit-interleaved across frames.
	var ambe [216]byte
	for i := 0; i < 216; i++ {
		frameIdx := i / 72
		bitPos := i % 72
		byteIdx := bitPos / 8
		bitOffset := 7 - uint(bitPos%8)
		ambe[i] = (frames[frameIdx][byteIdx] >> bitOffset) & 1
	}

	// Build 264-bit burst
	var bits [264]byte
	copy(bits[0:108], ambe[0:108])
	// SYNC/EMB at bits 108-155
	for i := 0; i < 48; i++ {
		bits[108+i] = (syncData[i/8] >> (7 - uint(i%8))) & 1
	}
	copy(bits[156:264], ambe[108:216])

	// Pack bits into bytes
	var burst [33]byte
	for i := 0; i < 264; i++ {
		if bits[i] == 1 {
			burst[i/8] |= 1 << (7 - uint(i%8))
		}
	}

	return burst
}

// ExtractAMBE extracts 3 AMBE+2 frames from a 33-byte DMR burst payload.
func ExtractAMBE(payload [33]byte) [3][9]byte {
	return deinterleaveDMR(payload)
}

// embRowMasks are the 7 basis codewords of the ETSI TS 102 361-1
// Quadratic Residue (16,7,6) generator matrix (Annex B.3.2), each packed
// as a 16-bit value with bit 15 = column 0 (MSB-first) through bit 0 =
// column 15.
var embRowMasks = [7]uint16{
	0x804F, 0x411E, 0x21B7, 0x11E2, 0x09C9, 0x04E5, 0x0273,
}

// buildEMB computes the 16-bit Embedded Signalling (EMB) field per ETSI
// TS 102 361-1 9.1.2: 4-bit colour code, 1-bit PI, 2-bit LCSS, followed
// by 9 bits of Quadratic Residue (16,7,6) parity (Annex B.3.2). Returns
// the two 8-bit halves that flank the 32-bit embedded data field in a
// voice burst.
func buildEMB(colourCode, pi, lcss byte) (first8, last8 byte) {
	data := (colourCode&0x0F)<<3 | (pi&0x01)<<2 | (lcss & 0x03)
	var out uint16
	for i := 0; i < 7; i++ {
		if data&(1<<uint(6-i)) != 0 {
			out ^= embRowMasks[i]
		}
	}
	return byte(out >> 8), byte(out)
}

// BuildAMBEPayload builds a 33-byte burst payload from 3 AMBE frames.
// burstIndex: 0-5 (A-F) determines the SYNC/EMB pattern. colourCode is
// embedded in the EMB field for bursts B-F per ETSI TS 102 361-1 9.1.2.
// DMRCON_EXACT_EMB_PORT -- exact byte-for-byte port of dmrcon.c's own
// get_emb_data()/encode_qr1676() (a real, verified-working reference
// implementation), applied as a post-processing overlay on bytes
// 13/14/18/19 of the 33-byte burst payload. Used instead of trusting
// our own from-scratch buildEMB/interleaveDMR computation for this
// specific field, to guarantee an exact match with what BrandMeister
// is known to accept.
var qr1676Table = [128]uint16{
	0x0000, 0x0273, 0x04E5, 0x0696, 0x09C9, 0x0BBA, 0x0D2C, 0x0F5F, 0x11E2, 0x1391, 0x1507, 0x1774,
	0x182B, 0x1A58, 0x1CCE, 0x1EBD, 0x21B7, 0x23C4, 0x2552, 0x2721, 0x287E, 0x2A0D, 0x2C9B, 0x2EE8,
	0x3055, 0x3226, 0x34B0, 0x36C3, 0x399C, 0x3BEF, 0x3D79, 0x3F0A, 0x411E, 0x436D, 0x45FB, 0x4788,
	0x48D7, 0x4AA4, 0x4C32, 0x4E41, 0x50FC, 0x528F, 0x5419, 0x566A, 0x5935, 0x5B46, 0x5DD0, 0x5FA3,
	0x60A9, 0x62DA, 0x644C, 0x663F, 0x6960, 0x6B13, 0x6D85, 0x6FF6, 0x714B, 0x7338, 0x75AE, 0x77DD,
	0x7882, 0x7AF1, 0x7C67, 0x7E14, 0x804F, 0x823C, 0x84AA, 0x86D9, 0x8986, 0x8BF5, 0x8D63, 0x8F10,
	0x91AD, 0x93DE, 0x9548, 0x973B, 0x9864, 0x9A17, 0x9C81, 0x9EF2, 0xA1F8, 0xA38B, 0xA51D, 0xA76E,
	0xA831, 0xAA42, 0xACD4, 0xAEA7, 0xB01A, 0xB269, 0xB4FF, 0xB68C, 0xB9D3, 0xBBA0, 0xBD36, 0xBF45,
	0xC151, 0xC322, 0xC5B4, 0xC7C7, 0xC898, 0xCAEB, 0xCC7D, 0xCE0E, 0xD0B3, 0xD2C0, 0xD456, 0xD625,
	0xD97A, 0xDB09, 0xDD9F, 0xDFEC, 0xE0E6, 0xE295, 0xE403, 0xE670, 0xE92F, 0xEB5C, 0xEDCA, 0xEFB9,
	0xF104, 0xF377, 0xF5E1, 0xF792, 0xF8CD, 0xFABE, 0xFC28, 0xFE5B,
}

// applyDmrconEMB overlays get_emb_data()-equivalent bytes onto positions
// 13,14,18,19 of a 33-byte burst payload (bursts B-F only), preserving
// the other nibble at each position (AMBE audio data).
func applyDmrconEMB(payload *[33]byte, colourCode byte) {
	demb0 := (colourCode << 4) & 0xF0
	// lcss left at 0 (continuation), matching our existing buildEMB usage.
	value := uint32(demb0>>1) & 0x7F
	cksum := qr1676Table[value]
	demb0 = byte(cksum >> 8)
	demb1 := byte(cksum & 0xFF)

	payload[13] = (payload[13] & 0xF0) | ((demb0 >> 4) & 0x0F)
	payload[14] = (payload[14] & 0x0F) | ((demb0 << 4) & 0xF0)
	payload[18] = (payload[18] & 0xF0) | ((demb1 >> 4) & 0x0F)
	payload[19] = (payload[19] & 0x0F) | ((demb1 << 4) & 0xF0)
}

// DMRCON_EMBEDDED_LC_IN_AMBE -- embRaw carries a real fragmented LC
// (dmrcon.c-verified) for bursts 1-4; burst 5 gets the null/LCSS=0
// treatment exactly like before.
func BuildAMBEPayload(frames [3][9]byte, burstIndex int, colourCode byte, embRaw [128]bool) [33]byte {
	var syncData [6]byte
	var result [33]byte

	switch burstIndex {
	case 0: // Burst A: voice sync pattern
		// The voice sync pattern spans 48 bits at positions 108-155
		// Using the 7-byte pattern mapped to 6 bytes for the SYNC field
		copy(syncData[:], VoiceSyncPattern[:6])
		result = interleaveDMR(frames, syncData)
	default:
		result = interleaveDMR(frames, syncData)
		lcss := embeddedFragmentForBurst(&result, embRaw, burstIndex)
		first8, last8 := buildEMB(colourCode, 0, lcss)
		applyDmrconEMB(&result, colourCode)
		_ = first8
		_ = last8
	}

	return result
}

// BuildDMRDFrame builds a 53-byte DMRD voice frame.
func BuildDMRDFrame(seq byte, srcID, dstID uint32, rptID uint32, slot, callType byte,
	frameType byte, voiceSeq byte, streamID uint32, payload [33]byte) []byte {
	// Some masters/tools (e.g. YSF2DMR) require the extended 55-byte
	// Homebrew DMRD packet (53-byte standard frame + 2 trailing bytes,
	// commonly RSSI/BER) and hard-crash on any other length. We don't
	// have real signal-quality data to report, so the 2 extra bytes are
	// left zeroed -- harmless padding for receivers that ignore them.
	frame := make([]byte, DMRDFrameSize+2)

	// Signature
	copy(frame[0:4], SigDMRD)
	// Sequence
	frame[4] = seq
	// Source ID (24-bit BE)
	frame[5] = byte(srcID >> 16)
	frame[6] = byte(srcID >> 8)
	frame[7] = byte(srcID)
	// Destination ID (24-bit BE)
	frame[8] = byte(dstID >> 16)
	frame[9] = byte(dstID >> 8)
	frame[10] = byte(dstID)
	// Repeater ID (32-bit BE)
	binary.BigEndian.PutUint32(frame[11:15], rptID)
	// Flags: slot(1) | callType(1) | frameType(2) | voiceSeq/dataType(4)
	flags := (slot & 0x01) << 7
	flags |= (callType & 0x01) << 6
	flags |= (frameType & 0x03) << 4
	flags |= voiceSeq & 0x0F
	frame[15] = flags
	// Stream ID (32-bit BE)
	binary.BigEndian.PutUint32(frame[16:20], streamID)
	// Burst payload
	copy(frame[20:53], payload[:])

	return frame
}

// ParseDMRDFrame parses a DMRD voice frame.
type DMRDFrame struct {
	Seq       byte
	SrcID     uint32
	DstID     uint32
	RptID     uint32
	Slot      byte
	CallType  byte
	FrameType byte
	VoiceSeq  byte
	StreamID  uint32
	Payload   [33]byte
}

func ParseDMRDFrame(data []byte) *DMRDFrame {
	if len(data) < DMRDFrameSize {
		return nil
	}
	if string(data[0:4]) != SigDMRD {
		return nil
	}

	f := &DMRDFrame{
		Seq: data[4],
		SrcID: uint32(data[5])<<16 | uint32(data[6])<<8 | uint32(data[7]),
		DstID: uint32(data[8])<<16 | uint32(data[9])<<8 | uint32(data[10]),
		RptID: binary.BigEndian.Uint32(data[11:15]),
	}

	flags := data[15]
	f.Slot = (flags >> 7) & 0x01
	f.CallType = (flags >> 6) & 0x01
	f.FrameType = (flags >> 4) & 0x03
	f.VoiceSeq = flags & 0x0F
	f.StreamID = binary.BigEndian.Uint32(data[16:20])
	copy(f.Payload[:], data[20:53])

	return f
}

// IsVoice returns true if this is a voice frame.
func (f *DMRDFrame) IsVoice() bool {
	return f.FrameType == FrameTypeVoice || f.FrameType == FrameTypeVoiceSync
}

// IsTerminator returns true if this is a voice terminator frame.
func (f *DMRDFrame) IsTerminator() bool {
	return f.FrameType == FrameTypeDataSync && f.VoiceSeq == 0x02
}

// IsHeader returns true if this is a voice LC header frame.
func (f *DMRDFrame) IsHeader() bool {
	return f.FrameType == FrameTypeDataSync && f.VoiceSeq == 0x01
}

// BuildLoginPacket creates an RPTL login packet.
func BuildLoginPacket(rptID uint32) []byte {
	buf := make([]byte, 8)
	copy(buf[0:4], SigRPTL)
	binary.BigEndian.PutUint32(buf[4:8], rptID)
	return buf
}

// BuildAuthPacket creates an RPTK auth response.
// nonce: 4-byte nonce from RPTACK, password: shared secret.
func BuildAuthPacket(rptID uint32, nonce []byte, password string) []byte {
	// SHA256(nonce + password)
	h := sha256.New()
	h.Write(nonce)
	h.Write([]byte(password))
	digest := h.Sum(nil)

	buf := make([]byte, 4+4+32)
	copy(buf[0:4], SigRPTK)
	binary.BigEndian.PutUint32(buf[4:8], rptID)
	copy(buf[8:40], digest)
	return buf
}

// BuildConfigPacket creates an RPTC configuration packet.
// The config string is a fixed 302-byte field describing the repeater.
func BuildConfigPacket(rptID uint32, callsign string, rxFreq, txFreq string,
	txPower, colorCode, lat, lon, height string,
	location, description, url, softwareID, packageID string) []byte {
	buf := make([]byte, 302)
	copy(buf[0:4], SigRPTC)
	binary.BigEndian.PutUint32(buf[4:8], rptID)

	// Callsign (8 bytes, space-padded)
	cs := padRight(callsign, 8)
	copy(buf[8:16], cs)

	// RX Freq (9 bytes, zero-padded)
	copy(buf[16:25], padRight(rxFreq, 9))
	// TX Freq (9 bytes, zero-padded)
	copy(buf[25:34], padRight(txFreq, 9))
	// TX Power (2 bytes)
	copy(buf[34:36], padRight(txPower, 2))
	// Color Code (2 bytes)
	copy(buf[36:38], padRight(colorCode, 2))
	// Latitude (8 bytes)
	copy(buf[38:46], padRight(lat, 8))
	// Longitude (9 bytes)
	copy(buf[46:55], padRight(lon, 9))
	// Height (3 bytes)
	copy(buf[55:58], padRight(height, 3))
	// Location (20 bytes)
	copy(buf[58:78], padRight(location, 20))
	// Description (19 bytes)
	copy(buf[78:97], padRight(description, 19))
	// URL (124 bytes)
	copy(buf[97:221], padRight(url, 124))
	// Software ID (40 bytes)
	copy(buf[221:261], padRight(softwareID, 40))
	// Package ID (40 bytes)
	copy(buf[261:301], padRight(packageID, 40))
	// Null terminator
	buf[301] = 0

	return buf
}

// BuildConfigPacketBrandMeister creates an RPTC configuration packet using
// the exact field layout from the original DL5DI/G4KLX/DG1HT "DMRplus IPSC
// Protocol for HB repeater" spec (2015-07-26), which BrandMeister's own
// wiki cites as its own basis. That spec lists Description as 20 bytes,
// not the 19 the shared BuildConfigPacket above uses -- a boundary that
// TGIF and HBLink3 both tolerate being one byte short, but that
// BrandMeister's own master apparently validates strictly, rejecting the
// standard packet with "MSTNAK during config" even after a successful
// login. Kept as a separate function (like BuildConfigPacketTGIF) so
// HBLink3 and TGIF keep using the shared layout unchanged.
func BuildConfigPacketBrandMeister(rptID uint32, callsign string, rxFreq, txFreq string,
	txPower, colorCode, lat, lon, height string,
	location, description, url, softwareID, packageID string) []byte {
	buf := make([]byte, 302)
	copy(buf[0:4], SigRPTC)
	binary.BigEndian.PutUint32(buf[4:8], rptID)
	// Callsign (8 bytes, space-padded)
	cs := padRight(callsign, 8)
	copy(buf[8:16], cs)
	// RX Freq (9 bytes, zero-padded)
	copy(buf[16:25], padRight(rxFreq, 9))
	// TX Freq (9 bytes, zero-padded)
	copy(buf[25:34], padRight(txFreq, 9))
	// TX Power (2 bytes)
	copy(buf[34:36], padRight(txPower, 2))
	// Color Code (2 bytes)
	copy(buf[36:38], padRight(colorCode, 2))
	// Latitude (8 bytes)
	copy(buf[38:46], padRight(lat, 8))
	// Longitude (9 bytes)
	copy(buf[46:55], padRight(lon, 9))
	// Height (3 bytes)
	copy(buf[55:58], padRight(height, 3))
	// Location (20 bytes)
	copy(buf[58:78], padRight(location, 20))
	// Description (20 bytes -- one more than the shared function's 19)
	copy(buf[78:98], padRight(description, 20))
	// URL (124 bytes)
	copy(buf[98:222], padRight(url, 124))
	// Software ID (39 bytes -- one less than the shared function's 40, to
	// keep the same 302-byte total until/unless BrandMeister's separately
	// documented 306-byte figure turns out to need real extra content
	// rather than just this boundary correction).
	copy(buf[222:261], padRight(softwareID, 39))
	// Package ID (40 bytes)
	copy(buf[261:301], padRight(packageID, 40))
	// Null terminator
	buf[301] = 0

	return buf
}

// BuildConfigPacketTGIF creates an RPTC configuration packet using TGIF's
// own real field layout (303 bytes), verified byte-for-byte against TGIF's
// published server source (tgif.network/hblink.py). This differs from the
// standard 302-byte layout used by BuildConfigPacket (HBLink3, BrandMeister,
// ADN, etc.) by one extra 1-byte SLOTS field between DESCRIPTION and URL --
// using this on a master that expects the standard layout would misalign
// every field after DESCRIPTION, so this is intentionally a separate
// function rather than a modification to the shared one.
func BuildConfigPacketTGIF(rptID uint32, callsign string, rxFreq, txFreq string,
	txPower, colorCode, lat, lon, height string,
	location, description, slots, url, softwareID, packageID string) []byte {
	buf := make([]byte, 303)
	copy(buf[0:4], SigRPTC)
	binary.BigEndian.PutUint32(buf[4:8], rptID)
	// Callsign (8 bytes, space-padded)
	cs := padRight(callsign, 8)
	copy(buf[8:16], cs)
	// RX Freq (9 bytes, zero-padded)
	copy(buf[16:25], padRight(rxFreq, 9))
	// TX Freq (9 bytes, zero-padded)
	copy(buf[25:34], padRight(txFreq, 9))
	// TX Power (2 bytes)
	copy(buf[34:36], padRight(txPower, 2))
	// Color Code (2 bytes)
	copy(buf[36:38], padRight(colorCode, 2))
	// Latitude (8 bytes)
	copy(buf[38:46], padRight(lat, 8))
	// Longitude (9 bytes)
	copy(buf[46:55], padRight(lon, 9))
	// Height (3 bytes)
	copy(buf[55:58], padRight(height, 3))
	// Location (20 bytes)
	copy(buf[58:78], padRight(location, 20))
	// Description (19 bytes)
	copy(buf[78:97], padRight(description, 19))
	// Slots (1 byte) -- present on TGIF's real layout, absent from the
	// standard one.
	copy(buf[97:98], padRight(slots, 1))
	// URL (124 bytes)
	copy(buf[98:222], padRight(url, 124))
	// Software ID (40 bytes)
	copy(buf[222:262], padRight(softwareID, 40))
	// Package ID (40 bytes)
	copy(buf[262:302], padRight(packageID, 40))
	// Null terminator
	buf[302] = 0

	return buf
}

// BuildConfigPacketBrandMeisterV2 creates a 302-byte RPTC packet matching
// dmrcon.c's own verified-working format byte-for-byte: same field layout
// as BuildConfigPacketTGIF (with the 1-byte field between Description and
// URL), but WITHOUT a trailing null terminator -- dmrcon.c's own send
// length is exactly 302, ending right after the 40-byte Package ID, one
// byte shorter than BuildConfigPacketTGIF's 303 (which has an explicit
// buf[302]=0 terminator TGIF's own master expects but BrandMeister's
// apparently doesn't).
func BuildConfigPacketBrandMeisterV2(rptID uint32, callsign string, rxFreq, txFreq string,
	txPower, colorCode, lat, lon, height string,
	location, description, slots, url, softwareID, packageID string) []byte {
	buf := make([]byte, 302)
	copy(buf[0:4], SigRPTC)
	binary.BigEndian.PutUint32(buf[4:8], rptID)
	cs := padRight(callsign, 8)
	copy(buf[8:16], cs)
	copy(buf[16:25], padRight(rxFreq, 9))
	copy(buf[25:34], padRight(txFreq, 9))
	copy(buf[34:36], padRight(txPower, 2))
	copy(buf[36:38], padRight(colorCode, 2))
	copy(buf[38:46], padRight(lat, 8))
	copy(buf[46:55], padRight(lon, 9))
	copy(buf[55:58], padRight(height, 3))
	copy(buf[58:78], padRight(location, 20))
	copy(buf[78:97], padRight(description, 19))
	copy(buf[97:98], padRight(slots, 1))
	copy(buf[98:222], padRight(url, 124))
	// BM_REVERT_PADLEFT_TO_PADRIGHT -- a real captured, BrandMeister-accepted
	// packet from dmrcon.c proved these should be left-justified (padRight)
	// like the DL5DI spec's other fields, not right-justified as an
	// earlier misreading of DMRGateway's own sprintf format assumed.
	copy(buf[222:262], padRight(softwareID, 40))
	copy(buf[262:302], padRight(packageID, 40))
	// No null terminator -- buffer ends here at exactly 302 bytes.
	return buf
}

// DMRCON_EMBEDDED_LC_PORT -- exact port of dmrcon.c's encode_embedded_data()
// / get_embedded_data(): the real, working reference embeds an actual
// fragmented LC (matching the voice header's own dst/src) across bursts
// B-E (LCSS 1,3,3,2), not a null/LCSS=0 field like our own buildEMB did
// for every burst. Burst F (index 5) still gets the null treatment.

// encode16114 computes the 5 parity bits of a (16,11,4) Hamming-like
// code in place, matching dmrcon.c's encode16114() exactly.
func encode16114(d *[16]bool) {
	d[11] = d[0] != d[1] != d[2] != d[3] != d[5] != d[7] != d[8]
	d[12] = d[1] != d[2] != d[3] != d[4] != d[6] != d[8] != d[9]
	d[13] = d[2] != d[3] != d[4] != d[5] != d[7] != d[9] != d[10]
	d[14] = d[0] != d[1] != d[2] != d[4] != d[6] != d[7] != d[10]
	d[15] = d[0] != d[2] != d[5] != d[6] != d[8] != d[9] != d[10]
}

// DUP_FUNCS_REMOVED -- byteToBitsBE/bitsToByteBE already exist in bptc.go, reused here.

// buildEmbRaw computes the 128-bit embedded-signalling raw array for a
// group voice call, exactly matching dmrcon.c's encode_embedded_data(),
// for later fragmentation across bursts B-E via embeddedFragmentForBurst.
func buildEmbRaw(dstID, srcID uint32) [128]bool {
	// lc_get_data_bits: 9-byte LC (FLCO=0 group voice, FID=0, options=0,
	// dst 3 bytes, src 3 bytes), converted to 72 bits.
	lcBytes := [9]byte{0, 0, 0,
		byte(dstID >> 16), byte(dstID >> 8), byte(dstID),
		byte(srcID >> 16), byte(srcID >> 8), byte(srcID)}
	var embData [72]bool
	for i, bb := range lcBytes {
		byteToBitsBE(bb, embData[i*8:i*8+8])
	}

	// 5-bit CRC: sum of the 9 bytes mod 31.
	var total uint16
	for i := 0; i < 72; i += 8 {
		total += uint16(bitsToByteBE(embData[i : i+8]))
	}
	crc := total % 31

	var data [128]bool
	data[106] = crc&0x01 == 0x01
	data[90] = crc&0x02 == 0x02
	data[74] = crc&0x04 == 0x04
	data[58] = crc&0x08 == 0x08
	data[42] = crc&0x10 == 0x10

	b := 0
	place := func(start, count int) {
		for a := start; a < start+count; a++ {
			data[a] = embData[b]
			b++
		}
	}
	place(0, 11)
	place(16, 11)
	place(32, 10)
	place(48, 10)
	place(64, 10)
	place(80, 10)
	place(96, 10)

	for a := 0; a < 112; a += 16 {
		var chunk [16]bool
		copy(chunk[:], data[a:a+16])
		encode16114(&chunk)
		copy(data[a:a+16], chunk[:])
	}
	for a := 0; a < 16; a++ {
		data[a+112] = data[a] != data[a+16] != data[a+32] != data[a+48] != data[a+64] != data[a+80] != data[a+96]
	}

	var embRaw [128]bool
	bb := 0
	for a := 0; a < 128; a++ {
		embRaw[a] = data[bb]
		bb += 16
		if bb > 127 {
			bb -= 127
		}
	}
	return embRaw
}

// embeddedFragmentForBurst extracts the 32-bit fragment for burst
// position n (1-4 real fragments, 0 or >=5 null) matching dmrcon.c's
// get_embedded_data(), overlaying it onto payload[14:19] and returning
// the LCSS value to feed into buildEMB.
func embeddedFragmentForBurst(payload *[33]byte, embRaw [128]bool, n int) byte {
	if n >= 1 && n < 5 {
		n--
		var bits [40]bool
		copy(bits[4:], embRaw[n*32:n*32+32])
		var bytes5 [5]byte
		bytes5[0] = bitsToByteBE(bits[0:8])
		bytes5[1] = bitsToByteBE(bits[8:16])
		bytes5[2] = bitsToByteBE(bits[16:24])
		bytes5[3] = bitsToByteBE(bits[24:32])
		bytes5[4] = bitsToByteBE(bits[32:40])
		payload[14] = (payload[14] & 0xF0) | (bytes5[0] & 0x0F)
		payload[15] = bytes5[1]
		payload[16] = bytes5[2]
		payload[17] = bytes5[3]
		payload[18] = (payload[18] & 0x0F) | (bytes5[4] & 0xF0)
		switch n {
		case 0:
			return 1
		case 3:
			return 2
		default:
			return 3
		}
	}
	payload[14] &= 0xF0
	payload[15] = 0
	payload[16] = 0
	payload[17] = 0
	payload[18] &= 0x0F
	return 0
}

// SigRPTO is the RPTO (repeater options) command signature.
const SigRPTO = "RPTO"

// BuildOptionsPacket creates an RPTO packet carrying a free-form options
// string, sent after RPTC config is accepted. Some masters (e.g. ADN's
// DMR peer server) parse this for static-TG pinning, e.g. "TS2=22270;TIMER=0".
func BuildOptionsPacket(rptID uint32, options string) []byte {
	buf := make([]byte, 8+len(options))
	copy(buf[0:4], SigRPTO)
	binary.BigEndian.PutUint32(buf[4:8], rptID)
	copy(buf[8:], options)
	return buf
}

// BuildPongPacket creates an RPTPONG response to MSTPING.
func BuildPongPacket(rptID uint32) []byte {
	buf := make([]byte, 11)
	copy(buf[0:7], SigRPTP)
	binary.BigEndian.PutUint32(buf[7:11], rptID)
	return buf
}

// BuildPingPacket creates an RPTPING keepalive sent proactively by the
// repeater/client to the master, as required by the MMDVM Homebrew
// protocol (e.g. HBLink3). The master should reply with MSTPONG.
func BuildPingPacket(rptID uint32) []byte {
	buf := make([]byte, 11)
	copy(buf[0:7], SigRPTG)
	binary.BigEndian.PutUint32(buf[7:11], rptID)
	return buf
}

// RPTCL_DISCONNECT_ADDED -- BuildClosePacket sends the Homebrew protocol's
// "RPTCL" (Repeater Close) signature, telling the master we're
// disconnecting cleanly. Close() previously just closed the local UDP
// socket without notifying the master at all, and every "docker rm -f"
// today (SIGKILL, bypassing even that) never gave the master ANY signal
// -- BrandMeister would have relied solely on a ping timeout to clean up
// our old session, possibly leaving stale sessions that interfered with
// routing for the same repeater ID across our many test cycles today.
func BuildClosePacket(rptID uint32) []byte {
	buf := make([]byte, 9)
	copy(buf[0:5], "RPTCL")
	binary.BigEndian.PutUint32(buf[5:9], rptID)
	return buf
}

// BuildVoiceLCHeader builds a DMRD frame for a Voice LC Header.
// This signals the start of a voice call.
func buildFullLC(dstID, srcID uint32, callType byte) [12]byte {
	var lc [9]byte
	if callType == CallTypePrivate {
		lc[0] = 0x03 // FLCO = Unit to Unit Voice Call
	}
	lc[3] = byte(dstID >> 16)
	lc[4] = byte(dstID >> 8)
	lc[5] = byte(dstID)
	lc[6] = byte(srcID >> 16)
	lc[7] = byte(srcID >> 8)
	lc[8] = byte(srcID)

	parity := rs129Encode(lc[:])

	var full [12]byte
	copy(full[0:9], lc[:])
	// RS(12,9) parity bytes are stored reversed: in[9]=parity[2],
	// in[10]=parity[1], in[11]=parity[0] (matches CRS129::check).
	full[9] = parity[2]
	full[10] = parity[1]
	full[11] = parity[0]
	return full
}

func BuildVoiceLCHeader(seq byte, srcID, dstID, rptID, streamID uint32, slot, callType byte) []byte {
	var payload [33]byte
	full := buildFullLC(dstID, srcID, callType)
	bptc19696Encode(full, &payload)
	// Data Sync pattern (BS_SOURCED_DATA_SYNC, verified byte-for-byte
	// against a real HBLink3/YSF2DMR capture): occupies payload[12]'s low
	// 6 bits, all of payload[13:19], and payload[19]. Applied after the
	// BPTC encode so it doesn't get clobbered, and OR'd (not assigned) on
	// payload[12] to preserve the BPTC tail bits already written there.
	payload[12] |= 0x04
	copy(payload[13:19], DataSyncBS[:])
	payload[19] = 0x7E
	return BuildDMRDFrame(seq, srcID, dstID, rptID, slot, callType,
		FrameTypeDataSync, 0x01, streamID, payload)
}

// BuildVoiceTerminator builds a DMRD frame for a Voice Terminator with LC.
func BuildVoiceTerminator(seq byte, srcID, dstID, rptID, streamID uint32, slot, callType byte) []byte {
	var payload [33]byte
	full := buildFullLC(dstID, srcID, callType)
	bptc19696Encode(full, &payload)
	payload[12] |= 0x04
	copy(payload[13:19], DataSyncBS[:])
	payload[19] = 0x7E
	return BuildDMRDFrame(seq, srcID, dstID, rptID, slot, callType,
		FrameTypeDataSync, 0x02, streamID, payload)
}

func padRight(s string, length int) string {
	for len(s) < length {
		s += " "
	}
	if len(s) > length {
		s = s[:length]
	}
	return s
}

// padLeft matches DMRGateway's own real config-building sprintf format
// ("%40.40s" without a "-" flag = right-justified, left-padded with
// spaces) for Software ID and Package ID specifically -- our other
// fields use padRight (left-justified) matching the rest of the spec,
// but these two apparently need to match this specific real behavior.
func padLeft(s string, length int) string {
	if len(s) > length {
		s = s[:length]
	}
	for len(s) < length {
		s = " " + s
	}
	return s
}
