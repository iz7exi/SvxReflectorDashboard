package main

import (
	"bufio"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
)

// dmrIDTable maps DMR radio IDs to callsigns, loaded once at startup from
// the radioid.net user database (baked into the image at build time).
var (
	dmrIDTable   map[uint32]string
	dmrIDTableMu sync.RWMutex

	// callsignToID is the reverse of dmrIDTable (callsign -> DMR ID),
	// keyed uppercase. Used to find the real DMR ID of an SVX-side talker
	// (identified by their SvxLink callsign) so the SVX->DMR direction can
	// report the actual speaker instead of always using the bridge's own
	// fixed configured DMR ID.
	callsignToID   map[string]uint32
	callsignToIDMu sync.RWMutex
)

// loadDMRIDTable parses the radioid.net CSV (RADIO_ID,CALLSIGN,...) into
// an in-memory lookup table. Errors are logged but non-fatal: the bridge
// falls back to numeric "DMR-<id>" labels if the table is unavailable.
func loadDMRIDTable(path string) {
	f, err := os.Open(path)
	if err != nil {
		log.Printf("[DMRID] Could not open %s: %v (callsign lookup disabled)", path, err)
		return
	}
	defer f.Close()

	table := make(map[uint32]string)
	revTable := make(map[string]uint32)
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	first := true
	for scanner.Scan() {
		line := scanner.Text()
		if first {
			first = false
			continue // skip CSV header row
		}
		parts := strings.SplitN(line, ",", 3)
		if len(parts) < 2 {
			continue
		}
		id, err := strconv.ParseUint(parts[0], 10, 32)
		if err != nil {
			continue
		}
		cs := strings.TrimSpace(parts[1])
		if cs == "" {
			continue
		}
		table[uint32(id)] = cs
		revTable[strings.ToUpper(cs)] = uint32(id)
	}
	if err := scanner.Err(); err != nil {
		log.Printf("[DMRID] Error reading %s: %v", path, err)
	}

	dmrIDTableMu.Lock()
	dmrIDTable = table
	dmrIDTableMu.Unlock()
	callsignToIDMu.Lock()
	callsignToID = revTable
	callsignToIDMu.Unlock()
	log.Printf("[DMRID] Loaded %d DMR ID -> callsign entries from %s", len(table), path)
}

// lookupDMRIDByCallsign returns the DMR radio ID registered for a
// callsign (case-insensitive), or ok=false if not found or the table
// hasn't loaded yet.
func lookupDMRIDByCallsign(callsign string) (uint32, bool) {
	callsignToIDMu.RLock()
	id, ok := callsignToID[strings.ToUpper(callsign)]
	callsignToIDMu.RUnlock()
	return id, ok
}

// lookupDMRCallsign returns the callsign for a DMR radio ID, or a
// "DMR-<id>" fallback label if the ID isn't found (or the table hasn't
// loaded yet).
func lookupDMRCallsign(id uint32) string {
	dmrIDTableMu.RLock()
	cs, ok := dmrIDTable[id]
	dmrIDTableMu.RUnlock()
	if ok {
		return cs
	}
	return "DMR-" + strconv.FormatUint(uint64(id), 10)
}
