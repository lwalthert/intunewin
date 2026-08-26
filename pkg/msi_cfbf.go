package pkg

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"unicode/utf16"

	"github.com/lwalthert/intunewin/internal/data"
)

const (
	cfbfMagic = "\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"

	fatEndSector   = 0xFFFFFFFE
	fatFreeSector  = 0xFFFFFFFF
	fatFatSector   = 0xFFFFFFFD
	fatDiFatSector = 0xFFFFFFFC

	objStorage = 1
	objStream  = 2
	objRoot    = 5
)

// cfbfDirEntry represents a directory entry in the CFBF container.
type cfbfDirEntry struct {
	Name           string
	EntryType      byte
	StartingSector uint32
	StreamSize     uint64
}

// cfbfReader reads Compound File Binary Format (CFBF/OLE2) files.
type cfbfReader struct {
	ra             io.ReaderAt
	sectorSize     int
	miniSectorSize int
	miniCutoff     uint64

	fat     []uint32
	miniFAT []uint32

	entries    []cfbfDirEntry
	miniStream []byte
}

func openCFBF(ra io.ReaderAt) (*cfbfReader, error) {
	header := make([]byte, 512)
	if _, err := ra.ReadAt(header, 0); err != nil {
		return nil, fmt.Errorf("read cfbf header: %w", err)
	}

	if string(header[:8]) != cfbfMagic {
		return nil, errors.New("invalid cfbf magic header")
	}

	sectorShift := binary.LittleEndian.Uint16(header[30:32])
	miniSectorShift := binary.LittleEndian.Uint16(header[32:34])
	numFATSectors := binary.LittleEndian.Uint32(header[44:48])
	firstDirSector := binary.LittleEndian.Uint32(header[48:52])
	miniCutoff := binary.LittleEndian.Uint32(header[56:60])
	firstMiniFATSector := binary.LittleEndian.Uint32(header[60:64])
	numMiniFATSectors := binary.LittleEndian.Uint32(header[64:68])
	firstDIFATSector := binary.LittleEndian.Uint32(header[68:72])
	numDIFATSectors := binary.LittleEndian.Uint32(header[72:76])

	sectorSize := 1 << sectorShift
	miniSectorSize := 1 << miniSectorShift

	r := &cfbfReader{
		ra:             ra,
		sectorSize:     sectorSize,
		miniSectorSize: miniSectorSize,
		miniCutoff:     uint64(miniCutoff),
	}

	// 1. Read DIFAT
	var difat []uint32
	for i := range 109 {
		sec := binary.LittleEndian.Uint32(header[76+i*4 : 80+i*4])
		if sec == fatFreeSector || sec == fatEndSector {
			break
		}
		difat = append(difat, sec)
	}

	curDIFATSector := firstDIFATSector
	entriesPerSector := sectorSize / 4
	for i := uint32(0); i < numDIFATSectors && curDIFATSector != fatEndSector && curDIFATSector != fatFreeSector; i++ {
		secBuf := make([]byte, sectorSize)
		if err := r.readSector(curDIFATSector, secBuf); err != nil {
			return nil, fmt.Errorf("read difat sector: %w", err)
		}
		for j := 0; j < entriesPerSector-1; j++ {
			sec := binary.LittleEndian.Uint32(secBuf[j*4 : (j+1)*4])
			if sec == fatFreeSector || sec == fatEndSector {
				break
			}
			difat = append(difat, sec)
		}
		curDIFATSector = binary.LittleEndian.Uint32(secBuf[(entriesPerSector-1)*4 : entriesPerSector*4])
	}

	// 2. Read FAT
	fat := make([]uint32, int(numFATSectors)*entriesPerSector)
	for i, fatSec := range difat {
		if uint32(i) >= numFATSectors {
			break
		}
		secBuf := make([]byte, sectorSize)
		if err := r.readSector(fatSec, secBuf); err != nil {
			return nil, fmt.Errorf("read fat sector: %w", err)
		}
		for j := range entriesPerSector {
			fat[i*entriesPerSector+j] = binary.LittleEndian.Uint32(secBuf[j*4 : (j+1)*4])
		}
	}
	r.fat = fat

	// 3. Read Directory Entries
	dirData, err := r.readChain(firstDirSector, fat)
	if err != nil {
		return nil, fmt.Errorf("read directory chain: %w", err)
	}

	for i := 0; i+128 <= len(dirData); i += 128 {
		entryBytes := dirData[i : i+128]
		nameLen := binary.LittleEndian.Uint16(entryBytes[64:66])
		entryType := entryBytes[66]

		if entryType == 0 {
			continue
		}

		var rawName []uint16
		for j := 0; j < 64 && j+2 <= int(nameLen); j += 2 {
			u := binary.LittleEndian.Uint16(entryBytes[j : j+2])
			if u == 0 {
				break
			}
			rawName = append(rawName, u)
		}

		name := decodeMSIStreamName(rawName)
		startSec := binary.LittleEndian.Uint32(entryBytes[116:120])
		streamSize := binary.LittleEndian.Uint64(entryBytes[120:128])
		if sectorShift == 9 {
			streamSize = streamSize & 0xFFFFFFFF
		}

		r.entries = append(r.entries, cfbfDirEntry{
			Name:           name,
			EntryType:      entryType,
			StartingSector: startSec,
			StreamSize:     streamSize,
		})
	}

	// 4. Read MiniFAT & MiniStream (Root entry is entries[0])
	if len(r.entries) > 0 && r.entries[0].EntryType == objRoot {
		root := r.entries[0]
		if root.StreamSize > 0 && root.StartingSector != fatEndSector {
			miniStream, err := r.readChain(root.StartingSector, r.fat)
			if err != nil {
				return nil, fmt.Errorf("read mini stream: %w", err)
			}
			if uint64(len(miniStream)) > root.StreamSize {
				miniStream = miniStream[:root.StreamSize]
			}
			r.miniStream = miniStream
		}

		if numMiniFATSectors > 0 && firstMiniFATSector != fatEndSector {
			miniFATBytes, err := r.readChain(firstMiniFATSector, r.fat)
			if err != nil {
				return nil, fmt.Errorf("read mini fat: %w", err)
			}
			nMiniEntries := len(miniFATBytes) / 4
			r.miniFAT = make([]uint32, nMiniEntries)
			for i := range nMiniEntries {
				r.miniFAT[i] = binary.LittleEndian.Uint32(miniFATBytes[i*4 : (i+1)*4])
			}
		}
	}

	return r, nil
}

func (r *cfbfReader) readSector(sectorID uint32, buf []byte) error {
	offset := int64(sectorID+1) * int64(r.sectorSize)
	_, err := r.ra.ReadAt(buf, offset)
	return err
}

func (r *cfbfReader) readChain(startSector uint32, fat []uint32) ([]byte, error) {
	var data []byte
	sec := startSector
	seen := make(map[uint32]bool)

	for sec != fatEndSector && sec != fatFreeSector {
		if seen[sec] || int(sec) >= len(fat) {
			break
		}
		seen[sec] = true

		buf := make([]byte, r.sectorSize)
		if err := r.readSector(sec, buf); err != nil {
			return nil, err
		}
		data = append(data, buf...)
		sec = fat[sec]
	}
	return data, nil
}

func (r *cfbfReader) readStream(entry cfbfDirEntry) ([]byte, error) {
	if entry.StreamSize < r.miniCutoff && len(r.miniStream) > 0 {
		var data []byte
		sec := entry.StartingSector
		seen := make(map[uint32]bool)

		for sec != fatEndSector && sec != fatFreeSector {
			if seen[sec] || int(sec) >= len(r.miniFAT) {
				break
			}
			seen[sec] = true

			offset := int(sec) * r.miniSectorSize
			if offset+r.miniSectorSize > len(r.miniStream) {
				break
			}
			data = append(data, r.miniStream[offset:offset+r.miniSectorSize]...)
			sec = r.miniFAT[sec]
		}
		if uint64(len(data)) > entry.StreamSize {
			data = data[:entry.StreamSize]
		}
		return data, nil
	}

	data, err := r.readChain(entry.StartingSector, r.fat)
	if err != nil {
		return nil, err
	}
	if uint64(len(data)) > entry.StreamSize {
		data = data[:entry.StreamSize]
	}
	return data, nil
}

func (r *cfbfReader) findStream(name string) (cfbfDirEntry, bool) {
	for _, e := range r.entries {
		if e.Name == name || e.Name == "!"+name || e.Name == "_"+name {
			return e, true
		}
	}
	return cfbfDirEntry{}, false
}

// decodeMSIStreamName decodes encoded MSI table and stream names.
func decodeMSIStreamName(raw []uint16) string {
	var sb strings.Builder
	for idx, ch := range raw {
		if ch == 0x4840 {
			sb.WriteRune('!')
		} else if ch == 0x3840 {
			sb.WriteRune('_')
		} else if (ch >= 0x3800 && ch < 0x4800) || (ch >= 0x4800 && ch < 0x5800) {
			base := 0x3800
			if ch >= 0x4800 {
				base = 0x4800
			}
			v := int(ch) - base
			c1 := v % 64
			c2 := v / 64
			sb.WriteRune(msi6BitToRune(c1))
			if c2 < 64 && !(idx == len(raw)-1 && c2 == 0) {
				sb.WriteRune(msi6BitToRune(c2))
			}
		} else {
			r := utf16.Decode([]uint16{ch})
			if len(r) > 0 {
				sb.WriteRune(r[0])
			}
		}
	}
	return sb.String()
}

func msi6BitToRune(v int) rune {
	if v >= 0 && v <= 9 {
		return rune('0' + v)
	}
	if v >= 10 && v <= 35 {
		return rune('A' + (v - 10))
	}
	if v >= 36 && v <= 61 {
		return rune('a' + (v - 36))
	}
	if v == 62 {
		return '.'
	}
	if v == 63 {
		return '_'
	}
	return '?'
}

// parseSummaryInfo parses the \x05SummaryInformation stream to get PID 9 (Package Code).
func parseSummaryInfo(data []byte) (string, error) {
	if len(data) < 48 {
		return "", errors.New("summary information stream too short")
	}

	byteOrder := binary.LittleEndian.Uint16(data[0:2])
	if byteOrder != 0xFFFE {
		return "", errors.New("unsupported byte order in property set")
	}

	numPropSets := binary.LittleEndian.Uint32(data[24:28])
	if numPropSets == 0 {
		return "", nil
	}

	setOffset := binary.LittleEndian.Uint32(data[44:48])
	if int(setOffset) >= len(data) {
		return "", errors.New("invalid property set offset")
	}

	setData := data[setOffset:]
	if len(setData) < 8 {
		return "", errors.New("invalid property set data")
	}

	numProps := binary.LittleEndian.Uint32(setData[4:8])
	for i := range numProps {
		offset := 8 + i*8
		if int(offset+8) > len(setData) {
			break
		}
		pid := binary.LittleEndian.Uint32(setData[offset : offset+4])
		propOffset := binary.LittleEndian.Uint32(setData[offset+4 : offset+8])

		if pid == 9 || pid == 12 { // PID 9 (Package Code) or PID 12
			if int(propOffset+4) <= len(setData) {
				val := parsePropertyValue(setData[propOffset:])
				if val != "" {
					return val, nil
				}
			}
		}
	}
	return "", nil
}

func parsePropertyValue(data []byte) string {
	if len(data) < 4 {
		return ""
	}
	propType := binary.LittleEndian.Uint32(data[:4])
	switch propType {
	case 30: // VT_LPSTR
		if len(data) < 8 {
			return ""
		}
		length := binary.LittleEndian.Uint32(data[4:8])
		if int(8+length) <= len(data) {
			strBytes := data[8 : 8+length]
			return strings.TrimRight(string(strBytes), "\x00")
		}
	case 31: // VT_LPWSTR
		if len(data) < 8 {
			return ""
		}
		charCount := binary.LittleEndian.Uint32(data[4:8])
		if int(8+charCount*2) <= len(data) {
			var u16s []uint16
			for i := range charCount {
				u16s = append(u16s, binary.LittleEndian.Uint16(data[8+i*2:10+i*2]))
			}
			return strings.TrimRight(string(utf16.Decode(u16s)), "\x00")
		}
	}
	return ""
}

// cfbfMSIReader reads MSI metadata using CFBF structured storage.
type cfbfMSIReader struct {
	path string
}

func (m *cfbfMSIReader) Path() string { return m.path }

func (m *cfbfMSIReader) Read() (*data.MSIProperties, error) {
	f, err := os.Open(m.path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	cfb, err := openCFBF(f)
	if err != nil {
		return nil, fmt.Errorf("open msi compound file: %w", err)
	}

	props := &data.MSIProperties{
		Summary:    map[string]string{},
		Properties: map[string]string{},
	}

	// 1. Summary Information
	if entry, ok := cfb.findStream("\x05SummaryInformation"); ok {
		sumData, err := cfb.readStream(entry)
		if err == nil {
			pkgCode, _ := parseSummaryInfo(sumData)
			if pkgCode != "" {
				props.Summary["Package Code"] = pkgCode
			}
		}
	}

	// 2. String Pool
	stringPool, is3ByteString, err := readMSIStringPool(cfb)
	if err != nil {
		return nil, fmt.Errorf("read string pool: %w", err)
	}

	// 3. Columns Schema
	columnsMap, err := readMSIColumns(cfb, stringPool, is3ByteString)
	if err != nil {
		return nil, fmt.Errorf("read columns: %w", err)
	}

	// 4. Property Table
	if propRows, err := readMSITableRows(cfb, "Property", columnsMap["Property"], stringPool, is3ByteString); err == nil {
		propCol := findColIndex(columnsMap["Property"], "Property")
		valCol := findColIndex(columnsMap["Property"], "Value")
		if propCol >= 0 && valCol >= 0 {
			for _, row := range propRows {
				if propCol < len(row) && valCol < len(row) {
					props.Properties[row[propCol]] = row[valCol]
				}
			}
		}
	}

	// 5. Database Tables
	database := &data.Database{
		Registry:    map[string]string{},
		Filesystems: map[string]string{},
		Components:  map[string]string{},
		Directories: map[string]string{},
	}

	if svcRows, err := readMSITableRows(cfb, "ServiceInstall", columnsMap["ServiceInstall"], stringPool, is3ByteString); err == nil {
		nameCol := findColIndex(columnsMap["ServiceInstall"], "Name")
		if nameCol < 0 && len(columnsMap["ServiceInstall"]) > 0 {
			nameCol = 0
		}
		if nameCol >= 0 {
			for _, row := range svcRows {
				if nameCol < len(row) && row[nameCol] != "" {
					database.Services = append(database.Services, row[nameCol])
				}
			}
		}
	}

	if odbcRows, err := readMSITableRows(cfb, "ODBCDataSource", columnsMap["ODBCDataSource"], stringPool, is3ByteString); err == nil {
		nameCol := findColIndex(columnsMap["ODBCDataSource"], "DataSource")
		if nameCol < 0 {
			nameCol = findColIndex(columnsMap["ODBCDataSource"], "Name")
		}
		if nameCol < 0 && len(columnsMap["ODBCDataSource"]) > 0 {
			nameCol = 0
		}
		if nameCol >= 0 {
			for _, row := range odbcRows {
				if nameCol < len(row) && row[nameCol] != "" {
					database.ODBCDataSources = append(database.ODBCDataSources, row[nameCol])
				}
			}
		}
	}

	if regRows, err := readMSITableRows(cfb, "Registry", columnsMap["Registry"], stringPool, is3ByteString); err == nil {
		regCol := findColIndex(columnsMap["Registry"], "Registry")
		rootCol := findColIndex(columnsMap["Registry"], "Root")
		if regCol >= 0 && rootCol >= 0 {
			for _, row := range regRows {
				if regCol < len(row) && rootCol < len(row) {
					database.Registry[row[regCol]] = row[rootCol]
				}
			}
		}
	}

	if fileRows, err := readMSITableRows(cfb, "File", columnsMap["File"], stringPool, is3ByteString); err == nil {
		fileCol := findColIndex(columnsMap["File"], "FileName")
		if fileCol < 0 {
			fileCol = findColIndex(columnsMap["File"], "File")
		}
		compCol := findColIndex(columnsMap["File"], "Component_")
		if fileCol >= 0 && compCol >= 0 {
			for _, row := range fileRows {
				if fileCol < len(row) && compCol < len(row) {
					database.Filesystems[row[fileCol]] = row[compCol]
				}
			}
		}
	}

	if compRows, err := readMSITableRows(cfb, "Component", columnsMap["Component"], stringPool, is3ByteString); err == nil {
		compCol := findColIndex(columnsMap["Component"], "Component")
		dirCol := findColIndex(columnsMap["Component"], "Directory_")
		if compCol >= 0 && dirCol >= 0 {
			for _, row := range compRows {
				if compCol < len(row) && dirCol < len(row) {
					database.Components[row[compCol]] = row[dirCol]
				}
			}
		}
	}

	if dirRows, err := readMSITableRows(cfb, "Directory", columnsMap["Directory"], stringPool, is3ByteString); err == nil {
		dirCol := findColIndex(columnsMap["Directory"], "Directory")
		parentCol := findColIndex(columnsMap["Directory"], "Directory_Parent")
		if dirCol >= 0 && parentCol >= 0 {
			for _, row := range dirRows {
				if dirCol < len(row) && parentCol < len(row) {
					database.Directories[row[dirCol]] = row[parentCol]
				}
			}
		}
	}

	props.Database = database
	return props, nil
}

type msiColumnDef struct {
	Number   int
	Name     string
	IsString bool
	ByteSize int
}

func findColIndex(cols []msiColumnDef, name string) int {
	for i, c := range cols {
		if c.Name == name {
			return i
		}
	}
	return -1
}

func readMSIStringPool(cfb *cfbfReader) ([]string, bool, error) {
	poolEntry, ok := cfb.findStream("_StringPool")
	if !ok {
		return nil, false, errors.New("_StringPool stream not found")
	}
	poolData, err := cfb.readStream(poolEntry)
	if err != nil {
		return nil, false, err
	}

	dataEntry, ok := cfb.findStream("_StringData")
	if !ok {
		return nil, false, errors.New("_StringData stream not found")
	}
	dataBytes, err := cfb.readStream(dataEntry)
	if err != nil {
		return nil, false, err
	}

	if len(poolData) < 4 {
		return nil, false, errors.New("_StringPool stream too short")
	}

	is3ByteString := (binary.LittleEndian.Uint16(poolData[2:4]) & 1) != 0

	var stringLengths []int
	for i := 4; i+4 <= len(poolData); i += 4 {
		l := int(binary.LittleEndian.Uint16(poolData[i : i+2]))
		ref := int(binary.LittleEndian.Uint16(poolData[i+2 : i+4]))
		if l == 0 && ref > 0 {
			l = (ref << 16) | int(binary.LittleEndian.Uint16(poolData[i+4:i+6]))
			i += 4
		}
		stringLengths = append(stringLengths, l)
	}

	stringsList := []string{""} // 0 is empty string
	offset := 0
	for _, l := range stringLengths {
		if offset+l > len(dataBytes) {
			stringsList = append(stringsList, "")
			continue
		}
		str := string(dataBytes[offset : offset+l])
		stringsList = append(stringsList, str)
		offset += l
	}

	return stringsList, is3ByteString, nil
}

func readMSIColumns(cfb *cfbfReader, pool []string, is3Byte bool) (map[string][]msiColumnDef, error) {
	colEntry, ok := cfb.findStream("_Columns")
	if !ok {
		return nil, errors.New("_Columns stream not found")
	}
	data, err := cfb.readStream(colEntry)
	if err != nil {
		return nil, err
	}

	// Schema of _Columns (columnar layout):
	// Column 1: Table (String)
	// Column 2: Number (Int16)
	// Column 3: Name (String)
	// Column 4: Type (Int16)
	colStringSize := 2
	if is3Byte {
		colStringSize = 3
	}
	rowSize := colStringSize*2 + 4
	if rowSize == 0 || len(data)%rowSize != 0 {
		return nil, fmt.Errorf("invalid _Columns stream length %d for row size %d", len(data), rowSize)
	}

	numRows := len(data) / rowSize

	offTable := 0
	offNum := numRows * colStringSize
	offName := offNum + numRows*2
	offType := offName + numRows*colStringSize

	result := make(map[string][]msiColumnDef)

	for i := range numRows {
		tableIdx := readInt(data[offTable+i*colStringSize:offTable+(i+1)*colStringSize], colStringSize)
		colNum := int(binary.LittleEndian.Uint16(data[offNum+i*2 : offNum+(i+1)*2]))
		nameIdx := readInt(data[offName+i*colStringSize:offName+(i+1)*colStringSize], colStringSize)
		colType := int(binary.LittleEndian.Uint16(data[offType+i*2 : offType+(i+1)*2]))

		var tableName, colName string
		if tableIdx < len(pool) {
			tableName = pool[tableIdx]
		}
		if nameIdx < len(pool) {
			colName = pool[nameIdx]
		}

		isString := (colType & 0x0800) != 0
		var byteSize int
		if isString {
			byteSize = colStringSize
		} else {
			byteSize = colType & 0xFF
			if byteSize == 0 {
				byteSize = 2
			}
		}

		colDef := msiColumnDef{
			Number:   colNum,
			Name:     colName,
			IsString: isString,
			ByteSize: byteSize,
		}

		result[tableName] = append(result[tableName], colDef)
	}

	// Sort columns by Number for each table
	for tableName := range result {
		cols := result[tableName]
		sort.Slice(cols, func(i, j int) bool {
			return cols[i].Number < cols[j].Number
		})
		result[tableName] = cols
	}

	return result, nil
}

func readMSITableRows(cfb *cfbfReader, tableName string, cols []msiColumnDef, pool []string, is3Byte bool) ([][]string, error) {
	if len(cols) == 0 {
		return nil, fmt.Errorf("table %s has no columns", tableName)
	}
	tableEntry, ok := cfb.findStream(tableName)
	if !ok {
		return nil, fmt.Errorf("stream for table %s not found", tableName)
	}
	data, err := cfb.readStream(tableEntry)
	if err != nil {
		return nil, err
	}

	rowSize := 0
	for _, c := range cols {
		rowSize += c.ByteSize
	}
	if rowSize == 0 || len(data)%rowSize != 0 {
		return nil, fmt.Errorf("table %s invalid stream size %d for row size %d", tableName, len(data), rowSize)
	}

	numRows := len(data) / rowSize
	colOffsets := make([]int, len(cols))
	curOff := 0
	for j, c := range cols {
		colOffsets[j] = curOff
		curOff += numRows * c.ByteSize
	}

	rows := make([][]string, numRows)
	for i := range numRows {
		rows[i] = make([]string, len(cols))
		for j, c := range cols {
			valStart := colOffsets[j] + i*c.ByteSize
			valBytes := data[valStart : valStart+c.ByteSize]

			if c.IsString {
				idx := readInt(valBytes, c.ByteSize)
				if idx < len(pool) {
					rows[i][j] = pool[idx]
				} else {
					rows[i][j] = ""
				}
			} else {
				val := readInt(valBytes, c.ByteSize)
				rows[i][j] = fmt.Sprintf("%d", val)
			}
		}
	}

	return rows, nil
}

func readInt(b []byte, size int) int {
	switch size {
	case 1:
		return int(b[0])
	case 2:
		return int(binary.LittleEndian.Uint16(b))
	case 3:
		return int(b[0]) | (int(b[1]) << 8) | (int(b[2]) << 16)
	case 4:
		return int(binary.LittleEndian.Uint32(b))
	}
	return 0
}
