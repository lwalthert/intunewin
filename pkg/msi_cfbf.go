package pkg

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"

	"github.com/lwalthert/intunewin/internal/data"
	"github.com/richardlehane/mscfb"
)

// cfbfMSIReader reads MSI metadata using mscfb to read CFBF structured storage.
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

	msi, err := mscfb.New(f)
	if err != nil {
		return nil, fmt.Errorf("open msi compound file: %w", err)
	}

	streams := make(map[string][]byte)
	for entry, err := msi.Next(); err == nil; entry, err = msi.Next() {
		if entry.FileInfo().IsDir() {
			continue
		}

		data, err := io.ReadAll(msi)
		if err != nil {
			return nil, fmt.Errorf("read stream %s: %w", entry.Name, err)
		}
		decodedName := decodeMSIStreamName(entry.Name)
		streams[decodedName] = data
		streams[entry.Name] = data
		if name, ok := strings.CutPrefix(decodedName, "!"); ok {
			streams[name] = data
		}
	}

	props := &data.MSIProperties{
		Summary:    map[string]string{},
		Properties: map[string]string{},
	}

	// 1. Summary Information
	if sumData, ok := streams["\x05SummaryInformation"]; ok {
		pkgCode, _ := parseSummaryInfo(sumData)
		if pkgCode != "" {
			props.Summary["Package Code"] = pkgCode
		}
	} else if sumData, ok := streams["SummaryInformation"]; ok {
		pkgCode, _ := parseSummaryInfo(sumData)
		if pkgCode != "" {
			props.Summary["Package Code"] = pkgCode
		}
	}

	// 2. String Pool
	stringPool, is3ByteString, err := readMSIStringPoolFromStreams(streams)
	if err != nil {
		return nil, fmt.Errorf("read string pool: %w", err)
	}

	// 3. Columns Schema
	columnsMap, err := readMSIColumnsFromStreams(streams, stringPool, is3ByteString)
	if err != nil {
		return nil, fmt.Errorf("read columns: %w", err)
	}

	// 4. Property Table
	if propRows, err := readMSITableRowsFromStreams(streams, "Property", columnsMap["Property"], stringPool, is3ByteString); err == nil {
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

	if svcRows, err := readMSITableRowsFromStreams(streams, "ServiceInstall", columnsMap["ServiceInstall"], stringPool, is3ByteString); err == nil {
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

	if odbcRows, err := readMSITableRowsFromStreams(streams, "ODBCDataSource", columnsMap["ODBCDataSource"], stringPool, is3ByteString); err == nil {
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

	if regRows, err := readMSITableRowsFromStreams(streams, "Registry", columnsMap["Registry"], stringPool, is3ByteString); err == nil {
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

	if fileRows, err := readMSITableRowsFromStreams(streams, "File", columnsMap["File"], stringPool, is3ByteString); err == nil {
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

	if compRows, err := readMSITableRowsFromStreams(streams, "Component", columnsMap["Component"], stringPool, is3ByteString); err == nil {
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

	if dirRows, err := readMSITableRowsFromStreams(streams, "Directory", columnsMap["Directory"], stringPool, is3ByteString); err == nil {
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

func decodeMSIStreamName(raw string) string {
	runes := []rune(raw)
	var sb strings.Builder
	for idx, ch := range runes {
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
			if c2 < 64 && !(idx == len(runes)-1 && c2 == 0) {
				sb.WriteRune(msi6BitToRune(c2))
			}
		} else {
			sb.WriteRune(ch)
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

	setOffset := uint64(binary.LittleEndian.Uint32(data[44:48]))
	if setOffset >= uint64(len(data)) {
		return "", errors.New("invalid property set offset")
	}

	setData := data[setOffset:]
	if len(setData) < 8 {
		return "", errors.New("invalid property set data")
	}

	numProps := uint64(binary.LittleEndian.Uint32(setData[4:8]))
	for i := uint64(0); i < numProps; i++ {
		offset := 8 + i*8
		if offset+8 > uint64(len(setData)) {
			break
		}
		pid := binary.LittleEndian.Uint32(setData[offset : offset+4])
		propOffset := uint64(binary.LittleEndian.Uint32(setData[offset+4 : offset+8]))

		if pid == 9 || pid == 12 { // PID 9 (Package Code) or PID 12
			if propOffset+4 <= uint64(len(setData)) {
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
		length := uint64(binary.LittleEndian.Uint32(data[4:8]))
		if 8+length <= uint64(len(data)) {
			strBytes := data[8 : 8+length]
			return strings.TrimRight(string(strBytes), "\x00")
		}
	case 31: // VT_LPWSTR
		if len(data) < 8 {
			return ""
		}
		charCount := uint64(binary.LittleEndian.Uint32(data[4:8]))
		if 8+charCount*2 <= uint64(len(data)) {
			var u16s []uint16
			for i := uint64(0); i < charCount; i++ {
				u16s = append(u16s, binary.LittleEndian.Uint16(data[8+i*2:10+i*2]))
			}
			return strings.TrimRight(string(utf16.Decode(u16s)), "\x00")
		}
	}
	return ""
}

func getStream(streams map[string][]byte, name string) ([]byte, bool) {
	if data, ok := streams[name]; ok {
		return data, true
	}
	if data, ok := streams["!"+name]; ok {
		return data, true
	}
	if data, ok := streams["_"+name]; ok {
		return data, true
	}
	return nil, false
}

func readMSIStringPoolFromStreams(streams map[string][]byte) ([]string, bool, error) {
	poolData, ok := getStream(streams, "_StringPool")
	if !ok {
		return nil, false, errors.New("_StringPool stream not found")
	}
	dataBytes, ok := getStream(streams, "_StringData")
	if !ok {
		return nil, false, errors.New("_StringData stream not found")
	}

	if len(poolData) < 4 {
		return nil, false, errors.New("_StringPool stream too short")
	}

	is3ByteString := (binary.LittleEndian.Uint16(poolData[2:4]) & 0x8000) != 0

	stringsList := []string{""} // 0 is empty string
	offset := 0

	for i := 4; i+4 <= len(poolData); {
		l := int(binary.LittleEndian.Uint16(poolData[i : i+2]))
		refs := int(binary.LittleEndian.Uint16(poolData[i+2 : i+4]))

		if l == 0 && refs == 0 {
			stringsList = append(stringsList, "")
			i += 4
			continue
		}

		if l == 0 && refs > 0 {
			if i+8 > len(poolData) {
				return nil, false, errors.New("truncated extended string entry in _StringPool")
			}
			l = (refs << 16) | int(binary.LittleEndian.Uint16(poolData[i+4:i+6]))
			i += 8
		} else {
			i += 4
		}

		if offset+l > len(dataBytes) {
			stringsList = append(stringsList, "")
			offset = len(dataBytes)
			continue
		}

		stringsList = append(stringsList, string(dataBytes[offset:offset+l]))
		offset += l
	}

	return stringsList, is3ByteString, nil
}

func readMSIColumnsFromStreams(streams map[string][]byte, pool []string, is3Byte bool) (map[string][]msiColumnDef, error) {
	data, ok := getStream(streams, "_Columns")
	if !ok {
		return nil, errors.New("_Columns stream not found")
	}

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

	for i := 0; i < numRows; i++ {
		tableIdx := readInt(data[offTable+i*colStringSize:offTable+(i+1)*colStringSize], colStringSize)
		colNumRaw := binary.LittleEndian.Uint16(data[offNum+i*2 : offNum+(i+1)*2])
		colNum := int(colNumRaw)
		if colNumRaw > 0 {
			colNum = int(int16(colNumRaw ^ 0x8000))
		}

		nameIdx := readInt(data[offName+i*colStringSize:offName+(i+1)*colStringSize], colStringSize)

		colTypeRaw := binary.LittleEndian.Uint16(data[offType+i*2 : offType+(i+1)*2])
		colType := int(colTypeRaw)
		if colTypeRaw > 0 {
			colType = int(int16(colTypeRaw ^ 0x8000))
		}

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

func readMSITableRowsFromStreams(streams map[string][]byte, tableName string, cols []msiColumnDef, pool []string, is3Byte bool) ([][]string, error) {
	if len(cols) == 0 {
		return nil, fmt.Errorf("table %s has no columns", tableName)
	}
	data, ok := getStream(streams, tableName)
	if !ok {
		return nil, fmt.Errorf("stream for table %s not found", tableName)
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
	for i := 0; i < numRows; i++ {
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
				if val, ok := readMSITableInt(valBytes, c.ByteSize); ok {
					rows[i][j] = strconv.Itoa(val)
				} else {
					rows[i][j] = ""
				}
			}
		}
	}

	return rows, nil
}

func readMSITableInt(b []byte, size int) (int, bool) {
	switch size {
	case 1:
		v := b[0]
		if v == 0 {
			return 0, false // NULL
		}
		return int(int8(v ^ 0x80)), true
	case 2:
		v := binary.LittleEndian.Uint16(b)
		if v == 0 {
			return 0, false // NULL
		}
		return int(int16(v ^ 0x8000)), true
	case 3:
		v := uint32(b[0]) | (uint32(b[1]) << 8) | (uint32(b[2]) << 16)
		if v == 0 {
			return 0, false // NULL
		}
		return int(int32(v ^ 0x800000)), true
	case 4:
		v := binary.LittleEndian.Uint32(b)
		if v == 0 {
			return 0, false // NULL
		}
		return int(int32(v ^ 0x80000000)), true
	}
	return 0, false
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
