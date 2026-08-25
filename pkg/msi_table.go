package pkg

// msiTable is a parsed MSI database table: the column names (row 1 of the
// msitools export format) and the data rows.
type msiTable struct {
	columns []string
	rows    [][]string
}

// columnIndex returns the 0-based index of the named column, or -1 if absent.
func (t *msiTable) columnIndex(name string) int {
	for i, c := range t.columns {
		if c == name {
			return i
		}
	}
	return -1
}

// rowsByColumn returns the value of the named column for every row, skipping
// rows where the value is empty.
func (t *msiTable) rowsByColumn(name string) []string {
	idx := t.columnIndex(name)
	if idx < 0 {
		return nil
	}
	var out []string
	for _, row := range t.rows {
		if idx < len(row) && row[idx] != "" {
			out = append(out, row[idx])
		}
	}
	return out
}

// keyValue returns a map from the value of keyCol to the value of valueCol for
// every row. Later rows win on duplicate keys.
func (t *msiTable) keyValue(keyCol, valueCol string) map[string]string {
	ki, vi := t.columnIndex(keyCol), t.columnIndex(valueCol)
	if ki < 0 || vi < 0 {
		return nil
	}
	out := map[string]string{}
	for _, row := range t.rows {
		if ki < len(row) && vi < len(row) {
			out[row[ki]] = row[vi]
		}
	}
	return out
}
