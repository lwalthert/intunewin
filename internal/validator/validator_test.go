package validator

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidator_CheckAndValid(t *testing.T) {
	v := New()
	if !v.Valid() {
		t.Fatal("new validator should be valid")
	}

	v.Check(true, "ok", "no error")
	if !v.Valid() {
		t.Fatal("validator should remain valid when all checks pass")
	}

	v.Check(false, "name", "name is blank")
	if v.Valid() {
		t.Fatal("validator should be invalid after a failed check")
	}
	if v.Errors["name"] != "name is blank" {
		t.Errorf("Errors[name] = %q, want %q", v.Errors["name"], "name is blank")
	}

	// AddError does not overwrite an existing key.
	v.AddError("name", "second message")
	if v.Errors["name"] != "name is blank" {
		t.Errorf("Errors[name] = %q, want original message preserved", v.Errors["name"])
	}
}

func TestPathIsExists(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "f.txt")
	if err := os.WriteFile(file, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}

	if !PathIsExists(dir, Directory) {
		t.Errorf("PathIsExists(%q, Directory) = false, want true", dir)
	}
	if PathIsExists(dir, File) {
		t.Errorf("PathIsExists(%q, File) = true, want false", dir)
	}
	if !PathIsExists(file, File) {
		t.Errorf("PathIsExists(%q, File) = false, want true", file)
	}
	if PathIsExists(file, Directory) {
		t.Errorf("PathIsExists(%q, Directory) = true, want false", file)
	}
	if PathIsExists(filepath.Join(dir, "missing"), File) {
		t.Errorf("PathIsExists for missing path = true, want false")
	}
}

func TestFileIsInDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "setup.exe"), []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}

	if !FileIsInDirectory("setup.exe", dir) {
		t.Errorf("FileIsInDirectory(setup.exe) = false, want true")
	}
	if FileIsInDirectory("other.exe", dir) {
		t.Errorf("FileIsInDirectory(other.exe) = true, want false")
	}
	if FileIsInDirectory("setup.exe", filepath.Join(dir, "missing")) {
		t.Errorf("FileIsInDirectory with missing dir = true, want false")
	}
}

func TestIsRelativePath(t *testing.T) {
	valid := []string{
		"setup.exe",
		"setup.msi",
		"my app.exe",
		"a.b.c",
		"bin/setup.exe",     // relative path, forward slash
		"bin\\setup.exe",    // relative path, backslash
		"sub/dir/setup.msi", // nested relative path
	}
	for _, name := range valid {
		if !IsRelativePath(name) {
			t.Errorf("IsRelativePath(%q) = false, want true", name)
		}
	}

	invalid := []string{
		"",
		"/abs/setup.exe",   // unix absolute
		"\\abs\\setup.exe", // windows absolute
		"C:\\setup.exe",    // windows drive root
		"C:/setup.exe",     // windows drive root (slash)
	}
	for _, name := range invalid {
		if IsRelativePath(name) {
			t.Errorf("IsRelativePath(%q) = true, want false", name)
		}
	}
}

func TestNotBlank(t *testing.T) {
	if NotBlank("") {
		t.Errorf("NotBlank(\"\") = true, want false")
	}
	if !NotBlank("x") {
		t.Errorf("NotBlank(\"x\") = false, want true")
	}
}
