package web

import (
	"io/fs"
	"regexp"
	"testing"
)

// The locked mode serves the page under "default-src 'self'", which refuses
// inline scripts, handlers and styles: the static files must have none, in
// the markup or in what the scripts write.
func TestStaticFilesFitTheCSP(t *testing.T) {
	inline := regexp.MustCompile(`(?i)\son\w+\s*=\s*["']|\sstyle\s*=\s*["']|<style|<script(\s[^>]*)?>\s*[^<\s]|javascript:`)
	err := fs.WalkDir(Static, "static", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := fs.ReadFile(Static, path)
		if err != nil {
			return err
		}
		for _, m := range inline.FindAll(data, -1) {
			t.Errorf("%s: %q is inline, the Content-Security-Policy would refuse it", path, m)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
