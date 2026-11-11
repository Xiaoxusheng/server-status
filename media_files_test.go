package main

import (
	"os"
	"path/filepath"
	"testing"
)

// 媒体目录含多级子目录时，收集结果必须是相对路径，且拼回 root 后文件真实存在。
func TestCollectMediaFilesUsesRelativePaths(t *testing.T) {
	root := t.TempDir()
	must := func(rel string) {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	must("a.mp4")
	must(filepath.Join("斗鱼直播", "南妹儿呀", "b.png"))
	must(filepath.Join("斗鱼直播", "c.webm"))
	must("ignore.txt")

	got, err := collectMediaFiles(root)
	if err != nil {
		t.Fatalf("collectMediaFiles error: %v", err)
	}
	want := map[string]bool{
		"a.mp4":           true,
		"斗鱼直播/南妹儿呀/b.png": true,
		"斗鱼直播/c.webm":     true,
	}
	if len(got) != len(want) {
		t.Fatalf("got %d files %v, want %d", len(got), got, len(want))
	}
	for _, rel := range got {
		if !want[rel] {
			t.Errorf("unexpected entry %q", rel)
		}
		// 关键断言：按相对路径拼回 root 必须能打开，否则 /api/media 会 404
		if _, statErr := os.Stat(filepath.Join(root, filepath.FromSlash(rel))); statErr != nil {
			t.Errorf("entry %q does not resolve under root: %v", rel, statErr)
		}
	}
}
