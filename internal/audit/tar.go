// Package audit — minimal tar writer used by ArchiveLogs.
//
// We use the stdlib archive/tar; this thin wrapper bundles the
// per-file boilerplate (stat, header, copy) so ArchiveLogs reads
// cleanly. No new external dependencies.

package audit

import (
	"archive/tar"
	"io"
	"os"
)

type tarBundle struct {
	tw *tar.Writer
}

func newTarWriter(w io.Writer) *tarBundle {
	return &tarBundle{tw: tar.NewWriter(w)}
}

func (b *tarBundle) addFile(src, arcname string) error {
	st, err := os.Stat(src)
	if err != nil {
		return err
	}
	hdr := &tar.Header{
		Name:    arcname,
		Mode:    int64(st.Mode().Perm()),
		Size:    st.Size(),
		ModTime: st.ModTime(),
	}
	if err := b.tw.WriteHeader(hdr); err != nil {
		return err
	}
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := io.Copy(b.tw, f); err != nil {
		return err
	}
	return nil
}

func (b *tarBundle) Close() error {
	return b.tw.Close()
}
