package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"
)

type filesystem struct {
	mountpoint string
	devno      uint64
}

func getFilesystemsWithWriteBarriers() ([]filesystem, error) {
	file, err := os.Open("/proc/mounts")
	if err != nil {
		return nil, err
	}

	fs := []filesystem{}
	s := bufio.NewScanner(file)

	for s.Scan() {
		fields := strings.Fields(s.Text())

		if len(fields) != 6 {
			return nil, errors.New("malformed entry in /proc/mounts: " + s.Text())
		}

		if hasWriteBarrier(fields[2], fields[3]) {
			devno, err := lstatDevno(fields[1])
			if err != nil {
				return nil, err
			}

			fs = append(fs, filesystem{
				mountpoint: fields[1],
				devno:      devno,
			})
		}
	}

	if err := file.Close(); err != nil {
		return nil, err
	}

	return fs, nil
}

func (fs *filesystem) isMounted() bool {
	devno, err := lstatDevno(fs.mountpoint)
	if err != nil {
		return false
	}

	return fs.devno == devno
}

func (fs *filesystem) disableWriteBarrier() error {
	return syscall.Mount("", fs.mountpoint, "", syscall.MS_REMOUNT, "nobarrier")
}

func (fs *filesystem) enableWriteBarrier() error {
	return syscall.Mount("", fs.mountpoint, "", syscall.MS_REMOUNT, "barrier")
}

func hasWriteBarrier(fstype, mountopts string) bool {
	switch fstype {
	// ReiserFS supports write barriers, but the option syntax appears to
	// be unconventional. Since it's fading into obscurity, just ignore it.
	case "ext2", "ext3", "ext4":
		for _, o := range strings.Split(mountopts, ",") {
			// Write barriers are on by default and do not show up
			// in the list of mount options, so check for the negative
			if o == "barrier=0" || o == "nobarrier" {
				return false
			}
		}
		return true
	}
	return false
}

func lstatDevno(path string) (uint64, error) {
	// stat(2):
	// On Linux, lstat() will generally not trigger automounter action,
	// whereas stat() will
	fi, err := os.Lstat(path)
	if err != nil {
		return 0, err
	}

	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, fmt.Errorf("lstat %#v: no stat_t", path)
	}

	return st.Dev, nil
}
