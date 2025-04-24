package goLuksSuspend

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	"github.com/guns/golibs/errutil"
)

type Cryptdevice struct {
	Name         string
	uuid         []byte
	dmdir        string
	Keyfile      Keyfile
	IsRootDevice bool
}

var luksUUIDPrefix = []byte("CRYPT-LUKS1-")

func GetCryptdevices() ([]Cryptdevice, map[string]*Cryptdevice, error) {
	dirs, err := filepath.Glob("/sys/block/*/dm")
	if err != nil || len(dirs) == 0 {
		return nil, nil, err
	}

	rootdev, rootkey, err := parseKernelCmdline()
	if err != nil {
		return nil, nil, err
	}

	cryptdevs := make([]Cryptdevice, len(dirs))
	cdmap := make(map[string]*Cryptdevice, len(dirs))
	j, lastidx := 1, 0

	for i := range dirs {
		// Skip if not a LUKS device
		uuid, err := ioutil.ReadFile(filepath.Join(dirs[i], "uuid"))
		if err != nil {
			return nil, nil, err
		} else if len(uuid) < len(luksUUIDPrefix) ||
			!bytes.Equal(uuid[:len(luksUUIDPrefix)], luksUUIDPrefix) {
			continue
		}

		cd := Cryptdevice{
			dmdir: dirs[i],
			uuid:  bytes.TrimSuffix(uuid, []byte{'\n'}),
		}

		// Skip if suspended
		if cd.Suspended() {
			continue
		}

		name, err := ioutil.ReadFile(filepath.Join(cd.dmdir, "name"))
		if err != nil {
			return nil, nil, err
		}

		cd.Name = string(bytes.TrimSuffix(name, []byte{'\n'}))

		if cd.Name == rootdev {
			if cryptdevs[0].IsRootDevice {
				return nil, nil, fmt.Errorf(
					"multiple root cryptdevices: %s, %s",
					cryptdevs[0].Name,
					cd.Name,
				)
			}
			cd.IsRootDevice = true
			cd.Keyfile = rootkey
			cryptdevs[0] = cd
			lastidx = 0
		} else if j >= len(dirs) {
			return nil, nil, errors.New("no root cryptdevice")
		} else {
			cryptdevs[j] = cd
			lastidx = j
			j++
		}

		if v, ok := cdmap[cd.Name]; ok {
			return nil, nil, fmt.Errorf("duplicate cryptdevice: %#v", v)
		}
		cdmap[cd.Name] = &cryptdevs[lastidx]
	}

	return cryptdevs[:j], cdmap, nil
}

func (cd *Cryptdevice) Exists() bool {
	uuid, err := ioutil.ReadFile(filepath.Join(cd.dmdir, "uuid"))
	if err != nil {
		// A read error implies this device has been removed
		return false
	}

	return bytes.Equal(cd.uuid, bytes.TrimSuffix(uuid, []byte{'\n'}))
}

func (cd *Cryptdevice) Suspended() bool {
	buf, err := ioutil.ReadFile(filepath.Join(cd.dmdir, "suspended"))
	if err != nil || len(buf) == 0 {
		// Ignore the error here for a cleaner API; read errors imply
		// that the device is gone, so technically, it's not suspended
		return false
	}

	return buf[0] == '1'
}

func (cd *Cryptdevice) Resume(stdin io.Reader) error {
	cmd := exec.Command("/usr/bin/cryptsetup", "--tries=1", "luksResume", cd.Name)
	cmd.Stdin = stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return Run(cmd)
}

var errNoKeyfile = errors.New("no keyfile")

const keyfileMountDir = "/go-luks-suspend-mnt"

func (cd *Cryptdevice) ResumeWithKeyfile() (err error) {
	args := make([]string, 0, 12)

	if cd.Keyfile.needsMount() {
		if err = os.Mkdir(keyfileMountDir, 0700); err != nil {
			return err
		}
		defer func() {
			err = errutil.First(err, os.Remove(keyfileMountDir))
		}()

		if err = syscall.Mount(cd.Keyfile.Device, keyfileMountDir, cd.Keyfile.FSType, syscall.MS_RDONLY, ""); err != nil {
			return err
		}
		defer func() {
			err = errutil.First(err, syscall.Unmount(keyfileMountDir, 0))
		}()

		args = append(args, "--key-file", filepath.Join(keyfileMountDir, cd.Keyfile.Path))
	} else {
		args = append(args, "--key-file", cd.Keyfile.Path)
		if cd.Keyfile.Offset > 0 {
			args = append(args, "--keyfile-offset", strconv.FormatUint(cd.Keyfile.Offset, 10))
		}
		if cd.Keyfile.Size > 0 {
			args = append(args, "--keyfile-size", strconv.FormatUint(cd.Keyfile.Size, 10))
		}
		if cd.Keyfile.KeySlotDefined() {
			args = append(args, "--key-slot", strconv.FormatUint(cd.Keyfile.GetKeySlot(), 10))
		}
		if len(cd.Keyfile.Header) > 0 {
			args = append(args, "--header", cd.Keyfile.Header)
		}
	}

	args = append(args, "luksResume", cd.Name)

	return Cryptsetup(args...)
}

// This is a variable to facilitate testing.
var kernelCmdline = "/proc/cmdline"

func parseKernelCmdline() (rootdev string, key Keyfile, err error) {
	buf, err := ioutil.ReadFile(kernelCmdline)
	if err != nil {
		return "", Keyfile{}, err
	}

	//
	// https://git.archlinux.org/svntogit/packages.git/tree/trunk/encrypt_hook?h=packages/cryptsetup
	//

	params := strings.Fields(string(buf))

	for i := range params {
		kv := strings.SplitN(params[i], "=", 2)
		if len(kv) < 2 {
			continue
		}

		switch kv[0] {
		case "cryptdevice":
			// cryptdevice=device:dmname:options
			fields := strings.SplitN(kv[1], ":", 3)
			if len(fields) < 2 {
				continue
			}

			rootdev = fields[1]
		case "cryptkey":
			fields := strings.SplitN(kv[1], ":", 3)
			if len(fields) < 2 {
				continue
			}

			// cryptkey=rootfs:path
			if len(fields) == 2 && fields[0] == "rootfs" {
				key.Path = fields[1]
				continue
			}

			if len(fields) < 3 {
				continue
			}

			if offset, err := strconv.ParseUint(fields[1], 10, 0); err == nil {
				// cryptkey=device:offset:size
				size, err := strconv.ParseUint(fields[2], 10, 0)
				if err != nil {
					continue // ignore malformed entry
				}
				key.Path = resolveDevice(fields[0])
				key.Offset = offset
				key.Size = size
				continue
			}

			// cryptkey=device:fstype:path
			key.Device = resolveDevice(fields[0])
			key.FSType = fields[1]
			key.Path = fields[2]
		}
	}

	if len(rootdev) == 0 {
		return "", Keyfile{}, errors.New("no root cryptdevice")
	}

	return rootdev, key, nil
}

func resolveDevice(name string) string {
	kv := strings.SplitN(name, "=", 2)
	if len(kv) < 2 {
		return name
	}

	switch kv[0] {
	// ID= and PATH= are not supported by the encrypt hook, but are provided by udev
	case "UUID", "LABEL", "PARTUUID", "PARTLABEL", "ID", "PATH":
		return filepath.Join("/dev/disk/by-"+strings.ToLower(kv[0]), kv[1])
	default:
		return name
	}
}

var ignoreLinePattern = regexp.MustCompile(`\A\s*\z|\A\s*#`)

func AddKeyfilesFromCrypttab(cdmap map[string]*Cryptdevice) error {
	file, err := os.Open("/etc/crypttab")
	if err != nil {
		return err
	}

	s := bufio.NewScanner(file)

	for s.Scan() {
		line := s.Bytes()
		if ignoreLinePattern.Match(line) {
			continue
		}

		name, key := parseCrypttabEntry(string(line))
		if len(name) == 0 {
			continue
		}

		if cd, ok := cdmap[name]; ok {
			cd.Keyfile = key
		}
	}

	return file.Close()
}
