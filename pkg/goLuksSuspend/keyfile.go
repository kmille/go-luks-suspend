package goLuksSuspend

import (
	"os"
	"strconv"
	"strings"
)

type Keyfile struct {
	Device  string
	FSType  string
	Header  string
	Path    string
	Offset  uint64
	Size    uint64
	KeySlot uint8
}

func parseCrypttabEntry(line string) (name string, key Keyfile) {
	fields := strings.Fields(line)

	// fields: name, device, keyfile, options
	//
	// crypttab(5):
	// The third field specifies the encryption password. If the field is
	// not present or the password is set to "none" or "-", the password
	// has to be manually entered during system boot.
	if len(fields) < 3 || fields[2] == "-" || fields[2] == "none" {
		return "", Keyfile{}
	}

	k := Keyfile{Path: fields[2]}

	if len(fields) >= 4 {
		opts := strings.Split(fields[3], ",")
		for i := range opts {
			kv := strings.SplitN(opts[i], "=", 2)
			if len(kv) < 2 {
				continue
			}

			switch kv[0] {
			case "keyfile-offset":
				n, err := strconv.ParseUint(kv[1], 10, 0)
				if err != nil {
					continue
				}
				k.Offset = n
			case "keyfile-size":
				n, err := strconv.ParseUint(kv[1], 10, 0)
				if err != nil {
					continue
				}
				k.Size = n
			case "key-slot":
				// LUKS currently only supports 8 key slots
				n, err := strconv.ParseUint(kv[1], 10, 7)
				if err != nil {
					continue
				}
				k.KeySlot = uint8(n | 0x80)
			case "header":
				k.Header = kv[1]
			}
		}
	}

	return fields[0], k
}

func (k *Keyfile) Defined() bool {
	return len(k.Path) > 0
}

func (k *Keyfile) needsMount() bool {
	return len(k.Device) > 0
}

func (k *Keyfile) Available() bool {
	if !k.Defined() {
		return false
	}
	f := k.Path
	if k.needsMount() {
		f = k.Device
	}
	_, err := os.Stat(f)
	return !os.IsNotExist(err)
}

func (k *Keyfile) KeySlotDefined() bool {
	return k.KeySlot&0x80 > 0
}

func (k *Keyfile) GetKeySlot() uint64 {
	return uint64(k.KeySlot & 0x7f)
}
