package goLuksSuspend

import (
	"errors"
	"io/ioutil"
	"os"
	"testing"
)

func TestKernelCmdlineParsing(t *testing.T) {
	kernelCmdlineSave := kernelCmdline
	kernelCmdline = "test_kernel_cmdline"
	defer func() {
		_ = os.Remove(kernelCmdline) // errcheck: rm -f
		kernelCmdline = kernelCmdlineSave
	}()

	data := []struct {
		in, name string
		key      Keyfile
		err      error
	}{
		// cryptdevice=
		{
			in:   "cryptdevice=UUID=d55cc35b-e99b-44ce-be89-4c573fccfb0b:cryptroot root=/dev/mapper/cryptroot\n",
			name: "cryptroot",
		},
		{
			in:   "cryptdevice=/dev/sda1:cryptroot1 cryptdevice=/dev/sda2:cryptroot2\n",
			name: "cryptroot2",
		},
		{
			in:   "cryptdevice=UUID=cd5dd4dc-5766-493e-b3c6-3d6dfd195082:cryptolvm:allow-discards root=/dev/mapper/system-root",
			name: "cryptolvm",
		},
		// cryptkey=
		{
			in:   "cryptdevice=/dev/sda2:root cryptkey=rootfs:/var/rootfs.key\n",
			name: "root",
			key:  Keyfile{Path: "/var/rootfs.key"},
		},
		{
			in:   "cryptdevice=/dev/sda2:root cryptkey=/dev/sdb:512:1024\n",
			name: "root",
			key:  Keyfile{Path: "/dev/sdb", Offset: 512, Size: 1024},
		},
		// errors
		{
			in:   "BOOT_IMAGE=../vmlinuz-linux rw initrd=../initramfs-linux.img\n",
			name: "",
			key:  Keyfile{},
			err:  errors.New("no root cryptdevice"),
		},
	}

	for _, row := range data {
		err := ioutil.WriteFile(kernelCmdline, []byte(row.in), 0644)
		if err != nil {
			t.Errorf("unexpected error: %#v", err)
		}

		name, key, err := parseKernelCmdline()
		if name != row.name {
			t.Errorf("%#v != %#v", name, row.name)
		}
		if key != row.key {
			t.Errorf("%#v != %#v", name, row.key)
		}
		if (err == nil) != (row.err == nil) {
			t.Errorf("%#v !~ %#v", err, row.err)
		}
	}
}
