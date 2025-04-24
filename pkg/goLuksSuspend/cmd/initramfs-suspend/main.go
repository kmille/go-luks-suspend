package main

import (
	"os"

	g "github.com/kmille/go-luks-suspend/pkg/goLuksSuspend"
)

func main() {
	g.ParseFlags()

	g.Debug("loading cryptdevices")
	r := os.NewFile(uintptr(3), "r")
	cryptdevs, err := loadCryptdevices(r)
	g.Assert(err)
	g.Assert(r.Close())

	if len(cryptdevs) == 0 {
		// This branch should be impossible.
		g.Warn("no cryptdevices found, doing normal suspend")
		g.Assert(g.SuspendToRAM())
		return
	}

	if cryptdevs[0].Keyfile.Defined() {
		g.Debug("starting udevd from initramfs")
		g.Assert(startUdevDaemon())

		defer func() {
			g.Debug("stopping udevd within initramfs")
			g.Assert(stopUdevDaemon())
		}()
	}

	g.Debug("suspending cryptdevices")
	g.Assert(suspendCryptdevices(cryptdevs))

	// Crypt keys have been purged, so be less paranoid
	g.IgnoreErrors = true

	// Shorten task freeze timeout
	oldtimeout, err := g.SetFreezeTimeout([]byte{'1', '0', '0', '0'})
	if err == nil {
		defer func() {
			_, e := g.SetFreezeTimeout(oldtimeout)
			g.Assert(e)
		}()
	} else {
		g.Assert(err)
	}

	if g.DebugMode {
		g.Debug("debug: skipping suspend to RAM")
	} else {
		g.Assert(g.SuspendToRAM())
	}

	g.Debug("resuming root cryptdevice")
	for {
		var err error
		for i := 0; i < 3; i++ {
			err = resumeRootCryptdevice(&cryptdevs[0])
			if err == nil {
				return
			}
		}
		// The -poweroff flag indicates the user's desire to take the
		// system offline on failure to unlock.
		if g.PoweroffOnError {
			g.IgnoreErrors = false
			g.Assert(err)
		}
	}
}
