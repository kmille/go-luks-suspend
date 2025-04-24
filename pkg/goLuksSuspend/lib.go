package goLuksSuspend

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"strings"
)

var DebugMode = false
var PoweroffOnError = false
var IgnoreErrors = false

func ParseFlags() {
	debugFlag := flag.Bool("debug", false, "print debug messages and spawn a shell on errors")
	poweroffFlag := flag.Bool("poweroff", false, "power off on errors and failure to unlock root device")
	versionFlag := flag.Bool("version", false, "print version and exit")

	flag.Parse()

	if *versionFlag {
		fmt.Println(Version)
		os.Exit(0)
	}

	DebugMode = *debugFlag
	PoweroffOnError = *poweroffFlag
}

func Debug(msg string) {
	if DebugMode {
		Warn(msg)
	}
}

func Warn(msg string) {
	log.Println(msg)
}

func Assert(err error) {
	if err == nil {
		return
	}

	Warn(err.Error())

	if IgnoreErrors {
		return
	}

	if DebugMode {
		DebugShell()
	} else if PoweroffOnError {
		Poweroff()
	} else {
		os.Exit(1)
	}
}

func DebugShell() {
	log.Println("===========================")
	log.Println("        DEBUG SHELL        ")
	log.Println("===========================")

	cmd := exec.Command("/bin/sh")
	cmd.Env = []string{"PS1=[\\w \\u\\$] "}
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	_ = cmd.Run()

	fmt.Println("EXIT DEBUG SHELL")
}

func Run(cmd *exec.Cmd) error {
	if DebugMode {
		if len(cmd.Args) > 0 {
			Warn("exec: " + strings.Join(cmd.Args, " "))
		} else {
			Warn("exec: " + cmd.Path)
		}
	}
	return cmd.Run()
}

func Cryptsetup(args ...string) error {
	return Run(exec.Command("/usr/bin/cryptsetup", args...))
}

func Systemctl(args ...string) error {
	return Run(exec.Command("/usr/bin/systemctl", args...))
}

const freezeTimeoutPath = "/sys/power/pm_freeze_timeout"

func SetFreezeTimeout(timeout []byte) (oldtimeout []byte, err error) {
	oldtimeout, err = ioutil.ReadFile(freezeTimeoutPath)
	if err != nil {
		return nil, err
	}
	return oldtimeout, ioutil.WriteFile(freezeTimeoutPath, timeout, 0644)
}

func SuspendToRAM() error {
	err := ioutil.WriteFile("/sys/power/state", []byte{'m', 'e', 'm'}, 0600)
	if err != nil {
		return fmt.Errorf("%s\n\nSuspend to RAM failed. Unlock the root volume and investigate `dmesg`.", err.Error())
	}
	return nil
}

func Poweroff() {
	for {
		_ = ioutil.WriteFile("/proc/sysrq-trigger", []byte{'o'}, 0600) // errcheck: POWERING OFF!
	}
}
