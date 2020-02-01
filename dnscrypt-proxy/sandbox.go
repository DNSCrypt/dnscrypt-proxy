package main

import (
	"os"
	"os/exec"
	"path/filepath"

	"github.com/facebookgo/pidfile"
)

// Determine the minimum set of privileges and files we need to access. We cannot expand our privileges
// after this function is called. This is only enforced on openbsd, but serves as a specification and may
// inform the creation of manual sandbox rules on other platforms.
//
// N.B. If you add any promises in this function also add them to the first Pledge call in main!
func InitSandbox(config *Config, flags *ConfigFlags) {
	// need to do this first before we start unveiling things to get access to directories
	execPath, err := exec.LookPath(os.Args[0])
	if err == nil {
		path, err := filepath.Abs(execPath)
		if err == nil {
			execPath = path
		} else {
			execPath = ""
		}
	} else {
		execPath = ""
	}

	// minimum promises needed to function
	// N.B. If you add any promises in this function also add them to the first Pledge call
	//      in main!
	promises := "cpath fattr inet rpath stdio wpath"

	Unveil("/dev/random", "r")
	Unveil("/dev/urandom", "r")
	Unveil("/etc/ssl/cert.pem", "r")

	if !config.IgnoreSystemDNS {
		promises += " dns"
	}

	if !config.OfflineMode {
		for _, cfgSource := range config.SourcesConfig {
			UnveilContainingDirectoryOf(cfgSource.CacheFile, "crw")
		}
	}

	if config.UseSyslog {
		promises += " unix"
		Unveil("/dev/log", "w")
	} else if config.LogFile != nil {
		Unveil(*config.LogFile, "cw")
	}

	if *flags.Check || *flags.List || *flags.ListAll {
		PledgePromises(promises)
		return
	}

	if len(config.UserName) > 0 && !*flags.Child {
		if len(execPath) > 0 {
			Unveil(execPath, "rx")
		}
		Unveil("/etc/passwd", "r")
		PledgePromises(promises + " exec id")
		return
	}

	if pidFilePath := pidfile.GetPidfilePath(); len(pidFilePath) > 1 {
		// doesn't work because of os.MkdirAll
		Unveil(pidFilePath, "cw")
	}

	if *flags.ShowCerts {
		PledgePromises(promises)
		return
	}

	Unveil(execPath, "r")

	// All these logs don't work because of os.MkdirAll

	Unveil(config.LocalDoH.CertFile, "r")
	Unveil(config.LocalDoH.CertKeyFile, "r")

	UnveilContainingDirectoryOf(config.QueryLog.File, "cw")

	UnveilContainingDirectoryOf(config.NxLog.File, "cw")

	Unveil(config.BlockName.File, "r")
	UnveilContainingDirectoryOf(config.BlockName.LogFile, "cw")

	Unveil(config.WhitelistName.File, "r")
	UnveilContainingDirectoryOf(config.WhitelistName.LogFile, "cw")

	Unveil(config.BlockIP.File, "r")
	UnveilContainingDirectoryOf(config.BlockIP.LogFile, "cw")

	Unveil(config.ForwardFile, "r")

	Unveil(config.CloakFile, "r")

	PledgePromises(promises)
}
