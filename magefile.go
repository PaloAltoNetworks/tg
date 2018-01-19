// +build mage

// nolint
package main

import (
	"github.com/aporeto-inc/domingo/golang"
	"github.com/magefile/mage/mg"
)

func init() {
	domingo.SetProjectName("tg")
}

// Init initialize the project.
func Init() {
	mg.Deps(
		domingo.Init,
		Version,
	)
}

// Version write the version file.
func Version() {
	mg.Deps(
		domingo.WriteVersion,
	)
}

// Test runs unit tests.
func Test() {
	mg.Deps(
		domingo.Lint,
		domingo.Test,
	)
}

// Build runs builds the project and prepare the docker container.
func Build() {
	mg.SerialDeps(
		func() error { return domingo.BuildFor("linux", domingo.BuildLinux) },
		func() error { return domingo.BuildFor("darwin", domingo.BuildDarwin) },
		func() error { return domingo.PackageFrom("build/linux/tg") },
	)
}
