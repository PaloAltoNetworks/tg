// +build mage

// nolint
package main

import (
	"github.com/aporeto-inc/domingo/golang"
	"github.com/magefile/mage/mg"
)

// Init initializes the project.
func Init() {
	mg.SerialDeps(
		domingo.InstallDependencies,
		Version,
	)
}

// Version writes the versions file.
func Version() error {
	return domingo.WriteVersion()
}

// Test runs the unit tests.
func Test() {
	mg.Deps(
		domingo.Lint,
		domingo.Test,
	)
}

// Build runs builds the project for all platforms.
func Build() {
	mg.SerialDeps(
		func() error { return domingo.BuildFor("linux", domingo.BuildLinux) },
		func() error { return domingo.BuildFor("darwin", domingo.BuildDarwin) },
	)
}

// Package prepares the docker container.
func Package() error {
	return domingo.PackageFrom("build/linux/tg")
}

// Docker builds the docker container.
func Docker() error {
	mg.SerialDeps(
		domingo.BuildLinux,
		Package,
	)

	return domingo.Container()
}
