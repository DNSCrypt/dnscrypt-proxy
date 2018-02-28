package pidfile_test

import (
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/facebookgo/pidfile"
)

// Make a temporary file, remove it, and return it's path with the hopes that
// no one else create a file with that name.
func tempfilename(t *testing.T) string {
	file, err := ioutil.TempFile("", "pidfile-test")
	if err != nil {
		t.Fatal(err)
	}

	err = file.Close()
	if err != nil {
		t.Fatal(err)
	}

	err = os.Remove(file.Name())
	if err != nil {
		t.Fatal(err)
	}

	return file.Name()
}

func TestGetSetPath(t *testing.T) {
	p := tempfilename(t)
	defer os.Remove(p)
	pidfile.SetPidfilePath(p)

	if a := pidfile.GetPidfilePath(); a != p {
		t.Fatalf("was expecting %s but got %s", p, a)
	}
}

func TestSimple(t *testing.T) {
	p := tempfilename(t)
	defer os.Remove(p)
	pidfile.SetPidfilePath(p)

	if err := pidfile.Write(); err != nil {
		t.Fatal(err)
	}

	pid, err := pidfile.Read()
	if err != nil {
		t.Fatal(err)
	}

	if os.Getpid() != pid {
		t.Fatalf("was expecting %d but got %d", os.Getpid(), pid)
	}
}

func TestPidfileNotConfigured(t *testing.T) {
	pidfile.SetPidfilePath("")

	err := pidfile.Write()
	if err == nil {
		t.Fatal("was expecting an error")
	}
	if !pidfile.IsNotConfigured(err) {
		t.Fatalf("was expecting IsNotConfigured error but got: %s", err)
	}

	_, err = pidfile.Read()
	if err == nil {
		t.Fatal("was expecting an error")
	}
	if !pidfile.IsNotConfigured(err) {
		t.Fatalf("was expecting IsNotConfigured error but got: %s", err)
	}
}

func TestNonIsConfiguredError(t *testing.T) {
	err := errors.New("foo")
	if pidfile.IsNotConfigured(err) {
		t.Fatal("should be false")
	}
}

func TestMakesDirectories(t *testing.T) {
	dir := tempfilename(t)
	defer os.RemoveAll(dir)
	p := filepath.Join(dir, "pidfile")
	pidfile.SetPidfilePath(p)

	if err := pidfile.Write(); err != nil {
		t.Fatal(err)
	}

	pid, err := pidfile.Read()
	if err != nil {
		t.Fatal(err)
	}

	if os.Getpid() != pid {
		t.Fatalf("was expecting %d but got %d", os.Getpid(), pid)
	}
}
