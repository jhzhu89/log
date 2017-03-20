package log

import (
	"testing"
)

func TestLog(t *testing.T) {
	Infof("??%v", 1)
	Warningf("??%v", 1)
	Errorf("??%v", 1)
	Fatalf("??%v", 1)
	//Exitf("??%v", 2)

	Infof("logging.verbosity: %v", logging.verbosity.get())

	V(0).Infof("?? verbose %v", 2)
}
