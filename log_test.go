package log

import (
	"fmt"
	"testing"
)

// TODO: add test cases.
func TestLog(t *testing.T) {
	Infof("??%v", 1)
	Warningf("??%v", 1)
	Errorf("??%v", 1)
	ErrorDepth(3, "???")
	Error("???")
	Error("???")
	Error("???", "!!!")
	Errorln("errorln", "err")
	Errorln("errorln")
	//Fatalf("??%v", 1)
	//Exitf("??%v", 2)

	Infof("logging.verbosity: %v", logging.verbosity.get())

	V(0).Infof("?? verbose %v", 2)

	V(1).Infof("%v", "just a test")
	ctx := F("key", "value").F("key1", "value1").F("key3", 1).
		F("key4", 2).F("key5", 3).F("key6", 3)
	ctx.Infoln("a", 1, "2")
	ctx.Errorln("a", 1, "2")
	//ctx.Fatalln("a", 1, "2")
	ctx.Warningln("a", 1, "2")

	ctx.Info("i")
	ctx.Warning("w")
	ctx.Error("e")
	//ctx.Fatal("f")
	ctx.Infof("i")
	ctx.Warningf("w")
	ctx.Errorf("e")
	//ctx.Fatalf("f %v", "FF")
	ctx.E(fmt.Errorf("this is an error: %v", 100)).Infof("test")

	V(0).F("key", "value").Info("haha")
	V(0).F("key1", "value").Info("haha")
	//Infof("%#v", V(0).WithField("key", 1))
	ctx = F("key", "what")
	ctx.Info("test")

	V(0).Fs("key1", "value", "key2?", "value2").Infoln("a test")
	ctx.Clone().Fs("key1", "value", "key2?", "value2").Error("a test")
}
