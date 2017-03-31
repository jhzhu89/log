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
	ctx := Field("key", "value").Field("key1", "value1").Field("key3", 1).
		Field("key4", 2).Field("key5", 3).Field("key6", 3)
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
	ctx.Err(fmt.Errorf("this is an error: %v", 100)).Infof("test")

	V(0).Field("key", "value").Info("haha")
	V(0).Field("key1", "value").Info("haha")
	//Infof("%#v", V(0).WithField("key", 1))
	ctx = Field("key", "what")
	ctx.Info("test")

	V(0).Fields(FieldsMap{"key1": "value"}).Infoln("a test")
}
