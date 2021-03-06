package log

import (
	"github.com/Sirupsen/logrus"
)

type Entry logrus.Fields

type FieldsMap logrus.Fields

func (e *Entry) F(key string, value interface{}) *Entry {
	(*e)[key] = value
	return e
}

func (e *Entry) Fs(kvs ...interface{}) *Entry {
	for i := 0; i < len(kvs); i += 2 {
		(*e)[kvs[i].(string)] = kvs[i+1]
	}
	return e
}

func (e *Entry) E(err error) *Entry {
	(*e)["error"] = err
	return e
}

func (e *Entry) Clone() (entry *Entry) {
	entry = &Entry{}
	for k, v := range *e {
		(*entry)[k] = v
	}
	return
}

func (e *Entry) Infoln(args ...interface{}) {
	logging.println(infoLog, logrus.Fields(*e), args...)
}

func (e *Entry) Warningln(args ...interface{}) {
	logging.println(warningLog, logrus.Fields(*e), args...)
}

func (e *Entry) Errorln(args ...interface{}) {
	logging.println(errorLog, logrus.Fields(*e), args...)
}

func (e *Entry) Fatalln(args ...interface{}) {
	logging.println(fatalLog, logrus.Fields(*e), args...)
}

func (e *Entry) Info(args ...interface{}) {
	logging.print(infoLog, logrus.Fields(*e), args...)
}

func (e *Entry) Warning(args ...interface{}) {
	logging.print(warningLog, logrus.Fields(*e), args...)
}

func (e *Entry) Error(args ...interface{}) {
	logging.print(errorLog, logrus.Fields(*e), args...)
}

func (e *Entry) Fatal(args ...interface{}) {
	logging.print(fatalLog, logrus.Fields(*e), args...)
}

func (e *Entry) Infof(format string, args ...interface{}) {
	logging.printf(infoLog, logrus.Fields(*e), format, args...)
}

func (e *Entry) Warningf(format string, args ...interface{}) {
	logging.printf(warningLog, logrus.Fields(*e), format, args...)
}

func (e *Entry) Errorf(format string, args ...interface{}) {
	logging.printf(errorLog, logrus.Fields(*e), format, args...)
}

func (e *Entry) Fatalf(format string, args ...interface{}) {
	logging.printf(fatalLog, logrus.Fields(*e), format, args...)
}

// Verbose support.

type VerboseEntry struct {
	verbose *Verbose
	entry   *Entry
}

func (ve *VerboseEntry) F(key string, value interface{}) *VerboseEntry {
	if *ve.verbose {
		ve.entry.F(key, value)
	}
	return ve
}

func (ve *VerboseEntry) Fs(kvs ...interface{}) *VerboseEntry {
	if *ve.verbose {
		ve.entry.Fs(kvs...)
	}
	return ve
}

func (ve *VerboseEntry) Clone() (ventry *VerboseEntry) {
	ventry = &VerboseEntry{ve.verbose, nil}
	if *ve.verbose {
		ventry.entry = &Entry{}
		for k, v := range *ve.entry {
			(*ventry.entry)[k] = v
		}
	}
	return
}

func (ve *VerboseEntry) Info(args ...interface{}) {
	if *ve.verbose {
		logging.print(infoLog, logrus.Fields(*ve.entry), args...)
	}
}

func (ve *VerboseEntry) Infoln(args ...interface{}) {
	if *ve.verbose {
		logging.println(infoLog, logrus.Fields(*ve.entry), args...)
	}
}

func (ve *VerboseEntry) Infof(format string, args ...interface{}) {
	if *ve.verbose {
		logging.printf(infoLog, logrus.Fields(*ve.entry), format, args...)
	}
}
