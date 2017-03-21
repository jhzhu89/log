package log

import (
	"github.com/Sirupsen/logrus"
)

type Entry logrus.Fields

type Fields logrus.Fields

func (e *Entry) WithField(key string, value interface{}) *Entry {
	(*e)[key] = value
	return e
}

func (e *Entry) WithFields(fields Fields) *Entry {
	for k, v := range fields {
		(*e)[k] = v
	}
	return e
}

func (e *Entry) WithError(err error) *Entry {
	(*e)["error"] = err
	return e
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

func (ve *VerboseEntry) WithField(key string, value interface{}) *VerboseEntry {
	if *ve.verbose {
		ve.entry.WithField(key, value)
	}
	return ve
}

func (ve *VerboseEntry) WithFields(fields Fields) *VerboseEntry {
	if *ve.verbose {
		ve.entry.WithFields(fields)
	}
	return ve
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
