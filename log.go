// Go support for leveled logs, analogous to https://code.google.com/p/google-glog/
//
// Copyright 2013 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//
// Package log exploits glog's APIs while delegates the real work to logrus. Some
// functions are removed since they are not needed. Some other types, functions are
// added to adapt to the logrus, for example, Entry, VerboseEntry, etc.
//

package log

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Sirupsen/logrus"
)

// severity identifies the sort of log: info, warning etc. It also implements
// the flag.Value interface. The -stderrthreshold flag is of type severity and
// should be modified only through the flag.Value interface. The values match
// the corresponding constants in C++.
type severity int32 // sync/atomic int32

// These constants identify the log levels in order of increasing severity.
// A message written to a high-severity log file is also written to each
// lower-severity log file.
const (
	infoLog severity = iota
	warningLog
	errorLog
	fatalLog
	numSeverity = 4
)

const srcMeta = "src"

var severityName = []string{
	infoLog:    "INFO",
	warningLog: "WARNING",
	errorLog:   "ERROR",
	fatalLog:   "FATAL",
}

// get returns the value of the severity.
func (s *severity) get() severity {
	return severity(atomic.LoadInt32((*int32)(s)))
}

// set sets the value of the severity.
func (s *severity) set(val severity) {
	atomic.StoreInt32((*int32)(s), int32(val))
}

// String is part of the flag.Value interface.
func (s *severity) String() string {
	return strconv.FormatInt(int64(*s), 10)
}

// Get is part of the flag.Value interface.
func (s *severity) Get() interface{} {
	return *s
}

// Set is part of the flag.Value interface.
func (s *severity) Set(value string) error {
	var threshold severity
	// Is it a known name?
	if v, ok := severityByName(value); ok {
		threshold = v
	} else {
		v, err := strconv.Atoi(value)
		if err != nil {
			return err
		}
		threshold = severity(v)
	}
	logging.stderrThreshold.set(threshold)
	return nil
}

func severityByName(s string) (severity, bool) {
	s = strings.ToUpper(s)
	for i, name := range severityName {
		if name == s {
			return severity(i), true
		}
	}
	return 0, false
}

// Level is exported because it appears in the arguments to V and is
// the type of the v flag, which can be set programmatically.
// It's a distinct type because we want to discriminate it from logType.
// Variables of type level are only changed under logging.mu.
// The -v flag is read only with atomic ops, so the state of the logging
// module is consistent.

// Level is treated as a sync/atomic int32.

// Level specifies a level of verbosity for V logs. *Level implements
// flag.Value; the -v flag is of type Level and should be modified
// only through the flag.Value interface.
type Level int32

// get returns the value of the Level.
func (l *Level) get() Level {
	return Level(atomic.LoadInt32((*int32)(l)))
}

// set sets the value of the Level.
func (l *Level) set(val Level) {
	atomic.StoreInt32((*int32)(l), int32(val))
}

// String is part of the flag.Value interface.
func (l *Level) String() string {
	return strconv.FormatInt(int64(*l), 10)
}

// Get is part of the flag.Value interface.
func (l *Level) Get() interface{} {
	return *l
}

// Set is part of the flag.Value interface.
func (l *Level) Set(value string) error {
	v, err := strconv.Atoi(value)
	if err != nil {
		return err
	}
	logging.mu.Lock()
	defer logging.mu.Unlock()
	logging.setVState(Level(v), logging.vmodule.filter, false)
	return nil
}

// moduleSpec represents the setting of the -vmodule flag.
type moduleSpec struct {
	filter []modulePat
}

// modulePat contains a filter for the -vmodule flag.
// It holds a verbosity level and a file pattern to match.
type modulePat struct {
	pattern string
	literal bool // The pattern is a literal string
	level   Level
}

// match reports whether the file matches the pattern. It uses a string
// comparison if the pattern contains no metacharacters.
func (m *modulePat) match(file string) bool {
	if m.literal {
		return file == m.pattern
	}
	match, _ := filepath.Match(m.pattern, file)
	return match
}

func (m *moduleSpec) String() string {
	// Lock because the type is not atomic. TODO: clean this up.
	logging.mu.Lock()
	defer logging.mu.Unlock()
	var b bytes.Buffer
	for i, f := range m.filter {
		if i > 0 {
			b.WriteRune(',')
		}
		fmt.Fprintf(&b, "%s=%d", f.pattern, f.level)
	}
	return b.String()
}

// Get is part of the (Go 1.2)  flag.Getter interface. It always returns nil for this flag type since the
// struct is not exported.
func (m *moduleSpec) Get() interface{} {
	return nil
}

var errVmoduleSyntax = errors.New("syntax error: expect comma-separated list of filename=N")

// Syntax: -vmodule=recordio=2,file=1,gfs*=3
func (m *moduleSpec) Set(value string) error {
	var filter []modulePat
	for _, pat := range strings.Split(value, ",") {
		if len(pat) == 0 {
			// Empty strings such as from a trailing comma can be ignored.
			continue
		}
		patLev := strings.Split(pat, "=")
		if len(patLev) != 2 || len(patLev[0]) == 0 || len(patLev[1]) == 0 {
			return errVmoduleSyntax
		}
		pattern := patLev[0]
		v, err := strconv.Atoi(patLev[1])
		if err != nil {
			return errors.New("syntax error: expect comma-separated list of filename=N")
		}
		if v < 0 {
			return errors.New("negative value for vmodule level")
		}
		if v == 0 {
			continue // Ignore. It's harmless but no point in paying the overhead.
		}
		// TODO: check syntax of filter?
		filter = append(filter, modulePat{pattern, isLiteral(pattern), Level(v)})
	}
	logging.mu.Lock()
	defer logging.mu.Unlock()
	logging.setVState(logging.verbosity, filter, true)
	return nil
}

// isLiteral reports whether the pattern is a literal string, that is, has no metacharacters
// that require filepath.Match to be called to match the pattern.
func isLiteral(pattern string) bool {
	return !strings.ContainsAny(pattern, `\*?[]`)
}

// traceLocation represents the setting of the -log_backtrace_at flag.
type traceLocation struct {
	file string
	line int
}

// isSet reports whether the trace location has been specified.
// logging.mu is held.
func (t *traceLocation) isSet() bool {
	return t.line > 0
}

// match reports whether the specified file and line matches the trace location.
// The argument file name is the full path, not the basename specified in the flag.
// logging.mu is held.
func (t *traceLocation) match(file string, line int) bool {
	if t.line != line {
		return false
	}
	if i := strings.LastIndex(file, "/"); i >= 0 {
		file = file[i+1:]
	}
	return t.file == file
}

func (t *traceLocation) String() string {
	// Lock because the type is not atomic. TODO: clean this up.
	logging.mu.Lock()
	defer logging.mu.Unlock()
	return fmt.Sprintf("%s:%d", t.file, t.line)
}

// Get is part of the (Go 1.2) flag.Getter interface. It always returns nil for this flag type since the
// struct is not exported
func (t *traceLocation) Get() interface{} {
	return nil
}

var errTraceSyntax = errors.New("syntax error: expect file.go:234")

// Syntax: -log_backtrace_at=gopherflakes.go:234
// Note that unlike vmodule the file extension is included here.
func (t *traceLocation) Set(value string) error {
	if value == "" {
		// Unset.
		t.line = 0
		t.file = ""
	}
	fields := strings.Split(value, ":")
	if len(fields) != 2 {
		return errTraceSyntax
	}
	file, line := fields[0], fields[1]
	if !strings.Contains(file, ".") {
		return errTraceSyntax
	}
	v, err := strconv.Atoi(line)
	if err != nil {
		return errTraceSyntax
	}
	if v <= 0 {
		return errors.New("negative or zero value for level")
	}
	logging.mu.Lock()
	defer logging.mu.Unlock()
	t.line = v
	t.file = file
	return nil
}

func initLogrus() {
	logging.logrus = logrus.New()
	formatter := TextFormatter{TimestampFormat: time.StampMicro, FullTimestamp: true}
	logging.logrus.Formatter = &formatter
	logging.logrus.Level = logrus.DebugLevel // Set to lowest.
}

func init() {
	flag.Var(&logging.verbosity, "v", "log level for V logs")
	flag.Var(&logging.stderrThreshold, "stderrthreshold", "logs at or above this threshold go to stderr")
	flag.Var(&logging.vmodule, "vmodule", "comma-separated list of pattern=N settings for file-filtered logging")
	flag.Var(&logging.traceLocation, "log_backtrace_at", "when logging hits line file:N, emit a stack trace")

	// Default stderrThreshold is ERROR.
	logging.stderrThreshold = errorLog

	initLogrus()
	logging.setVState(0, nil, false)
}

// loggingT collects all the global state of the logging setup.
type loggingT struct {
	// Level flag. Handled atomically.
	stderrThreshold severity // The -stderrthreshold flag.

	// mu protects the remaining elements of this structure and is
	// used to synchronize logging.
	mu sync.Mutex
	// pcs is used in V to avoid an allocation when computing the caller's PC.
	pcs [1]uintptr
	// vmap is a cache of the V Level for each V() call site, identified by PC.
	// It is wiped whenever the vmodule flag changes state.
	vmap map[uintptr]Level
	// filterLength stores the length of the vmodule filter chain. If greater
	// than zero, it means vmodule is enabled. It may be read safely
	// using sync.LoadInt32, but is only modified under mu.
	filterLength int32
	// traceLocation is the state of the -log_backtrace_at flag.
	traceLocation traceLocation
	// These flags are modified only under lock, although verbosity may be fetched
	// safely using atomic.LoadInt32.
	vmodule   moduleSpec // The state of the -vmodule flag.
	verbosity Level      // V logging level, the value of the -v flag/

	logrus *logrus.Logger
}

var logging loggingT

// setVState sets a consistent state for V logging.
// l.mu is held.
func (l *loggingT) setVState(verbosity Level, filter []modulePat, setFilter bool) {
	// Turn verbosity off so V will not fire while we are in transition.
	logging.verbosity.set(0)
	// Ditto for filter length.
	atomic.StoreInt32(&logging.filterLength, 0)

	// Set the new filters and wipe the pc->Level map if the filter has changed.
	if setFilter {
		logging.vmodule.filter = filter
		logging.vmap = make(map[uintptr]Level)
	}

	// Things are consistent now, so enable filtering and verbosity.
	// They are enabled in order opposite to that in V.
	atomic.StoreInt32(&logging.filterLength, int32(len(filter)))
	logging.verbosity.set(verbosity)
}

func (l *loggingT) fileAndLine(depth int) (string, int) {
	_, file, line, ok := runtime.Caller(3 + depth)
	if !ok {
		file = "???"
		line = 1
	} else {
		slash := strings.LastIndex(file, "/")
		if slash >= 0 {
			file = file[slash+1:]
		}
	}
	return file, line
}

func (l *loggingT) contextLogger(file string, line int, fields logrus.Fields) *logrus.Entry {
	return l.logrus.WithField(srcMeta, fmt.Sprintf("%s:%v", file, line)).WithFields(fields)
}

func (l *loggingT) traceLoc(file string, line int) string {
	if l.traceLocation.isSet() {
		if l.traceLocation.match(file, line) {
			var buf bytes.Buffer
			buf.WriteString("\n")
			buf.Write(stacks(false))
			return buf.String()
		}
	}
	return ""
}

func (l *loggingT) println(s severity, fields logrus.Fields, args ...interface{}) {
	if s < l.stderrThreshold.get() {
		return
	}
	file, line := l.fileAndLine(0)
	ctx := l.contextLogger(file, line, fields)
	trace := l.traceLoc(file, line)
	if trace != "" {
		args = append(args, trace)
	}
	switch s {
	case infoLog:
		ctx.Infoln(args...)
	case warningLog:
		ctx.Warnln(args...)
	case errorLog:
		ctx.Errorln(args...)
	case fatalLog:
		ctx.Fatalln(args...)
	default:
	}

}

func (l *loggingT) print(s severity, fields logrus.Fields, args ...interface{}) {
	if s < l.stderrThreshold.get() {
		return
	}
	l.printDepth(s, 1, fields, args...)
}

func (l *loggingT) printDepth(s severity, depth int, fields logrus.Fields, args ...interface{}) {
	if s < l.stderrThreshold.get() {
		return
	}
	file, line := l.fileAndLine(depth)
	ctx := l.contextLogger(file, line, fields)
	trace := l.traceLoc(file, line)
	if trace != "" {
		args = append(args, trace)
	}
	switch s {
	case infoLog:
		ctx.Info(args...)
	case warningLog:
		ctx.Warn(args...)
	case errorLog:
		ctx.Error(args...)
	case fatalLog:
		ctx.Fatal(args...)
	default:
	}
}

func (l *loggingT) printf(s severity, fields logrus.Fields, format string, args ...interface{}) {
	if s < l.stderrThreshold.get() {
		return
	}
	file, line := l.fileAndLine(0)
	ctx := l.contextLogger(file, line, fields)
	trace := l.traceLoc(file, line)
	if trace != "" {
		format += "\n%s"
		args = append(args, trace)
	}
	switch s {
	case infoLog:
		ctx.Infof(format, args...)
	case warningLog:
		ctx.Warnf(format, args...)
	case errorLog:
		ctx.Errorf(format, args...)
	case fatalLog:
		ctx.Fatalf(format, args...)
	default:
	}
}

// stacks is a wrapper for runtime.Stack that attempts to recover the data for all goroutines.
func stacks(all bool) []byte {
	// We don't know how big the traces are, so grow a few times if they don't fit. Start large, though.
	n := 10000
	if all {
		n = 100000
	}
	var trace []byte
	for i := 0; i < 5; i++ {
		trace = make([]byte, n)
		nbytes := runtime.Stack(trace, all)
		if nbytes < len(trace) {
			return trace[:nbytes]
		}
		n *= 2
	}
	return trace
}

// setV computes and remembers the V level for a given PC
// when vmodule is enabled.
// File pattern matching takes the basename of the file, stripped
// of its .go suffix, and uses filepath.Match, which is a little more
// general than the *? matching used in C++.
// l.mu is held.
func (l *loggingT) setV(pc uintptr) Level {
	fn := runtime.FuncForPC(pc)
	file, _ := fn.FileLine(pc)
	// The file is something like /a/b/c/d.go. We want just the d.
	if strings.HasSuffix(file, ".go") {
		file = file[:len(file)-3]
	}
	if slash := strings.LastIndex(file, "/"); slash >= 0 {
		file = file[slash+1:]
	}
	for _, filter := range l.vmodule.filter {
		if filter.match(file) {
			l.vmap[pc] = filter.level
			return filter.level
		}
	}
	l.vmap[pc] = 0
	return 0
}

// Verbose is a boolean type that implements Infof (like Printf) etc.
// See the documentation of V for more information.
type Verbose bool

// V reports whether verbosity at the call site is at least the requested level.
// The returned value is a boolean of type Verbose, which implements Info, Infoln
// and Infof. These methods will write to the Info log if called.
// Thus, one may write either
//	if glog.V(2) { glog.Info("log this") }
// or
//	glog.V(2).Info("log this")
// The second form is shorter but the first is cheaper if logging is off because it does
// not evaluate its arguments.
//
// Whether an individual call to V generates a log record depends on the setting of
// the -v and --vmodule flags; both are off by default. If the level in the call to
// V is at least the value of -v, or of -vmodule for the source file containing the
// call, the V call will log.
func V(level Level) Verbose {
	// This function tries hard to be cheap unless there's work to do.
	// The fast path is two atomic loads and compares.

	// Here is a cheap but safe test to see if V logging is enabled globally.
	if logging.verbosity.get() >= level {
		return Verbose(true)
	}

	// It's off globally but it vmodule may still be set.
	// Here is another cheap but safe test to see if vmodule is enabled.
	if atomic.LoadInt32(&logging.filterLength) > 0 {
		// Now we need a proper lock to use the logging structure. The pcs field
		// is shared so we must lock before accessing it. This is fairly expensive,
		// but if V logging is enabled we're slow anyway.
		logging.mu.Lock()
		defer logging.mu.Unlock()
		if runtime.Callers(2, logging.pcs[:]) == 0 {
			return Verbose(false)
		}
		v, ok := logging.vmap[logging.pcs[0]]
		if !ok {
			v = logging.setV(logging.pcs[0])
		}
		return Verbose(v >= level)
	}
	return Verbose(false)
}

// Info is equivalent to the global Info function, guarded by the value of v.
// See the documentation of V for usage.
func (v Verbose) Info(args ...interface{}) {
	if v {
		logging.print(infoLog, nil, args...)
	}
}

// Infoln is equivalent to the global Infoln function, guarded by the value of v.
// See the documentation of V for usage.
func (v Verbose) Infoln(args ...interface{}) {
	if v {
		logging.println(infoLog, nil, args...)
	}
}

// Infof is equivalent to the global Infof function, guarded by the value of v.
// See the documentation of V for usage.
func (v Verbose) Infof(format string, args ...interface{}) {
	if v {
		logging.printf(infoLog, nil, format, args...)
	}
}

func (v Verbose) F(key string, value interface{}) (ve *VerboseEntry) {
	if v {
		ve = &VerboseEntry{&v, (&Entry{}).F(key, value)}
	} else {
		ve = &VerboseEntry{&v, nil}
	}
	return
}

func (v Verbose) Fs(fields FieldsMap) (ve *VerboseEntry) {
	if v {
		ve = &VerboseEntry{&v, (&Entry{}).Fs(fields)}
	} else {
		ve = &VerboseEntry{&v, nil}
	}
	return
}

// Info logs to the INFO log.
// Arguments are handled in the manner of fmt.Print; a newline is appended if missing.
func Info(args ...interface{}) {
	logging.print(infoLog, nil, args...)
}

// InfoDepth acts as Info but uses depth to determine which call frame to log.
// InfoDepth(0, "msg") is the same as Info("msg").
func InfoDepth(depth int, args ...interface{}) {
	logging.printDepth(infoLog, depth, nil, args...)
}

// Infoln logs to the INFO log.
// Arguments are handled in the manner of fmt.Println; a newline is appended if missing.
func Infoln(args ...interface{}) {
	logging.println(infoLog, nil, args...)
}

// Infof logs to the INFO log.
// Arguments are handled in the manner of fmt.Printf; a newline is appended if missing.
func Infof(format string, args ...interface{}) {
	logging.printf(infoLog, nil, format, args...)
}

// Warning logs to the WARNING and INFO logs.
// Arguments are handled in the manner of fmt.Print; a newline is appended if missing.
func Warning(args ...interface{}) {
	logging.print(warningLog, nil, args...)
}

// WarningDepth acts as Warning but uses depth to determine which call frame to log.
// WarningDepth(0, "msg") is the same as Warning("msg").
func WarningDepth(depth int, args ...interface{}) {
	logging.printDepth(warningLog, depth, nil, args...)
}

// Warningln logs to the WARNING and INFO logs.
// Arguments are handled in the manner of fmt.Println; a newline is appended if missing.
func Warningln(args ...interface{}) {
	logging.println(warningLog, nil, args...)
}

// Warningf logs to the WARNING and INFO logs.
// Arguments are handled in the manner of fmt.Printf; a newline is appended if missing.
func Warningf(format string, args ...interface{}) {
	logging.printf(warningLog, nil, format, args...)
}

// Error logs to the ERROR, WARNING, and INFO logs.
// Arguments are handled in the manner of fmt.Print; a newline is appended if missing.
func Error(args ...interface{}) {
	logging.print(errorLog, nil, args...)
}

// ErrorDepth acts as Error but uses depth to determine which call frame to log.
// ErrorDepth(0, "msg") is the same as Error("msg").
func ErrorDepth(depth int, args ...interface{}) {
	logging.printDepth(errorLog, depth, nil, args...)
}

// Errorln logs to the ERROR, WARNING, and INFO logs.
// Arguments are handled in the manner of fmt.Println; a newline is appended if missing.
func Errorln(args ...interface{}) {
	logging.println(errorLog, nil, args...)
}

// Errorf logs to the ERROR, WARNING, and INFO logs.
// Arguments are handled in the manner of fmt.Printf; a newline is appended if missing.
func Errorf(format string, args ...interface{}) {
	logging.printf(errorLog, nil, format, args...)
}

// Fatal logs to the FATAL, ERROR, WARNING, and INFO logs,
// including a stack trace of all running goroutines, then calls os.Exit(255).
// Arguments are handled in the manner of fmt.Print; a newline is appended if missing.
func Fatal(args ...interface{}) {
	logging.print(fatalLog, nil, args...)
}

// FatalDepth acts as Fatal but uses depth to determine which call frame to log.
// FatalDepth(0, "msg") is the same as Fatal("msg").
func FatalDepth(depth int, args ...interface{}) {
	logging.printDepth(fatalLog, depth, nil, args...)
}

// Fatalln logs to the FATAL, ERROR, WARNING, and INFO logs,
// including a stack trace of all running goroutines, then calls os.Exit(255).
// Arguments are handled in the manner of fmt.Println; a newline is appended if missing.
func Fatalln(args ...interface{}) {
	logging.println(fatalLog, nil, args...)
}

// Fatalf logs to the FATAL, ERROR, WARNING, and INFO logs,
// including a stack trace of all running goroutines, then calls os.Exit(255).
// Arguments are handled in the manner of fmt.Printf; a newline is appended if missing.
func Fatalf(format string, args ...interface{}) {
	if atomic.LoadUint32(&fatalNoStacks) == 0 {
		trace := stacks(true)
		args = append(args, trace)
		logging.printf(fatalLog, nil, format+"\n%s", args...)
		return
	}
	logging.printf(fatalLog, nil, format, args...)
}

// fatalNoStacks is non-zero if we are to exit without dumping goroutine stacks.
// It allows Exit and relatives to use the Fatal logs.
var fatalNoStacks uint32

// Exit logs to the FATAL, ERROR, WARNING, and INFO logs, then calls os.Exit(1).
// Arguments are handled in the manner of fmt.Print; a newline is appended if missing.
func Exit(args ...interface{}) {
	atomic.StoreUint32(&fatalNoStacks, 1)
	logging.print(fatalLog, nil, args...)
}

// ExitDepth acts as Exit but uses depth to determine which call frame to log.
// ExitDepth(0, "msg") is the same as Exit("msg").
func ExitDepth(depth int, args ...interface{}) {
	atomic.StoreUint32(&fatalNoStacks, 1)
	logging.printDepth(fatalLog, depth, nil, args...)
}

// Exitln logs to the FATAL, ERROR, WARNING, and INFO logs, then calls os.Exit(1).
func Exitln(args ...interface{}) {
	atomic.StoreUint32(&fatalNoStacks, 1)
	logging.println(fatalLog, nil, args...)
}

// Exitf logs to the FATAL, ERROR, WARNING, and INFO logs, then calls os.Exit(1).
// Arguments are handled in the manner of fmt.Printf; a newline is appended if missing.
func Exitf(format string, args ...interface{}) {
	atomic.StoreUint32(&fatalNoStacks, 1)
	Fatalf(format, args...)
}

// Adds a field to the log entry, note that it doesn't log until you call
// Debug, Print, Info, Warn, Fatal or Panic. It only creates a log entry.
// If you want multiple fields, use `Fields`.
func F(key string, value interface{}) *Entry {
	return (&Entry{}).F(key, value)
}

// Adds a struct of fields to the log entry. All it does is call `WithField` for
// each `Field`.
func Fs(fields FieldsMap) *Entry {
	return (&Entry{}).Fs(fields)
}

// Add an error as single field to the log entry.  All it does is call
// `E` for the given `error`.
func E(err error) *Entry {
	return (&Entry{}).E(err)
}
