//go:build race

package conformance

// raceEnabled reports whether the test binary was built with the race detector.
// What it is read for here is cost rather than behaviour, and offsetsDriven
// (properties_test.go) is where that is argued.
const raceEnabled = true
