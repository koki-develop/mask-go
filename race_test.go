//go:build race

package mask

// raceEnabled reports whether the test binary was built with the race
// detector, which allocates on paths that otherwise do not.
const raceEnabled = true
