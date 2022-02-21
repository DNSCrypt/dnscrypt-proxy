// Package ewma: exponentially weighted moving averages
package ewma

// New EWMA by moving window size.
func NewMovingAverage(slide int) *EWMA {
	return &EWMA{
		slide: slide,
	}
}

type EWMA struct {
	// Too big slide is meaningless.
	slide int
	// Count before warmed up.
	count int
	// Decay by slide size.
	decay float64
	// The average.
	value float64
}

// Add a value to the series and update the moving average.
func (a *EWMA) Add(value float64) {
	switch {
	case a.count <= a.slide:
		a.count++
		a.decay = 2 / float64(a.count + 1)
		a.value = a.value * (1 - a.decay) + value * a.decay
	default:
		a.value = a.value * (1 - a.decay) + value * a.decay
	}
}

// Return the current EWMA value.
func (a *EWMA) Value() float64 {
	return a.value
}

// Set the EWMA value for continuing.
func (a *EWMA) Set(value float64) {
	a.value = value
	a.decay = 2 / float64(a.slide + 1)
	a.count = a.slide + 1
}
