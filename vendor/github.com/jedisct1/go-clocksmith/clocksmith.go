package clocksmith

import "time"

const (
	// DefaultGranularity - Maximum duration of actual time.Sleep() calls
	DefaultGranularity = 5 * time.Second
)

// SleepWithGranularity - sleeps for the given amount of time, with the given granularity;
// doesn't pause if the system goes to hibernation
func SleepWithGranularity(duration time.Duration, granularity time.Duration) {
	if duration <= granularity {
		time.Sleep(duration)
		return
	}
	start := time.Now().Unix()
	for {
		time.Sleep(granularity)
		elapsed := time.Duration(time.Now().Unix()-start) * time.Second
		if elapsed < 0 || elapsed > duration {
			break
		} else if elapsed > duration-granularity {
			time.Sleep(duration - elapsed)
			break
		}
	}
}

// Sleep - sleeps for the given amount of time, with the default granularity;
// doesn't pause if the system goes to hibernation
func Sleep(duration time.Duration) {
	SleepWithGranularity(duration, DefaultGranularity)
}
