package main

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

type TimeRange struct {
	after  int
	before int
}

type WeeklyRanges struct {
	ranges [7][]TimeRange
}

type TimeRangeStr struct {
	After  string
	Before string
}

type WeeklyRangesStr struct {
	Sun, Mon, Tue, Wed, Thu, Fri, Sat []TimeRangeStr
}

func daySecsFromStr(str string) (int, error) {
	parts := strings.Split(str, ":")
	if len(parts) != 2 {
		return -1, fmt.Errorf("Syntax error in a time expression: [%s]", str)
	}
	hours, err := strconv.Atoi(parts[0])
	if err != nil || hours < 0 || hours > 23 {
		return -1, fmt.Errorf("Syntax error in a time expression: [%s]", str)
	}
	minutes, err := strconv.Atoi(parts[1])
	if err != nil || minutes < 0 || minutes > 59 {
		return -1, fmt.Errorf("Syntax error in a time expression: [%s]", str)
	}
	return (hours*60 + minutes) * 60, nil
}

func parseTimeRanges(timeRangesStr []TimeRangeStr) ([]TimeRange, error) {
	timeRanges := []TimeRange{}
	for _, timeRangeStr := range timeRangesStr {
		after, err := daySecsFromStr(timeRangeStr.After)
		if err != nil {
			return timeRanges, err
		}
		before, err := daySecsFromStr(timeRangeStr.Before)
		if err != nil {
			return timeRanges, err
		}
		if after == before {
			after, before = -1, 86402
		}
		timeRanges = append(timeRanges, TimeRange{after: after, before: before})
	}
	return timeRanges, nil
}

func parseWeeklyRanges(weeklyRangesStr WeeklyRangesStr) (WeeklyRanges, error) {
	weeklyRanges := WeeklyRanges{}
	weeklyRangesStrX := [7][]TimeRangeStr{weeklyRangesStr.Sun, weeklyRangesStr.Mon, weeklyRangesStr.Tue, weeklyRangesStr.Wed, weeklyRangesStr.Thu, weeklyRangesStr.Fri, weeklyRangesStr.Sat}
	for day, weeklyRangeStrX := range weeklyRangesStrX {
		timeRanges, err := parseTimeRanges(weeklyRangeStrX)
		if err != nil {
			return weeklyRanges, err
		}
		weeklyRanges.ranges[day] = timeRanges
	}
	return weeklyRanges, nil
}

func ParseAllWeeklyRanges(allWeeklyRangesStr map[string]WeeklyRangesStr) (*map[string]WeeklyRanges, error) {
	allWeeklyRanges := make(map[string]WeeklyRanges)
	for weeklyRangesName, weeklyRangesStr := range allWeeklyRangesStr {
		weeklyRanges, err := parseWeeklyRanges(weeklyRangesStr)
		if err != nil {
			return nil, err
		}
		allWeeklyRanges[weeklyRangesName] = weeklyRanges
	}
	return &allWeeklyRanges, nil
}

func (weeklyRanges *WeeklyRanges) Match() bool {
	now := time.Now().Local()
	day := now.Weekday()
	weeklyRange := weeklyRanges.ranges[day]
	if len(weeklyRange) == 0 {
		return false
	}
	hour, min, _ := now.Clock()
	nowX := (hour*60 + min) * 60
	for _, timeRange := range weeklyRange {
		if timeRange.after > timeRange.before {
			if nowX >= timeRange.after || nowX <= timeRange.before {
				return true
			}
		} else if nowX >= timeRange.after && nowX <= timeRange.before {
			return true
		}
	}
	return false
}
