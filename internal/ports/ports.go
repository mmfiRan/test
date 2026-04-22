package ports

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

type Interval struct {
	Lo int
	Hi int
}

type Set struct {
	intervals []Interval
}

func Any() Set {
	return MustParse("1-65535")
}

func MustParse(spec string) Set {
	set, err := Parse(spec)
	if err != nil {
		panic(err)
	}
	return set
}

func Parse(spec string) (Set, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return Set{}, fmt.Errorf("ports spec is empty")
	}

	var intervals []Interval
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			return Set{}, fmt.Errorf("invalid ports spec %q", spec)
		}

		if lo, hi, ok := strings.Cut(part, "-"); ok {
			lo = strings.TrimSpace(lo)
			hi = strings.TrimSpace(hi)
			loN, err := strconv.Atoi(lo)
			if err != nil {
				return Set{}, fmt.Errorf("invalid port %q", lo)
			}
			hiN, err := strconv.Atoi(hi)
			if err != nil {
				return Set{}, fmt.Errorf("invalid port %q", hi)
			}
			if loN < 1 || hiN < 1 || loN > 65535 || hiN > 65535 || loN > hiN {
				return Set{}, fmt.Errorf("invalid port range %q", part)
			}
			intervals = append(intervals, Interval{Lo: loN, Hi: hiN})
			continue
		}

		n, err := strconv.Atoi(part)
		if err != nil {
			return Set{}, fmt.Errorf("invalid port %q", part)
		}
		if n < 1 || n > 65535 {
			return Set{}, fmt.Errorf("invalid port %d", n)
		}
		intervals = append(intervals, Interval{Lo: n, Hi: n})
	}

	sort.Slice(intervals, func(i, j int) bool {
		if intervals[i].Lo != intervals[j].Lo {
			return intervals[i].Lo < intervals[j].Lo
		}
		return intervals[i].Hi < intervals[j].Hi
	})

	merged := intervals[:0]
	for _, iv := range intervals {
		if len(merged) == 0 {
			merged = append(merged, iv)
			continue
		}
		last := &merged[len(merged)-1]
		if iv.Lo <= last.Hi+1 {
			if iv.Hi > last.Hi {
				last.Hi = iv.Hi
			}
			continue
		}
		merged = append(merged, iv)
	}

	return Set{intervals: merged}, nil
}

func (s Set) Contains(port int) bool {
	if port < 1 || port > 65535 {
		return false
	}
	for _, iv := range s.intervals {
		if port < iv.Lo {
			return false
		}
		if port <= iv.Hi {
			return true
		}
	}
	return false
}
