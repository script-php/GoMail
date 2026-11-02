package mailclient

import (
	"fmt"
	"strconv"
	"strings"

	"gomail/store"
)

func validateIMAPUIDSet(value string) error {
	if value == "" {
		return fmt.Errorf("empty sequence set")
	}
	for _, item := range strings.Split(value, ",") {
		bounds := strings.Split(item, ":")
		if len(bounds) > 2 || len(bounds) == 0 {
			return fmt.Errorf("invalid sequence set")
		}
		for _, bound := range bounds {
			if bound == "*" {
				continue
			}
			number, err := strconv.ParseUint(bound, 10, 32)
			if err != nil || number == 0 {
				return fmt.Errorf("invalid sequence number")
			}
		}
	}
	return nil
}

func imapUIDSetContains(value string, uid, maximum uint32) bool {
	for _, item := range strings.Split(value, ",") {
		bounds := strings.Split(item, ":")
		parse := func(raw string) uint32 {
			if raw == "*" {
				return maximum
			}
			parsed, _ := strconv.ParseUint(raw, 10, 32)
			return uint32(parsed)
		}
		first, last := parse(bounds[0]), parse(bounds[0])
		if len(bounds) == 2 {
			last = parse(bounds[1])
		}
		if first > last {
			first, last = last, first
		}
		if uid >= first && uid <= last {
			return true
		}
	}
	return false
}

func compactUIDSet(values []uint32) string {
	if len(values) == 0 {
		return ""
	}
	result := make([]string, 0, len(values))
	for start := 0; start < len(values); {
		end := start
		for end+1 < len(values) && values[end+1] == values[end]+1 {
			end++
		}
		if end == start {
			result = append(result, strconv.FormatUint(uint64(values[start]), 10))
		} else {
			result = append(result, fmt.Sprintf("%d:%d", values[start], values[end]))
		}
		start = end + 1
	}
	return strings.Join(result, ",")
}

func resolveIMAPSequenceSet(value string, refs []store.IMAPMessageRef, byUID bool) ([]store.IMAPMessageRef, error) {
	if value == "" {
		return nil, fmt.Errorf("empty sequence set")
	}
	var maximum uint32
	if len(refs) > 0 {
		if byUID {
			maximum = refs[len(refs)-1].UID
		} else {
			maximum = uint32(len(refs))
		}
	}
	type sequenceRange struct{ first, last uint32 }
	var ranges []sequenceRange
	parseNumber := func(token string) (uint32, error) {
		if token == "*" {
			return maximum, nil
		}
		number, err := strconv.ParseUint(token, 10, 32)
		if err != nil || number == 0 {
			return 0, fmt.Errorf("invalid sequence number %q", token)
		}
		return uint32(number), nil
	}
	for _, item := range strings.Split(value, ",") {
		bounds := strings.Split(item, ":")
		if len(bounds) > 2 {
			return nil, fmt.Errorf("invalid sequence range")
		}
		first, err := parseNumber(bounds[0])
		if err != nil {
			return nil, err
		}
		last := first
		if len(bounds) == 2 {
			last, err = parseNumber(bounds[1])
			if err != nil {
				return nil, err
			}
		}
		if first > last {
			first, last = last, first
		}
		ranges = append(ranges, sequenceRange{first: first, last: last})
	}
	var result []store.IMAPMessageRef
	for _, ref := range refs {
		key := ref.Sequence
		if byUID {
			key = ref.UID
		}
		for _, valueRange := range ranges {
			if key >= valueRange.first && key <= valueRange.last {
				result = append(result, ref)
				break
			}
		}
	}
	return result, nil
}
