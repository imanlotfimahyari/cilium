// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package returnaffinity

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type capacityKeySequence struct {
	keys    [][]byte
	calls   int
	failure error
}

func (s *capacityKeySequence) NextKeyBytes(previous any) ([]byte, error) {
	if s.calls == 0 && previous != nil {
		return nil, errors.New("initial cursor must be nil, not a typed nil slice")
	}
	s.calls++
	if s.failure != nil {
		return nil, s.failure
	}
	if s.calls > len(s.keys) {
		return nil, nil
	}
	return s.keys[s.calls-1], nil
}

func TestCapacityEnumeration(t *testing.T) {
	for _, test := range []struct {
		name           string
		keys           [][]byte
		maximum, count uint32
		failure        string
	}{
		{"empty", nil, 4, 0, ""},
		{"partial", [][]byte{{1}, {2}}, 4, 2, ""},
		{"full", [][]byte{{1}, {2}, {3}, {4}}, 4, 4, ""},
		{"cycle_under_churn", [][]byte{{1}, {2}, {1}}, 4, 0, "revisited"},
		{"bounded_under_churn", [][]byte{{1}, {2}, {3}, {4}, {5}}, 4, 0, "exceeded"},
	} {
		t.Run(test.name, func(t *testing.T) {
			reader := &capacityKeySequence{keys: test.keys}
			count, err := countCapacityKeys(context.Background(), reader, test.maximum)
			if test.failure == "" {
				if err != nil || count != test.count {
					t.Fatalf("count=%d error=%v", count, err)
				}
			} else if err == nil || !strings.Contains(err.Error(), test.failure) || count != 0 {
				t.Fatalf("partial enumeration was accepted: count=%d error=%v", count, err)
			}
			if reader.calls > int(test.maximum)+1 {
				t.Fatal("enumeration was not bounded")
			}
		})
	}
}

func TestCapacityEnumerationCancellationAndPrivacy(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	reader := &capacityKeySequence{}
	if _, err := countCapacityKeys(ctx, reader, 4); !errors.Is(err, context.Canceled) || reader.calls != 0 {
		t.Fatal("cancelled inspection continued reading")
	}
	reader = &capacityKeySequence{failure: errors.New("private key/value or path must not be emitted")}
	if _, err := countCapacityKeys(context.Background(), reader, 4); err == nil || strings.Contains(err.Error(), "private") {
		t.Fatal("lookup error leaked raw details or was ignored")
	}
}

func TestCapacityMissingBundleIsIncomplete(t *testing.T) {
	report := InspectCapacity(context.Background(), t.TempDir())
	if report.Complete || len(report.Errors) == 0 || len(report.Maps) != 0 || report.Atomic || report.Finished.Before(report.Started) {
		t.Fatalf("missing bundle reported healthy or empty: %+v", report)
	}
}
