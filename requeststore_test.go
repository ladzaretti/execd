package main

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestRequestStoreComplete(t *testing.T) {
	t.Parallel()

	requests := NewTestRequestStore(t)

	const id = "request-001"

	initialState := execStateQueued
	runningState := execStateRunning
	finalState := execStateFailed

	requestState := RequestState{
		Path:  "/exec/ping",
		State: initialState,
	}
	if _, err := requests.insert(t.Context(), id, requestState); err != nil {
		t.Fatalf("insert request: %v", err)
	}

	if _, err := requests.updateState(t.Context(), id, runningState); err != nil {
		t.Fatalf("update request state: %v", err)
	}

	updated, err := requests.selectByUUID(t.Context(), id)
	if err != nil {
		t.Fatalf("select updated request: %v", err)
	}

	wantUpdated := RequestState{
		UUID:  id,
		Path:  requestState.Path,
		State: runningState,
	}
	if diff := cmp.Diff(wantUpdated, updated, cmpopts.IgnoreFields(RequestState{}, "StartedAt")); diff != "" {
		t.Errorf("updated request mismatch (-want +got):\n%s", diff)
	}

	execResult := ExecResult{
		Stdout:          "stdout",
		Stderr:          "stderr",
		OutputTruncated: true,
		Detached:        true,
		PID:             new(42),
		ExitCode:        new(7),
		Error:           "exit status 7",
	}
	if _, err := requests.complete(t.Context(), id, RequestState{
		State:  finalState,
		Result: execResult,
	}); err != nil {
		t.Fatalf("complete request: %v", err)
	}

	got, err := requests.selectByUUID(t.Context(), id)
	if err != nil {
		t.Fatalf("select request: %v", err)
	}

	want := RequestState{
		UUID:   id,
		Path:   requestState.Path,
		State:  finalState,
		Result: execResult,
	}
	if diff := cmp.Diff(want, got, cmpopts.IgnoreFields(RequestState{}, "StartedAt", "CompletedAt")); diff != "" {
		t.Errorf("request mismatch (-want +got):\n%s", diff)
	}

	if got.StartedAt.IsZero() {
		t.Error("got zero started time, want non-zero time")
	}

	if got.CompletedAt.IsZero() {
		t.Error("got zero completed time, want non-zero time")
	}
}

func TestRequestStoreSelectPage(t *testing.T) {
	t.Parallel()

	requests := NewTestRequestStore(t)
	for _, request := range []struct {
		id    string
		state execState
	}{
		{id: "001", state: execStateCanceled},
		{id: "002", state: execStateCompleted},
		{id: "003", state: execStateCompleted},
		{id: "004", state: execStateFailed},
	} {
		if _, err := requests.insert(t.Context(), request.id, RequestState{
			Path:  "/exec/ping",
			State: request.state,
		}); err != nil {
			t.Fatalf("insert test request: %v", err)
		}
	}

	tests := []struct {
		name    string
		cursor  string
		filters []string
		limit   int
		wantIDs []string
	}{
		{
			name:    "descending limit",
			limit:   2,
			wantIDs: []string{"004", "003"},
		},
		{
			name:    "inclusive cursor",
			cursor:  "002",
			limit:   2,
			wantIDs: []string{"002", "001"},
		},
		{
			name:    "state filters",
			filters: []string{string(execStateCompleted), string(execStateCanceled)},
			wantIDs: []string{"003", "002", "001"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			page, err := requests.selectPage(t.Context(), tt.cursor, tt.filters, tt.limit)
			if err != nil {
				t.Fatalf("select request page: %v", err)
			}

			gotIDs := make([]string, len(page))
			for i, request := range page {
				gotIDs[i] = request.UUID
			}

			if diff := cmp.Diff(tt.wantIDs, gotIDs); diff != "" {
				t.Errorf("request IDs mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
