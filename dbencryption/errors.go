package dbencryption

import "errors"

var (
	// ErrTaskNotFound is returned when a task is not found
	ErrTaskNotFound = errors.New("task not found")

	// ErrTaskCancelled is returned when a task is cancelled
	ErrTaskCancelled = errors.New("task cancelled")

	// ErrTaskFailed is returned when a task fails
	ErrTaskFailed = errors.New("task failed")

	// ErrInvalidScope is returned when an invalid scope is provided
	ErrInvalidScope = errors.New("invalid scope")

	// ErrInvalidCollection is returned when an invalid collection is provided
	ErrInvalidCollection = errors.New("invalid collection")

	// ErrNoProtectedFields is returned when no protected fields are found for a collection
	ErrNoProtectedFields = errors.New("no protected fields found for collection")

	// ErrDEKRotationInProgress is returned when a DEK rotation is already in progress
	ErrDEKRotationInProgress = errors.New("DEK rotation already in progress")

	// ErrInvalidTaskType is returned when an invalid task type is provided
	ErrInvalidTaskType = errors.New("invalid task type")

	// ErrInvalidTaskStatus is returned when an invalid task status is provided
	ErrInvalidTaskStatus = errors.New("invalid task status")

	// ErrTaskQueueFull is returned when the task queue is full
	ErrTaskQueueFull = errors.New("task queue is full")
)
