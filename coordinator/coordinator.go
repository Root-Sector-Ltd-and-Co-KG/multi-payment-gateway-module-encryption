package coordinator

import (
	"context"
	"fmt"
	"sync"
	"time"
)

type ProcessStatus string

const (
	StatusRunning   ProcessStatus = "running"
	StatusPaused    ProcessStatus = "paused"
	StatusCompleted ProcessStatus = "completed"
	StatusFailed    ProcessStatus = "failed"
)

type Process struct {
	ID        string
	Status    ProcessStatus
	StartTime time.Time
	Progress  float64
	Error     error
	Cancel    context.CancelFunc
	ctx       context.Context
}

type Coordinator struct {
	mu              sync.RWMutex
	activeProcesses map[string]*Process
	shutdownCh      chan struct{}
	wg              sync.WaitGroup
}

func NewCoordinator() *Coordinator {
	return &Coordinator{
		activeProcesses: make(map[string]*Process),
		shutdownCh:      make(chan struct{}),
	}
}

func (c *Coordinator) StartProcess(ctx context.Context, processID string) (*Process, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Check if process already exists
	if _, exists := c.activeProcesses[processID]; exists {
		return nil, fmt.Errorf("process %s already exists", processID)
	}

	// Create cancellable context
	processCtx, cancel := context.WithCancel(ctx)

	process := &Process{
		ID:        processID,
		Status:    StatusRunning,
		StartTime: time.Now(),
		Cancel:    cancel,
		ctx:       processCtx,
	}

	c.activeProcesses[processID] = process
	c.wg.Add(1)

	// Start a goroutine to monitor context cancellation
	go func() {
		<-processCtx.Done()
		c.mu.Lock()
		if p, exists := c.activeProcesses[processID]; exists && p.Status == StatusRunning {
			p.Status = StatusFailed
			p.Error = processCtx.Err()
		}
		c.mu.Unlock()
	}()

	return process, nil
}

func (c *Coordinator) StopProcess(processID string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if process, exists := c.activeProcesses[processID]; exists {
		process.Cancel()
		delete(c.activeProcesses, processID)
		c.wg.Done()
	}
}

func (c *Coordinator) UpdateProcessStatus(processID string, status ProcessStatus, progress float64, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if process, exists := c.activeProcesses[processID]; exists {
		process.Status = status
		process.Progress = progress
		process.Error = err
	}
}

func (c *Coordinator) GetProcessStatus(processID string) *Process {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if process, exists := c.activeProcesses[processID]; exists {
		// Return a copy to prevent race conditions
		return &Process{
			ID:        process.ID,
			Status:    process.Status,
			StartTime: process.StartTime,
			Progress:  process.Progress,
			Error:     process.Error,
		}
	}
	return nil
}

func (c *Coordinator) ListProcesses() []*Process {
	c.mu.RLock()
	defer c.mu.RUnlock()

	processes := make([]*Process, 0, len(c.activeProcesses))
	for _, process := range c.activeProcesses {
		// Return copies to prevent race conditions
		processes = append(processes, &Process{
			ID:        process.ID,
			Status:    process.Status,
			StartTime: process.StartTime,
			Progress:  process.Progress,
			Error:     process.Error,
		})
	}
	return processes
}

func (c *Coordinator) Shutdown(ctx context.Context) error {
	// Signal shutdown
	close(c.shutdownCh)

	// Cancel all active processes
	c.mu.Lock()
	for _, process := range c.activeProcesses {
		process.Cancel()
	}
	c.mu.Unlock()

	// Wait for all processes with timeout
	done := make(chan struct{})
	go func() {
		c.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *Coordinator) IsShuttingDown() bool {
	select {
	case <-c.shutdownCh:
		return true
	default:
		return false
	}
}
