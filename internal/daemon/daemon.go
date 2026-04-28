package daemon

import (
	"context"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

// ConnectionHandler is the interface for processing a single connection.
// Decouples the daemon from the concrete handler implementation.
type ConnectionHandler interface {
	Handle(conn net.Conn)
}

// Daemon manages the Unix socket listener and connection lifecycle.
type Daemon struct {
	socketPath string
	handler    ConnectionHandler
	listener   net.Listener
	wg         sync.WaitGroup
	sem        chan struct{} // connection semaphore
}

const (
	maxConnections  = 64            // max concurrent connections
	shutdownTimeout = 5 * time.Second
	readDeadline    = 30 * time.Second
)

func New(socketPath string, h ConnectionHandler) *Daemon {
	return &Daemon{
		socketPath: socketPath,
		handler:    h,
		sem:        make(chan struct{}, maxConnections),
	}
}

// Run starts the daemon and blocks until SIGINT or SIGTERM is received.
func (d *Daemon) Run() error {
	// Ensure the socket directory exists
	if err := os.MkdirAll(filepath.Dir(d.socketPath), 0700); err != nil {
		return err
	}

	// Remove stale socket if present (single file only, not recursive)
	if err := os.Remove(d.socketPath); err != nil && !os.IsNotExist(err) {
		return err
	}

	l, err := net.Listen("unix", d.socketPath)
	if err != nil {
		return err
	}
	d.listener = l

	// Ensure only the owner can access the socket (0600)
	if err := os.Chmod(d.socketPath, 0600); err != nil {
		l.Close()
		return err
	}

	log.Printf("keychain-auth daemon listening on %s\n", d.socketPath)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go d.acceptLoop(ctx)

	// Wait for termination signal
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs

	log.Println("Shutting down daemon...")
	cancel()
	return d.Shutdown()
}

func (d *Daemon) acceptLoop(ctx context.Context) {
	for {
		conn, err := d.listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return // Shutdown requested
			default:
				log.Printf("accept error: %v", err)
				continue
			}
		}

		// Enforce connection limit — blocks if at capacity
		select {
		case d.sem <- struct{}{}:
		case <-ctx.Done():
			conn.Close()
			return
		}

		d.wg.Add(1)
		go func() {
			defer d.wg.Done()
			defer func() { <-d.sem }()

			// Set an initial read deadline so idle connections don't linger
			if tc, ok := conn.(*net.UnixConn); ok {
				tc.SetReadDeadline(time.Now().Add(readDeadline))
			}

			d.handler.Handle(conn)
		}()
	}
}

// Shutdown gracefully closes the listener, waits for handlers (with timeout),
// and removes the socket file.
func (d *Daemon) Shutdown() error {
	var firstErr error

	if d.listener != nil {
		if err := d.listener.Close(); err != nil {
			firstErr = err
		}

		// Wait for in-flight connections with a timeout
		done := make(chan struct{})
		go func() {
			d.wg.Wait()
			close(done)
		}()

		select {
		case <-done:
		case <-time.After(shutdownTimeout):
			log.Println("WARN: timed out waiting for connections to drain")
		}
	}

	// Always clean up the socket file
	if err := os.Remove(d.socketPath); err != nil && !os.IsNotExist(err) {
		if firstErr == nil {
			firstErr = err
		}
	}

	return firstErr
}
