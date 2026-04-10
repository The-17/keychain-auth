package daemon

import (
    "context"
    "log"
    "net"
    "os"
    "os/signal"
    "sync"
    "syscall"

    "github.com/The-17/keychain-auth/internal/handler"
)

type Daemon struct {
    socketPath string
    handler    *handler.Handler
    listener   net.Listener
    wg         sync.WaitGroup
}

func New(socketPath string, h *handler.Handler) *Daemon {
    return &Daemon{
        socketPath: socketPath,
        handler:    h,
    }
}

// Run starts the daemon and blocks until SIGINT or SIGTERM is received.
func (d *Daemon) Run() error {
    if err := os.RemoveAll(d.socketPath); err != nil {
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

        d.wg.Add(1)
        go func() {
            defer d.wg.Done()
            d.handler.Handle(conn)
        }()
    }
}

// Shutdown gracefully closes the listener and waits for current handlers to finish.
func (d *Daemon) Shutdown() error {
    if d.listener != null {
        err := d.listener.Close()
        d.wg.Wait()
        return err
    }
    return nil
}
