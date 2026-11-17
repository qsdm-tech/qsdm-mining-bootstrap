// Command pulse-pool runs the PULSE pool server.
//
//	pulse-pool keygen -out /var/lib/pulse/pool.key   (prints only the pool ID)
//	pulse-pool id -key /var/lib/pulse/pool.key        (prints the pool ID)
//	pulse-pool serve -config /etc/pulse/pool.json
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
	"github.com/qsdm-tech/qsdm-mining-bootstrap/internal/pool"
	"github.com/qsdm-tech/qsdm-mining-bootstrap/pulse"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: pulse-pool keygen|id|serve ...")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "keygen":
		err = keygen(os.Args[2:])
	case "id":
		err = id(os.Args[2:])
	case "serve":
		err = serve(os.Args[2:])
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "pulse-pool:", err)
		os.Exit(1)
	}
}

func loadKey(path string) (*pulse.KeyPair, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if st.Mode().Perm()&0o077 != 0 && os.PathSeparator == '/' {
		return nil, fmt.Errorf("%s is readable by others (mode %v): chmod 600", path, st.Mode().Perm())
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	raw, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(raw) != mldsa87.SeedSize {
		return nil, errors.New("key file must hold one hex seed")
	}
	var seed [mldsa87.SeedSize]byte
	copy(seed[:], raw)
	return pulse.KeyPairFromSeed(seed), nil
}

func keygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	out := fs.String("out", "", "key file to create (refuses to overwrite)")
	_ = fs.Parse(args)
	if *out == "" {
		return errors.New("-out is required")
	}
	k, err := pulse.NewKeyPair()
	if err != nil {
		return err
	}
	f, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(hex.EncodeToString(k.Seed[:]) + "\n"); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	fmt.Println("PULSE-KEYGEN OK pool_id", k.ID())
	return nil
}

func id(args []string) error {
	fs := flag.NewFlagSet("id", flag.ExitOnError)
	kp := fs.String("key", "", "key file")
	_ = fs.Parse(args)
	k, err := loadKey(*kp)
	if err != nil {
		return err
	}
	fmt.Println(k.ID())
	return nil
}

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	cp := fs.String("config", "", "config file (JSON)")
	_ = fs.Parse(args)
	b, err := os.ReadFile(*cp)
	if err != nil {
		return err
	}
	var cfg pool.Config
	d := json.NewDecoder(strings.NewReader(string(b)))
	d.DisallowUnknownFields()
	if err := d.Decode(&cfg); err != nil {
		return fmt.Errorf("config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	k, err := loadKey(cfg.KeyFile)
	if err != nil {
		return err
	}
	jr, err := pool.OpenJournal(cfg.DataDir)
	if err != nil {
		return err
	}
	defer jr.Close()
	p, err := pool.New(cfg, k, jr)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	pl := &pool.Poller{Pool: p, API: strings.TrimRight(cfg.ProducerAPI, "/"), Client: &http.Client{Timeout: 10 * time.Second}}
	go pl.Run(ctx, time.Duration(cfg.PollSeconds)*time.Second, log.Printf)
	srv := &http.Server{Addr: cfg.Listen, Handler: p.Handler(), ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second}
	go func() {
		<-ctx.Done()
		sc, c := context.WithTimeout(context.Background(), 5*time.Second)
		defer c()
		_ = srv.Shutdown(sc)
	}()
	log.Printf("PULSE pool %s listening on %s (fee %d bps, window %dx)", k.ID(), cfg.Listen, cfg.FeeBPS, cfg.WindowFactor)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
