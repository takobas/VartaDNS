// Command vartadns is a filtering DNS forwarder with a built-in web panel.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"
	_ "time/tzdata" // embedded time zones: scratch images have none

	"github.com/takobas/vartadns/internal/app"
)

func main() {
	cfgPath := flag.String("config", "/etc/vartadns/config.json", "path to JSON config (optional)")
	printDefault := flag.Bool("print-default-config", false, "print the default config and exit")
	showVersion := flag.Bool("version", false, "print version and exit")
	profileFlag := flag.String("profile", "", `hardware profile: "standard" or "light" (default: env VARTA_PROFILE)`)
	memLimitMB := flag.Int("mem-limit", 0, "soft memory limit in MiB (0 = env GOMEMLIMIT or unlimited)")
	flag.Parse()

	if *showVersion {
		fmt.Println("vartadns", app.Version)
		return
	}
	if *printDefault {
		b, _ := json.MarshalIndent(app.DefaultConfig(), "", "  ")
		fmt.Println(string(b))
		return
	}
	if *memLimitMB > 0 {
		// Makes the GC work harder instead of exceeding RAM on small routers.
		debug.SetMemoryLimit(int64(*memLimitMB) << 20)
	}

	log.SetFlags(log.LstdFlags | log.Lmsgprefix)
	log.SetPrefix("vartadns: ")

	cfg, err := app.LoadConfig(*cfgPath)
	if err != nil {
		log.Fatal(err)
	}
	profile := os.Getenv("VARTA_PROFILE")
	if *profileFlag != "" {
		profile = *profileFlag
	}
	if err := app.ApplyProfile(&cfg, profile); err != nil {
		log.Fatal(err)
	}
	if profile != "" {
		log.Printf("profile: %s", profile)
	}
	if v := os.Getenv("VARTA_DATA_DIR"); v != "" {
		cfg.DataDir = v
	}
	a, err := app.New(cfg)
	if err != nil {
		log.Fatal(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	log.Printf("VartaDNS %s starting", app.Version)
	if err := a.Run(ctx); err != nil {
		log.Fatal(err)
	}
	log.Print("stopped")
}
