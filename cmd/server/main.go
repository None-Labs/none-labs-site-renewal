package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// SecurityAndRoutingMiddleware wraps the http.Handler to provide security headers and clean URL routing.
func SecurityAndRoutingMiddleware(root string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Security Headers
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "SAMEORIGIN")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("X-XSS-Protection", "1; mode=block")

		// Health Check Endpoint
		if r.URL.Path == "/healthz" || r.URL.Path == "/health" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status":"ok","timestamp":"` + time.Now().UTC().Format(time.RFC3339) + `"}`))
			return
		}

		// Clean URL handling: if /foo is requested and /foo.html exists, serve /foo.html
		cleanPath := strings.TrimPrefix(r.URL.Path, "/")
		if cleanPath != "" && !strings.Contains(filepath.Base(cleanPath), ".") {
			candidate := filepath.Join(root, cleanPath+".html")
			if fi, err := os.Stat(candidate); err == nil && !fi.IsDir() {
				http.ServeFile(w, r, candidate)
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	docRoot := os.Getenv("DOC_ROOT")
	if docRoot == "" {
		docRoot = "."
	}

	fs := http.FileServer(http.Dir(docRoot))
	handler := SecurityAndRoutingMiddleware(docRoot, fs)

	server := &http.Server{
		Addr:         ":" + port,
		Handler:      handler,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Graceful shutdown channel
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	go func() {
		log.Printf("[None Labs] Web Server listening on port %s (serving: %s)...", port, docRoot)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server error: %v", err)
		}
	}()

	<-stop
	log.Println("[None Labs] Shutting down web server gracefully...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}

	log.Println("[None Labs] Web Server stopped cleanly.")
}
