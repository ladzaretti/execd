package main

import (
	"context"
	"crypto/subtle"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
)

func chain(h http.Handler, middlewares ...func(h http.Handler) http.Handler) http.Handler {
	for _, m := range middlewares {
		h = m(h)
	}

	return h
}

func withAuth(password string, unsafe bool, sess *sessions) func(h http.Handler) http.Handler { //nolint:revive,cyclop,gocognit
	const bearerPrefix = "Bearer "

	eq := func(a, b string) bool {
		if len(a) != len(b) {
			return false
		}

		return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
	}

	mutating := func(m string) bool {
		switch m {
		case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
			return true

		default:
			return false
		}
	}

	validateBearer := func(w http.ResponseWriter, auth string) (ok bool) {
		if len(auth) < len(bearerPrefix) || !strings.EqualFold(auth[:len(bearerPrefix)], bearerPrefix) {
			w.Header().Set("WWW-Authenticate", `Bearer"`)

			return false
		}

		got := strings.TrimSpace(auth[len(bearerPrefix):])
		if !eq(got, password) {
			w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)

			return false
		}

		return true
	}

	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodOptions || unsafe {
				h.ServeHTTP(w, r)
				return
			}

			if auth := r.Header.Get("Authorization"); auth != "" {
				if validateBearer(w, auth) {
					h.ServeHTTP(w, r)
				}

				return
			}

			sidC, err := r.Cookie("sid")
			if err != nil || sidC == nil || sidC.Value == "" {
				http.Error(w, "unauthorized", http.StatusUnauthorized)

				return
			}

			s, ok := sess.valid(sidC.Value)
			if !ok {
				http.Error(w, "unauthorized", http.StatusUnauthorized)

				return
			}

			if mutating(r.Method) {
				csrfC, _ := r.Cookie("csrf")
				tokenHdr := r.Header.Get("X-Csrf-Token")

				if csrfC == nil || csrfC.Value == "" ||
					!eq(tokenHdr, csrfC.Value) || !eq(csrfC.Value, s.csrf) {
					http.Error(w, "csrf", http.StatusForbidden)

					return
				}
			}

			_ = sess.touch(sidC.Value)

			h.ServeHTTP(w, r)
		})
	}
}

func withSecurityHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'; base-uri 'self'")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")

		h.ServeHTTP(w, r)
	})
}

func withTracing(h http.Handler) http.Handler {
	const hdrRequestID = "X-Request-Id"

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get(hdrRequestID)
		if id == "" {
			u, _ := uuid.NewV7()
			id = u.String()
		}

		ctx := context.WithValue(r.Context(), requestKey, id)

		sw := &statusWriter{ResponseWriter: w}
		sw.Header().Set(hdrRequestID, id)

		logger.Debug("request received",
			"id", id,
			"path", r.URL.Path,
			"method", r.Method,
			"remote", r.RemoteAddr,
		)

		defer func(start time.Time) {
			logger.Debug("request completed",
				"id", id,
				"status", sw.status,
				"bytes", sw.n,
				"duration", time.Since(start).String(),
			)
		}(time.Now())

		h.ServeHTTP(sw, r.WithContext(ctx))
	})
}

func withMeta(h http.Handler) http.Handler {
	const (
		hdrConfigSHA = "X-Config-Sha"
		hdrVersion   = "X-Execd-Version"
	)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(hdrConfigSHA, config.sha)
		w.Header().Set(hdrVersion, Version)

		h.ServeHTTP(w, r)
	})
}
