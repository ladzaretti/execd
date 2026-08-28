package main

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
)

var (
	errInvalidBearer = errors.New("invalid bearer authorization")
	errUnauthorized  = errors.New("unauthorized")
)

func chain(h http.Handler, middlewares ...func(h http.Handler) http.Handler) http.Handler {
	for _, m := range middlewares {
		h = m(h)
	}

	return h
}

type authConfig struct {
	enabled bool
}

type authOption func(*authConfig)

func authEnabled(enabled bool) authOption {
	return func(config *authConfig) {
		config.enabled = enabled
	}
}

func withAuth(password string, options ...authOption) func(h http.Handler) http.Handler {
	config := authConfig{enabled: true}
	for _, opt := range options {
		opt(&config)
	}

	const bearerPrefix = "Bearer "

	validateBearer := func(auth, password string) error {
		if len(auth) < len(bearerPrefix) {
			return errInvalidBearer
		}

		bearerReceived, passwordReceived := auth[:len(bearerPrefix)], strings.TrimSpace(auth[len(bearerPrefix):])

		if !strings.EqualFold(bearerReceived, bearerPrefix) {
			return errInvalidBearer
		}

		if subtle.ConstantTimeCompare([]byte(passwordReceived), []byte(password)) != 1 {
			return errUnauthorized
		}

		return nil
	}

	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !config.enabled {
				h.ServeHTTP(w, r)
				return
			}

			if err := validateBearer(r.Header.Get("Authorization"), password); err != nil {
				switch {
				case errors.Is(err, errInvalidBearer):
					w.Header().Set("WWW-Authenticate", "Bearer")
					http.Error(w, "unauthorized", http.StatusUnauthorized)
				case errors.Is(err, errUnauthorized):
					w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
					http.Error(w, "unauthorized", http.StatusUnauthorized)
				default:
					http.Error(w, "internal", http.StatusInternalServerError)
				}

				return
			}

			h.ServeHTTP(w, r)
		})
	}
}

func withTracing(h http.Handler) http.Handler {
	const hdrRequestID = "X-Request-ID"

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get(hdrRequestID)
		if id == "" {
			u, err := uuid.NewV7()
			if err != nil {
				http.Error(w, "generate request ID", http.StatusInternalServerError)

				return
			}

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

func withMeta(configSHA string) func(http.Handler) http.Handler {
	const (
		hdrConfigSHA = "X-Config-Sha"
		hdrVersion   = "X-Execd-Version"
	)

	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set(hdrConfigSHA, configSHA)
			w.Header().Set(hdrVersion, Version)

			h.ServeHTTP(w, r)
		})
	}
}
