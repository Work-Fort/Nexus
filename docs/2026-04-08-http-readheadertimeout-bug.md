# Bug: HTTP Server Missing ReadHeaderTimeout

## Problem

`cmd/daemon.go` lines 312-321 — the `http.Server` sets `ReadTimeout` (10s)
and `IdleTimeout` (60s). `WriteTimeout` is intentionally omitted (image-pull
handlers need unbounded response time). However, `ReadHeaderTimeout` is
also absent.

Without `ReadHeaderTimeout`, a client can hold a connection in the header-
reading phase indefinitely, which is a Slowloris-class vulnerability
independent of `ReadTimeout`.

## Fix

Add:

```go
ReadHeaderTimeout: 5 * time.Second
```

`WriteTimeout` can remain omitted per the existing comment about image pulls.

## Severity

Low — `ReadTimeout` provides partial mitigation, but `ReadHeaderTimeout`
is the specific defense against slow-header attacks.
