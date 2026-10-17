// Package scanner defines the contract every reconnaissance module implements.
// The engine depends only on this package, so new modules can be added by
// implementing Scanner and registering it in main — no engine changes needed.
package scanner

import (
	"context"

	"github.com/sudosoc/rectool/internal/httpx"
	"github.com/sudosoc/rectool/internal/models"
	"github.com/sudosoc/rectool/internal/pool"
)

// Deps are the shared services the engine hands to every module.
type Deps struct {
	HTTP *httpx.Client
	Pool *pool.Pool
	// Progress may be nil. Modules call it as they complete units of work.
	Progress func(module string, done, total int)
}

// Scanner is a pluggable reconnaissance module.
type Scanner interface {
	// Name is the short unique identifier used by the -modules flag.
	Name() string
	// Description is a one-line human description.
	Description() string
	// CanRun lets the intelligence engine decide, from the supplied inputs,
	// whether the module is applicable.
	CanRun(t models.Target) bool
	// Scan performs the work. It must honour ctx cancellation, run its
	// concurrent work on d.Pool, and report results through emit (which is
	// safe for concurrent use). It must not call emit after returning.
	Scan(ctx context.Context, t models.Target, d Deps, emit func(models.Finding)) error
}
