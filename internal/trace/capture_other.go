//go:build !linux && !darwin && !freebsd && !netbsd && !openbsd && !dragonfly

package trace

import (
	"context"
	"fmt"
)

func LiveCapture(ctx context.Context, opts Options) error {
	return fmt.Errorf("Live capture requires Linux.")
}
