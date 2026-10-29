//go:build linux

package watch

import ( 
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

var _ = package.Identifier 