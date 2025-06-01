// syft/pkg/cataloger/wrapper/wrapper.go
package wrapper

import (
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/cpegenerate"
	"sort"
)

// GenerateCPEs returns a sorted list of CPEs for a package.
// It first tries to use the dictionary; if not available, it falls back to heuristics.
func GenerateCPEs(p pkg.Package) []cpe.CPE {
	cpes, ok := cpegenerate.FromDictionaryFind(p)
	if !ok {
		cpes = cpegenerate.FromPackageAttributes(p)
	}
	sort.Sort(cpe.BySourceThenSpecificity(cpes))
	return cpes
}
