package output

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type Printer struct {
	JSON, YAML, CSV, Quiet, Verbose bool
}

func New(jsonOut, yamlOut, csvOut, quiet, verbose bool) Printer {
	return Printer{JSON: jsonOut, YAML: yamlOut, CSV: csvOut, Quiet: quiet, Verbose: verbose}
}

func (p Printer) PrintTable(headers []string, rows [][]string) {
	if p.JSON || p.YAML {
		return
	}
	if p.CSV {
		w := csv.NewWriter(os.Stdout)
		_ = w.Write(headers)
		for _, r := range rows {
			_ = w.Write(r)
		}
		w.Flush()
		return
	}
	if p.Quiet {
		return
	}
	widths := make([]int, len(headers))
	for i, h := range headers {
		widths[i] = len(h)
	}
	for _, r := range rows {
		for i, c := range r {
			if i < len(widths) && len(c) > widths[i] {
				widths[i] = len(c)
			}
		}
	}
	cells := make([]string, len(headers))
	for i, h := range headers {
		cells[i] = fmt.Sprintf("%-*s", widths[i], h)
	}
	fmt.Println(strings.Join(cells, "  "))
	for _, r := range rows {
		for i := range cells {
			if i < len(r) {
				cells[i] = fmt.Sprintf("%-*s", widths[i], r[i])
			}
		}
		fmt.Println(strings.Join(cells, "  "))
	}
}

func (p Printer) PrintAny(v interface{}) {
	switch {
	case p.JSON:
		b, _ := json.MarshalIndent(v, "", "  ")
		fmt.Println(string(b))
	case p.YAML:
		b, _ := yaml.Marshal(v)
		fmt.Print(string(b))
	case p.CSV:
		b, _ := json.Marshal(v) // temp implementation, will fix
		fmt.Println(string(b))
	case !p.Quiet:
		fmt.Printf("%v\n", v)
	}
}
