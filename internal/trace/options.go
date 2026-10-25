package trace

type Options struct {
	Iface      string
	Filter     string
	Count      int
	Duration   int
	ExportPcap string
	ImportPcap string
	Decode     string
	Limit      int
}
