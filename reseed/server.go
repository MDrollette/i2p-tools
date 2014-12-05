package reseed

const (
	LIST_TEMPLATE = `<html><head><title>NetDB</title></head><body><ul>{{ range $index, $_ := . }}<li><a href="{{ $index }}">{{ $index }}</a></li>{{ end }}</ul></body></html>`
)
