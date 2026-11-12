package qlogwriter

import "slices"

var registeredEventSchemas []string

// RegisterEventSchema registers a qlog event schema.
// It must only be called from init functions of packages that produce qlog events.
// Traces declare all registered event schemas in the trace header,
// independent of whether events of a particular schema end up being recorded.
func RegisterEventSchema(schema string) {
	if !slices.Contains(registeredEventSchemas, schema) {
		registeredEventSchemas = append(registeredEventSchemas, schema)
	}
}
