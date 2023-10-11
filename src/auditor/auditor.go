package auditor

// Auditor represents an entity capable of emitting
// rich audit logs for certificate issuance events.
type Auditor interface {
	Audit(*Event) error
}
