package auditor

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/qldbsession"
	"github.com/awslabs/amazon-qldb-driver-go/v3/qldbdriver"
)

// QLDBAuditor is an Amazon QLDB
// implementation of the Auditor interface.
type QLDBAuditor struct {
	driver           *qldbdriver.QLDBDriver
	tableName        string
	executeTxTimeout time.Duration
}

// ensure QLDBAuditor implements Auditor.
var _ Auditor = (*QLDBAuditor)(nil)

// NewQLDBAuditor returns an Amazon QLDB implementation of the Auditor interface.
func NewQLDBAuditor(
	cfg aws.Config,
	ledgerName string,
	tableName string,
) (*QLDBAuditor, error) {
	driver, err := qldbdriver.New(
		ledgerName,
		qldbsession.NewFromConfig(cfg),
		func(options *qldbdriver.DriverOptions) {
			options.LoggerVerbosity = qldbdriver.LogInfo
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize QLDB driver: %v", err)
	}

	return &QLDBAuditor{
		driver:           driver,
		tableName:        tableName,
		executeTxTimeout: time.Second * 5,
	}, nil
}

// Close closes the QLDB driver.
func (q *QLDBAuditor) Close(ctx context.Context) {
	q.driver.Shutdown(ctx)
	return
}

// Audit handles an audit event.
func (q *QLDBAuditor) Audit(e *Event) error {
	ctx, cancel := context.WithTimeout(context.Background(), q.executeTxTimeout)
	defer cancel()

	_, err := q.driver.Execute(
		ctx,
		func(txn qldbdriver.Transaction) (interface{}, error) {
			return txn.Execute(fmt.Sprintf("INSERT INTO %s ?", q.tableName), e)
		},
	)
	if err != nil {
		return fmt.Errorf("failed to emit audit event via the Amazon QLDB driver: %v", err)
	}

	return nil
}
