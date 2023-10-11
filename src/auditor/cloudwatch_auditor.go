package auditor

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
)

const (
	defaultPutLogEventsTimeout = time.Second * 5
)

// CloudWatchAuditor is an AWS CloudWatch
// implementation of the Auditor interface.
type CloudWatchAuditor struct {
	cwClient            *cloudwatchlogs.Client
	logGroup            string
	logStream           string
	putLogEventsTimeout time.Duration
}

// ensure CloudWatchAuditor implements Auditor.
var _ Auditor = (*CloudWatchAuditor)(nil)

// CloudWatchOption represents a configuration
// option for the AWS CloudWatch based Auditor.
type CloudWatchOption func(*CloudWatchAuditor)

// NewCloudWatchAuditor returns an AWS CloudWatch implementation of the Auditor interface.
func NewCloudWatchAuditor(
	cfg aws.Config,
	logGroup,
	logStream string,
	opts ...CloudWatchOption,
) *CloudWatchAuditor {
	a := &CloudWatchAuditor{
		cwClient:            cloudwatchlogs.NewFromConfig(cfg),
		logGroup:            logGroup,
		logStream:           logStream,
		putLogEventsTimeout: defaultPutLogEventsTimeout,
	}
	for _, opt := range opts {
		opt(a)
	}
	return a
}

// Audit handles an audit event.
func (a *CloudWatchAuditor) Audit(e *Event) error {
	jsonData, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("failed to json-encode audit event: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), a.putLogEventsTimeout)
	defer cancel()

	_, err = a.cwClient.PutLogEvents(
		ctx,
		&cloudwatchlogs.PutLogEventsInput{
			LogEvents: []types.InputLogEvent{
				{
					Timestamp: aws.Int64(e.Timestamp),
					Message:   aws.String(string(jsonData)),
				},
			},
			LogGroupName:  &a.logGroup,
			LogStreamName: &a.logStream,
		},
	)
	if err != nil {
		return fmt.Errorf("failed to emit audit event via the AWS CloudWatch Logs API: %v", err)
	}

	return nil
}
