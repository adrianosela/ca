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

// cwAuditor is an AWS CloudWatch
// implementation of the Auditor interface.
type cwAuditor struct {
	cwClient            *cloudwatchlogs.Client
	logGroup            string
	logStream           string
	putLogEventsTimeout time.Duration
}

// ensure cwAuditor implements Auditor.
var _ Auditor = (*cwAuditor)(nil)

// CloudWatchOption represents a configuration
// option for the AWS CloudWatch based Auditor.
type CloudWatchOption func(*cwAuditor)

// NewCloudWatch returns an AWS CloudWatch implementation of the Auditor interface.
func NewCloudWatch(
	cfg aws.Config,
	logGroup,
	logStream string,
	opts ...CloudWatchOption,
) Auditor {
	a := &cwAuditor{
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
func (a *cwAuditor) Audit(e *Event) error {
	ctx, cancel := context.WithTimeout(context.Background(), a.putLogEventsTimeout)
	defer cancel()

	jsonData, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("failed to json-encode audit event: %v", err)
	}

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
		return fmt.Errorf("failed to put log events: %v", err)
	}

	return nil
}
