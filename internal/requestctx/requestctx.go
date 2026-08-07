package requestctx

import "context"

type key string

const (
	requestIDKey key = "request-id"
	taskIDKey    key = "task-id"
	jobIDKey     key = "job-id"
)

func WithRequestID(ctx context.Context, value string) context.Context {
	return context.WithValue(ctx, requestIDKey, value)
}

func RequestID(ctx context.Context) string {
	value, _ := ctx.Value(requestIDKey).(string)
	return value
}

func WithTaskID(ctx context.Context, value string) context.Context {
	return context.WithValue(ctx, taskIDKey, value)
}

func TaskID(ctx context.Context) string {
	value, _ := ctx.Value(taskIDKey).(string)
	return value
}

func WithJobID(ctx context.Context, value string) context.Context {
	return context.WithValue(ctx, jobIDKey, value)
}

func JobID(ctx context.Context) string {
	value, _ := ctx.Value(jobIDKey).(string)
	return value
}
