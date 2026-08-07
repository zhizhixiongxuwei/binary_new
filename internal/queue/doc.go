// Package queue owns durable MySQL job leasing and fencing.
//
// task_attempts.attempt_number is the user-visible logical task attempt. A
// task attempt can contain multiple automatic job deliveries, counted by
// jobs.attempt. Every successful Claim increments that job's fencing token.
// Scan-job claims also synchronize the token to the reused task_attempt row;
// child jobs keep independent fences so they cannot invalidate their parent
// scan attempt.
package queue
