// Package aws validates AWS caller identity by verifying presigned
// GetCallerIdentity requests against AWS STS. This enables AWS workloads
// (Lambda, ECS, EC2) to exchange IAM role credentials for WIMSE JWTs.
package aws
