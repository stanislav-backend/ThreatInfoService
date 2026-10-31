package domain

import (
	"strings"
	"time"
)

type Threat struct {
	MD5 string

	Name        string
	Description *string
	Severity    string
	ThreatType  *string

	DetectedAt *time.Time
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

func NewThreat(
	md5 string,
	name string,
	description *string,
	severity string,
	threatType *string,
	detectedAt *time.Time,
	createdAt time.Time,
	updatedAt time.Time,
) Threat {
	return Threat{
		MD5:         strings.ToLower(md5),
		Name:        name,
		Description: description,
		Severity:    severity,
		ThreatType:  threatType,
		DetectedAt:  detectedAt,
		CreatedAt:   createdAt,
		UpdatedAt:   updatedAt,
	}
}

func NewThreatInitialized(
	md5 string,
	name string,
	description *string,
	severity string,
	threatType *string,
	detectedAt *time.Time,
) Threat {
	now := time.Now().UTC()

	return NewThreat(
		md5,
		name,
		description,
		severity,
		threatType,
		detectedAt,
		now,
		now,
	)
}