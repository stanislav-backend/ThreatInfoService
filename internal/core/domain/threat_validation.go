package domain

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	core_errors "threatinfoservice/internal/core/errors"
)

var md5Pattern = regexp.MustCompile(`^[a-fA-F0-9]{32}$`)

func (t *Threat) Validate() error {
	if !md5Pattern.MatchString(t.MD5) {
		return fmt.Errorf(
			"invalid `MD5` format: %w",
			core_errors.ErrInvalidArgument,
		)
	}

	nameLen := len([]rune(t.Name))

	if nameLen < 1 || nameLen > 100 ||
		strings.TrimSpace(t.Name) == "" {
		return fmt.Errorf(
			"invalid `Name` len: %d: %w",
			nameLen,
			core_errors.ErrInvalidArgument,
		)
	}

	if t.Description != nil {
		descriptionLen := len([]rune(*t.Description))

		if descriptionLen < 1 || descriptionLen > 1000 ||
			strings.TrimSpace(*t.Description) == "" {
			return fmt.Errorf(
				"invalid `Description` len: %d: %w",
				descriptionLen,
				core_errors.ErrInvalidArgument,
			)
		}
	}

	switch t.Severity {
	case "", "low", "medium", "high", "critical":
	default:
		return fmt.Errorf(
			"invalid `Severity`: %s: %w",
			t.Severity,
			core_errors.ErrInvalidArgument,
		)
	}

	if t.ThreatType != nil {
		threatTypeLen := len([]rune(*t.ThreatType))

		if threatTypeLen < 1 || threatTypeLen > 50 ||
			strings.TrimSpace(*t.ThreatType) == "" {
			return fmt.Errorf(
				"invalid `ThreatType` len: %d: %w",
				threatTypeLen,
				core_errors.ErrInvalidArgument,
			)
		}
	}

	if t.CreatedAt.IsZero() {
		return fmt.Errorf(
			"`CreatedAt` cannot be zero: %w",
			core_errors.ErrInvalidArgument,
		)
	}

	if t.UpdatedAt.IsZero() {
		return fmt.Errorf(
			"`UpdatedAt` cannot be zero: %w",
			core_errors.ErrInvalidArgument,
		)
	}

	if t.UpdatedAt.Before(t.CreatedAt) {
		return fmt.Errorf(
			"`UpdatedAt` cannot be before `CreatedAt`: %w",
			core_errors.ErrInvalidArgument,
		)
	}

	if t.DetectedAt != nil {
		if t.DetectedAt.IsZero() {
			return fmt.Errorf(
				"`DetectedAt` cannot be zero: %w",
				core_errors.ErrInvalidArgument,
			)
		}

		if t.DetectedAt.After(time.Now().UTC()) {
			return fmt.Errorf(
				"`DetectedAt` cannot be in the future: %w",
				core_errors.ErrInvalidArgument,
			)
		}
	}

	return nil
}