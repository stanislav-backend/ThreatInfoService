package threats_postgres_repository

import (
	"context"
	"errors"
	"fmt"

	"threatinfoservice/internal/core/domain"
	core_errors "threatinfoservice/internal/core/errors"
	core_postgres_pool "threatinfoservice/internal/core/repository/postgres/pool"
)

func (r *ThreatsRepository) CreateThreat(
	ctx context.Context,
	threat domain.Threat,
) (domain.Threat, error) {
	ctx, cancel := context.WithTimeout(
		ctx,
		r.pool.OpTimeout(),
	)
	defer cancel()

	query := `
		INSERT INTO threatinfoservice.threats (
			md5,
			name,
			description,
			severity,
			threat_type,
			detected_at,
			created_at,
			updated_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING
			md5,
			name,
			description,
			severity,
			threat_type,
			detected_at,
			created_at,
			updated_at;
	`

	row := r.pool.QueryRow(
		ctx,
		query,
		threat.MD5,
		threat.Name,
		threat.Description,
		threat.Severity,
		threat.ThreatType,
		threat.DetectedAt,
		threat.CreatedAt,
		threat.UpdatedAt,
	)

	var threatModel ThreatModel

	if err := row.Scan(
		&threatModel.MD5,
		&threatModel.Name,
		&threatModel.Description,
		&threatModel.Severity,
		&threatModel.ThreatType,
		&threatModel.DetectedAt,
		&threatModel.CreatedAt,
		&threatModel.UpdatedAt,
	); err != nil {

		if errors.Is(
			err,
			core_postgres_pool.ErrUniqueViolation,
		) {
			return domain.Threat{}, fmt.Errorf(
				"threat with MD5 '%s' already exists: %w",
				threat.MD5,
				core_errors.ErrConflict,
			)
		}

		return domain.Threat{}, fmt.Errorf(
			"create threat scan error: %w",
			err,
		)
	}

	return ThreatDomainFromModel(threatModel), nil
}