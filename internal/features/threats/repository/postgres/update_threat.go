package threats_postgres_repository

import (
	"context"
	"errors"
	"fmt"

	"threatinfoservice/internal/core/domain"
	core_errors "threatinfoservice/internal/core/errors"
	core_postgres_pool "threatinfoservice/internal/core/repository/postgres/pool"
)

func (r *ThreatsRepository) UpdateThreat(ctx context.Context, md5 string,name string) (domain.Threat,error){
	ctx, cancel := context.WithTimeout(
		ctx,
		r.pool.OpTimeout(),
	)
	defer cancel()

	query := `
		UPDATE threatinfoservice.threats
		SET
			name = $2,
			updated_at = NOW()
		WHERE md5 = $1
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
		ctx,query,
		md5,
		name,
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
			core_postgres_pool.ErrNoRows,
		){
			return domain.Threat{}, fmt.Errorf(
				"threat with MD5 '%s' not found: %w",md5,
				core_errors.ErrNotFound,
			)
		}

		return domain.Threat{}, fmt.Errorf(
			"update threat scan error: %w",err,
		)
	}

	return ThreatDomainFromModel(threatModel),nil
}