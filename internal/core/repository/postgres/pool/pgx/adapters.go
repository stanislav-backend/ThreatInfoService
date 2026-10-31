package core_pgx_pool

import (
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	core_postgres_pool "threatinfoservice/internal/core/repository/postgres/pool"
)

type pgxRows struct {
	pgx.Rows
}

func (r pgxRows) Scan(dest ...any) error {
	if err := r.Rows.Scan(dest...); err != nil {
		return mapErrors(err)
	}

	return nil
}

func (r pgxRows) Err() error {
	if err := r.Rows.Err(); err != nil {
		return mapErrors(err)
	}

	return nil
}

type pgxRow struct {
	pgx.Row
}

func (r pgxRow) Scan(dest ...any) error {
	if err := r.Row.Scan(dest...); err != nil {
		return mapErrors(err)
	}

	return nil
}

type pgxCommandTag struct {
	pgconn.CommandTag
}

func mapErrors(err error) error {
	if err == nil {
		return nil
	}

	const (
		pgxViolatesForeignKeyErrorCode = "23503"
		pgxUniqueViolationErrorCode    = "23505"
	)

	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf(
			"%v: %w",
			err,
			core_postgres_pool.ErrNoRows,
		)
	}

	var pgErr *pgconn.PgError

	if errors.As(err, &pgErr) {
		switch pgErr.Code {

		case pgxViolatesForeignKeyErrorCode:
			return fmt.Errorf(
				"%v: %w",
				err,
				core_postgres_pool.ErrViolatesForeignKey,
			)

		case pgxUniqueViolationErrorCode:
			return fmt.Errorf(
				"%v: %w",
				err,
				core_postgres_pool.ErrUniqueViolation,
			)
		}
	}

	return fmt.Errorf(
		"%v: %w",
		err,
		core_postgres_pool.ErrUnknown,
	)
}