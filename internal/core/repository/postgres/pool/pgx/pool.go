package core_pgx_pool

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	core_postgres_pool "threatinfoservice/internal/core/repository/postgres/pool"
)

type Pool struct {
	*pgxpool.Pool

	opTimeOut time.Duration
}

var _ core_postgres_pool.Pool = (*Pool)(nil)

func NewPool(ctx context.Context, config Config) (*Pool, error) {
	connURL := &url.URL{
		Scheme: "postgres",
		User: url.UserPassword(
			config.User,
			config.Password,
		),
		Host: net.JoinHostPort(
			config.Host,
			config.Port,
		),
		Path: "/" + config.DataBase,
	}

	query := connURL.Query()
	query.Set("sslmode", "disable")
	connURL.RawQuery = query.Encode()

	pgxConfig, err := pgxpool.ParseConfig(connURL.String())
	if err != nil {
		return nil, fmt.Errorf("parse pgxconfig: %w", err)
	}

	pool, err := pgxpool.NewWithConfig(ctx, pgxConfig)
	if err != nil {
		return nil, fmt.Errorf("create pgxpool: %w", err)
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("pgxpool ping: %w", err)
	}

	return &Pool{
		Pool:      pool,
		opTimeOut: config.TimeOut,
	}, nil
}

func (p *Pool) Query(
	ctx context.Context,
	sql string,
	args ...any,
) (core_postgres_pool.Rows, error) {
	rows, err := p.Pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, mapErrors(err)
	}

	return pgxRows{Rows: rows}, nil
}

func (p *Pool) QueryRow(
	ctx context.Context,
	sql string,
	args ...any,
) core_postgres_pool.Row {
	row := p.Pool.QueryRow(ctx, sql, args...)

	return pgxRow{Row: row}
}

func (p *Pool) Exec(
	ctx context.Context,
	sql string,
	args ...any,
) (core_postgres_pool.CommandTag, error) {
	tag, err := p.Pool.Exec(ctx, sql, args...)
	if err != nil {
		return nil, mapErrors(err)
	}

	return pgxCommandTag{CommandTag: tag}, nil
}

func (p *Pool) OpTimeout() time.Duration {
	return p.opTimeOut
}