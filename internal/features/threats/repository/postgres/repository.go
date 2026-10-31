package threats_postgres_repository

import (
	core_postgres_pool "threatinfoservice/internal/core/repository/postgres/pool"
)

type ThreatsRepository struct {
	pool core_postgres_pool.Pool
}

func NewThreatsRepository(
	pool core_postgres_pool.Pool,
) *ThreatsRepository {
	return &ThreatsRepository{
		pool: pool,
	}
}