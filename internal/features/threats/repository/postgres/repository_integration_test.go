package threats_postgres_repository

import (
	"context"
	"errors"
	"testing"

	"threatinfoservice/internal/core/domain"
	core_errors "threatinfoservice/internal/core/errors"
	core_pgx_pool "threatinfoservice/internal/core/repository/postgres/pool/pgx"
)

func TestCreateThreat_Integration(t *testing.T) {
	ctx := context.Background()
	config := core_pgx_pool.NewConfigMust()
	config.DataBase = "threatinfoservice_test"

	pool, err := core_pgx_pool.NewPool(ctx, config)
	if err != nil {
		t.Fatalf("connect to test database: %v", err)
	}

	t.Cleanup(func() {
		pool.Close()
	})
	repository := NewThreatsRepository(pool)

	md5 := "a41d8cd98f00b204e9800998ecf8427e"
	name := "Integration.Test.Threat"

	t.Cleanup(func() {
		_, err := pool.Exec(
			context.Background(),
			"DELETE FROM threatinfoservice.threats WHERE md5 = $1",
			md5,
		)
		if err != nil {
			t.Errorf("cleanup test threat: %v", err)
		}
	})

	threat := domain.NewThreatInitialized(
		md5,
		name,
		nil,
		"",
		nil,
		nil,
	)

	createdThreat, err := repository.CreateThreat(ctx, threat)
	if err != nil {
		t.Fatalf("CreateThreat() returned unexpected error: %v", err)
	}
	if createdThreat.MD5 != md5 {
		t.Errorf("expected MD5 %q, got %q", md5, createdThreat.MD5)
	}
	if createdThreat.Name != name {
		t.Errorf("expected name %q, got %q", name, createdThreat.Name)
	}
}


func TestGetThreat_Integration(t *testing.T) {
	ctx := context.Background()
	config := core_pgx_pool.NewConfigMust()
	config.DataBase = "threatinfoservice_test"

	pool, err := core_pgx_pool.NewPool(ctx, config)
	if err != nil {
		t.Fatalf("connect to test database: %v",err)
	}
	t.Cleanup(func() { pool.Close() })

	md5 := "b41d8cd98f00b204e9800998ecf8427e"
	name := "Integration.Get.Threat"

	t.Cleanup(func() {
		_, err := pool.Exec(context.Background(),
			"DELETE FROM threatinfoservice.threats WHERE md5 = $1", md5)
		if err != nil {
			t.Errorf("cleanup: %v", err)
		}
	})
	repository := NewThreatsRepository(pool)

	threat := domain.NewThreatInitialized(md5, name, nil, "", nil, nil)

	if _, err := repository.CreateThreat(ctx, threat); err != nil {
		t.Fatalf("prepare threat: %v", err)
	}

	result, err := repository.GetThreat(ctx, md5)
	if err != nil {
		t.Fatalf("GetThreat() returned unexpected error: %v", err)
	}
	if result.MD5 != md5 || result.Name != name {
		t.Errorf("unexpected threat: %+v", result)
	}
}

func TestUpdateThreat_Integration(t *testing.T) {
	ctx := context.Background()

	config := core_pgx_pool.NewConfigMust()
	config.DataBase = "threatinfoservice_test"

	pool, err := core_pgx_pool.NewPool(ctx, config)
	if err != nil {
		t.Fatalf("connect to test database: %v", err)
	}
	t.Cleanup(func() { pool.Close() })

	md5 := "c41d8cd98f00b204e9800998ecf8427e"
	t.Cleanup(func() {
		_, err := pool.Exec(context.Background(),
			"DELETE FROM threatinfoservice.threats WHERE md5 = $1", md5)
		if err != nil {
			t.Errorf("cleanup: %v", err)
		}
	})

	repository := NewThreatsRepository(pool)

	threat := domain.NewThreatInitialized(
		md5, "Old.Threat.Name", nil, "", nil, nil,
	)
	if _, err := repository.CreateThreat(ctx, threat); err != nil {
		t.Fatalf("prepare threat: %v", err)
	}

	updated, err := repository.UpdateThreat(ctx, md5, "New.Threat.Name")
	if err != nil {
		t.Fatalf("UpdateThreat() returned unexpected error: %v", err)
	}
	if updated.Name != "New.Threat.Name" {
		t.Errorf("expected updated name, got %q", updated.Name)
	}
	stored, err := repository.GetThreat(ctx, md5)
	if err != nil {
		t.Fatalf("get updated threat: %v", err)
	}

	if stored.Name != "New.Threat.Name" {
		t.Errorf("updated name was not saved: %q", stored.Name)
	}
}

func TestCreateThreat_Conflict_Integration(t *testing.T) {
	ctx := context.Background()
	config := core_pgx_pool.NewConfigMust()
	config.DataBase = "threatinfoservice_test"

	pool, err := core_pgx_pool.NewPool(ctx, config)
	if err != nil {
		t.Fatalf("connect to test database: %v", err)
	}
	t.Cleanup(func() { pool.Close() })
	md5 := "e41d8cd98f00b204e9800998ecf8427e"

	t.Cleanup(func() {
		_, err := pool.Exec(context.Background(),
			"DELETE FROM threatinfoservice.threats WHERE md5 = $1", md5)
		if err != nil {
			t.Errorf("cleanup: %v", err)
		}
	})
	repository := NewThreatsRepository(pool)

	threat := domain.NewThreatInitialized(
		md5, "Duplicate.Test", nil, "", nil, nil,
	)

	if _, err := repository.CreateThreat(ctx, threat); err != nil {
		t.Fatalf("prepare threat: %v", err)
	}
	_, err = repository.CreateThreat(ctx, threat)

	if !errors.Is(err, core_errors.ErrConflict) {
		t.Fatalf("expected ErrConflict, got %v", err)
	}
}

func TestGetThreat_NotFound_Integration(t *testing.T) {
	ctx := context.Background()
	config := core_pgx_pool.NewConfigMust()
	config.DataBase = "threatinfoservice_test"

	pool, err := core_pgx_pool.NewPool(ctx, config)
	if err != nil {
		t.Fatalf("connect to test database: %v", err)
	}
	defer pool.Close()
	repository := NewThreatsRepository(pool)

	md5 := "f41d8cd98f00b204e9800998ecf8427e"
	_, err = repository.GetThreat(ctx, md5)

	if !errors.Is(err, core_errors.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestUpdateThreat_NotFound_Integration(t *testing.T) {
	ctx := context.Background()

	config := core_pgx_pool.NewConfigMust()
	config.DataBase = "threatinfoservice_test"
	pool, err := core_pgx_pool.NewPool(ctx, config)
	if err != nil {
		t.Fatalf("connect to test database: %v", err)
	}
	defer pool.Close()

	repository := NewThreatsRepository(pool)

	md5 := "041d8cd98f00b204e9800998ecf8427e"

	_, err = repository.UpdateThreat(ctx, md5, "Missing.Threat")

	if !errors.Is(err, core_errors.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}