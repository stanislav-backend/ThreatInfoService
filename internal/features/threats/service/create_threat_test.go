package threats_service

import (
	"context"
	"testing"

	"errors"
	"threatinfoservice/internal/core/domain"
	core_errors "threatinfoservice/internal/core/errors"
)

func TestCreateThreat_Success(t *testing.T) {
	ctx := context.Background()

	md5 := "d41d8cd98f00b204e9800998ecf8427e"
	name := "Trojan.Win32.Test"

	repositoryCalled := false
	repository := &mockThreatsRepository{
		createThreatFunc: func(
			ctx context.Context,
			threat domain.Threat,
		) (domain.Threat,error) {
			repositoryCalled = true

			if threat.MD5 != md5 {
				t.Errorf("expected MD5 %q, got %q", md5, threat.MD5)
			}
			if threat.Name != name {
				t.Errorf("expected name %q, got %q", name, threat.Name)
			}

			return threat, nil
		},
	}

	service := NewThreatsService(repository)

	createdThreat, err := service.CreateThreat(ctx, md5, name)
	if err != nil {
		t.Fatalf("CreateThreat() returned unexpected error: %v", err)
	}
	if !repositoryCalled {
		t.Fatal("repository CreateThreat() was not called")
	}

	if createdThreat.MD5 != md5 {
		t.Errorf("expected MD5 %q, got %q", md5, createdThreat.MD5)
	}

	if createdThreat.Name != name {
		t.Errorf("expected name %q, got %q", name, createdThreat.Name)
	}
}



func TestCreateThreat_InvalidMD5(t *testing.T) {
	ctx := context.Background()
	repositoryCalled := false

	repository := &mockThreatsRepository{
		createThreatFunc: func(
			ctx context.Context,
			threat domain.Threat,
		) (domain.Threat,error) {
			repositoryCalled = true
			return threat, nil
		},
	}
	service := NewThreatsService(repository)
	_, err := service.CreateThreat(ctx, "invalid-md5", "Trojan.Win32.Test")

	if err == nil {
		t.Fatal("expected validation error, got nil")
	}

	if repositoryCalled {
		t.Error("repository must not be called for invalid MD5")
	}
}


func TestCreateThreat_EmptyName(t *testing.T) {
	repositoryCalled := false
	repository := &mockThreatsRepository{
		createThreatFunc: func(
			ctx context.Context,
			threat domain.Threat,
		) (domain.Threat,error) {
			repositoryCalled = true
			return threat, nil
		},
	}
	service := NewThreatsService(repository)

	_, err := service.CreateThreat(
		context.Background(),
		"d41d8cd98f00b204e9800998ecf8427e",
		"",
	)

	if !errors.Is(err, core_errors.ErrInvalidArgument) {
		t.Fatalf("expected ErrInvalidArgument, got %v", err)
	}
	if repositoryCalled {
		t.Error("repository must not be called for empty name")
	}
}

func TestCreateThreat_WhitespaceName(t *testing.T) {
	repositoryCalled := false

	repository := &mockThreatsRepository{
		createThreatFunc: func(
			ctx context.Context,
			threat domain.Threat,
		) (domain.Threat,error) {
			repositoryCalled = true
			return threat, nil
		},
	}

	service := NewThreatsService(repository)
	_, err := service.CreateThreat(
		context.Background(),
		"d41d8cd98f00b204e9800998ecf8427e",
		"   ",
	)

	if !errors.Is(err, core_errors.ErrInvalidArgument) {
		t.Fatalf("expected ErrInvalidArgument, got %v", err)
	}
	if repositoryCalled {
		t.Error("repository must not be called for whitespace name")
	}
}

func TestCreateThreat_Conflict(t *testing.T) {
	repository := &mockThreatsRepository{
		createThreatFunc: func(
			ctx context.Context,
			threat domain.Threat,
		) (domain.Threat,error) {
			return domain.Threat{}, core_errors.ErrConflict
		},
	}

	service := NewThreatsService(repository)
	_, err := service.CreateThreat(
		context.Background(),
		"d41d8cd98f00b204e9800998ecf8427e",
		"Trojan.Win32.Test",
	)

	if !errors.Is(err, core_errors.ErrConflict) {
		t.Fatalf("expected ErrConflict, got %v", err)
	}
}

func TestCreateThreat_RepositoryError(t *testing.T) {
	expectedErr := errors.New("database unavailable")
	repository := &mockThreatsRepository{
		createThreatFunc: func(
			ctx context.Context,
			threat domain.Threat,
		) (domain.Threat,error) {
			return domain.Threat{}, expectedErr
		},
	}

	service := NewThreatsService(repository)

	_, err := service.CreateThreat(
		context.Background(),
		"d41d8cd98f00b204e9800998ecf8427e",
		"Trojan.Win32.Test",
	)

	if !errors.Is(err, expectedErr) {
		t.Fatalf("expected repository error, got %v", err)
	}
}