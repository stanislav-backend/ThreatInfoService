package threats_service

import (
	"context"
	"errors"
	"testing"

	"threatinfoservice/internal/core/domain"
	core_errors "threatinfoservice/internal/core/errors"
)

func TestGetThreat_Success(t *testing.T) {
	md5 := "d41d8cd98f00b204e9800998ecf8427e"
	expectedThreat := domain.Threat{
		MD5:  md5,
		Name: "Trojan.Win32.Test",
	}
	repositoryCalled := false

	repository := &mockThreatsRepository{
		getThreatFunc: func(ctx context.Context, receivedMD5 string) (domain.Threat,error) {
			repositoryCalled = true

			if receivedMD5 != md5 {
				t.Errorf("expected MD5 %q, got %q", md5, receivedMD5)
			}

			return expectedThreat, nil
		},
	}
	service := NewThreatsService(repository)
	threat, err := service.GetThreat(context.Background(), md5)
	if err != nil {
		t.Fatalf("GetThreat() returned unexpected error: %v", err)
	}

	if !repositoryCalled {
		t.Fatal("repository GetThreat() was not called")
	}
	if threat.MD5 != expectedThreat.MD5 {
		t.Errorf("expected MD5 %q, got %q", expectedThreat.MD5, threat.MD5)
	}
	if threat.Name != expectedThreat.Name {
		t.Errorf("expected name %q, got %q", expectedThreat.Name, threat.Name)
	}
}

func TestGetThreat_InvalidMD5(t *testing.T) {
	repositoryCalled := false

	repository := &mockThreatsRepository{
		getThreatFunc: func(ctx context.Context, md5 string) (domain.Threat, error) {
			repositoryCalled = true
			return domain.Threat{}, nil
		},
	}

	service := NewThreatsService(repository)
	_, err := service.GetThreat(context.Background(), "invalid-md5")

	if !errors.Is(err, core_errors.ErrInvalidArgument) {
		t.Fatalf("expected ErrInvalidArgument, got %v", err)
	}
	if repositoryCalled {
		t.Error("repository must not be called for invalid MD5")
	}
}

func TestGetThreat_UppercaseMD5(t *testing.T) {
	uppercaseMD5 := "D41D8CD98F00B204E9800998ECF8427E"
	lowercaseMD5 := "d41d8cd98f00b204e9800998ecf8427e"
	repositoryCalled := false

	repository := &mockThreatsRepository{
		getThreatFunc: func(ctx context.Context, md5 string) (domain.Threat, error) {
			repositoryCalled = true

			if md5 != lowercaseMD5 {
				t.Errorf("expected lowercase MD5 %q, got %q", lowercaseMD5, md5)
			}

			return domain.Threat{
				MD5:  lowercaseMD5,
				Name: "Trojan.Win32.Test",
			}, nil
		},
	}
	service := NewThreatsService(repository)

	threat, err := service.GetThreat(context.Background(), uppercaseMD5)
	if err != nil {
		t.Fatalf("GetThreat() returned unexpected error: %v", err)
	}

	if !repositoryCalled {
		t.Fatal("repository GetThreat() was not called")
	}
	if threat.MD5 != lowercaseMD5 {
		t.Errorf("expected MD5 %q, got %q", lowercaseMD5, threat.MD5)
	}
}

func TestGetThreat_NotFound(t *testing.T) {
	repository := &mockThreatsRepository{
		getThreatFunc: func(ctx context.Context, md5 string) (domain.Threat, error) {
			return domain.Threat{}, core_errors.ErrNotFound
		},
	}

	service := NewThreatsService(repository)
	_, err := service.GetThreat(
		context.Background(),
		"d41d8cd98f00b204e9800998ecf8427e",
	)
	if !errors.Is(err, core_errors.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestGetThreat_RepositoryError(t *testing.T) {
	expectedErr := errors.New("database unavailable")

	repository := &mockThreatsRepository{
		getThreatFunc: func(ctx context.Context, md5 string) (domain.Threat, error) {
			return domain.Threat{}, expectedErr
		},
	}

	service := NewThreatsService(repository)
	_, err := service.GetThreat(
		context.Background(),
		"d41d8cd98f00b204e9800998ecf8427e",
	)

	if !errors.Is(err, expectedErr) {
		t.Fatalf("expected repository error, got %v", err)
	}
}

func TestGetThreat_EmptyMD5(t *testing.T) {
	repositoryCalled := false
	repository := &mockThreatsRepository{
		getThreatFunc: func(ctx context.Context, md5 string) (domain.Threat, error) {
			repositoryCalled = true
			return domain.Threat{}, nil
		},
	}

	service := NewThreatsService(repository)

	_, err := service.GetThreat(context.Background(), "")

	if !errors.Is(err, core_errors.ErrInvalidArgument) {
		t.Fatalf("expected ErrInvalidArgument, got %v", err)
	}
	if repositoryCalled {
		t.Error("repository must not be called for empty MD5")
	}
}