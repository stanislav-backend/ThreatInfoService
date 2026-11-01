package threats_service

import (
	"context"
	"errors"
	"testing"

	"threatinfoservice/internal/core/domain"
	core_errors "threatinfoservice/internal/core/errors"
)

func TestUpdateThreat_Success(t *testing.T) {
	md5 := "d41d8cd98f00b204e9800998ecf8427e"
	name := "Trojan.Win32.Updated"
	repositoryCalled := false

	repository := &mockThreatsRepository{
		updateThreatFunc: func(
			ctx context.Context,
			receivedMD5 string,
			receivedName string,
		) (domain.Threat,error) {
			repositoryCalled = true
			if receivedMD5 != md5 {
				t.Errorf("expected MD5 %q, got %q", md5, receivedMD5)
			}

			if receivedName != name {
				t.Errorf("expected name %q, got %q", name, receivedName)
			}
			return domain.Threat{
				MD5:  md5,
				Name: name,
			}, nil
		},
	}

	service := NewThreatsService(repository)
	updatedThreat, err := service.UpdateThreat(
		context.Background(),
		md5,
		name,
	)

	if err != nil {
		t.Fatalf("UpdateThreat() returned unexpected error: %v", err)
	}
	if !repositoryCalled {
		t.Fatal("repository UpdateThreat() was not called")
	}

	if updatedThreat.MD5 != md5 {
		t.Errorf("expected MD5 %q, got %q", md5, updatedThreat.MD5)
	}

	if updatedThreat.Name != name {
		t.Errorf("expected name %q, got %q", name, updatedThreat.Name)
	}
}

func TestUpdateThreat_InvalidMD5(t *testing.T) {
	repositoryCalled := false
	repository := &mockThreatsRepository{
		updateThreatFunc: func(
			ctx context.Context,
			md5 string,
			name string,
		) (domain.Threat,error) {
			repositoryCalled = true
			return domain.Threat{}, nil
		},
	}

	service := NewThreatsService(repository)

	_, err := service.UpdateThreat(
		context.Background(),
		"invalid-md5",
		"Trojan.Win32.Updated",
	)

	if !errors.Is(err, core_errors.ErrInvalidArgument) {
		t.Fatalf("expected ErrInvalidArgument, got %v", err)
	}
	if repositoryCalled {
		t.Error("repository must not be called for invalid MD5")
	}
}

func TestUpdateThreat_EmptyName(t *testing.T) {
	repositoryCalled := false
	repository := &mockThreatsRepository{
		updateThreatFunc: func(
			ctx context.Context,
			md5 string,
			name string,
		) (domain.Threat,error) {
			repositoryCalled = true
			return domain.Threat{}, nil
		},
	}

	service := NewThreatsService(repository)

	_, err := service.UpdateThreat(
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

func TestUpdateThreat_UppercaseMD5(t *testing.T) {
	uppercaseMD5 := "D41D8CD98F00B204E9800998ECF8427E"
	lowercaseMD5 := "d41d8cd98f00b204e9800998ecf8427e"
	name := "Trojan.Win32.Updated"

	repositoryCalled := false
	repository := &mockThreatsRepository{
		updateThreatFunc: func(
			ctx context.Context,
			md5 string,
			receivedName string,
		) (domain.Threat,error) {
			repositoryCalled = true

			if md5 != lowercaseMD5 {
				t.Errorf("expected lowercase MD5 %q, got %q", lowercaseMD5, md5)
			}

			if receivedName != name {
				t.Errorf("expected name %q, got %q", name, receivedName)
			}

			return domain.Threat{
				MD5:  lowercaseMD5,
				Name: name,
			}, nil
		},
	}

	service := NewThreatsService(repository)

	updatedThreat, err := service.UpdateThreat(
		context.Background(),
		uppercaseMD5,
		name,
	)
	if err != nil {
		t.Fatalf("UpdateThreat() returned unexpected error: %v", err)
	}

	if !repositoryCalled {
		t.Fatal("repository UpdateThreat() was not called")
	}
	if updatedThreat.MD5 != lowercaseMD5 {
		t.Errorf("expected MD5 %q, got %q", lowercaseMD5, updatedThreat.MD5)
	}
}

func TestUpdateThreat_NotFound(t *testing.T) {
	repository := &mockThreatsRepository{
		updateThreatFunc: func(
			ctx context.Context,
			md5 string,
			name string,
		) (domain.Threat,error) {
			return domain.Threat{}, core_errors.ErrNotFound
		},
	}

	service := NewThreatsService(repository)
	_, err := service.UpdateThreat(
		context.Background(),
		"d41d8cd98f00b204e9800998ecf8427e",
		"Trojan.Win32.Updated",
	)

	if !errors.Is(err, core_errors.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestUpdateThreat_RepositoryError(t *testing.T) {
	expectedErr := errors.New("database unavailable")
	repository := &mockThreatsRepository{
		updateThreatFunc: func(
			ctx context.Context,
			md5 string,
			name string,
		) (domain.Threat,error) {
			return domain.Threat{}, expectedErr
		},
	}

	service := NewThreatsService(repository)
	_, err := service.UpdateThreat(
		context.Background(),
		"d41d8cd98f00b204e9800998ecf8427e",
		"Trojan.Win32.Updated",
	)
	if !errors.Is(err, expectedErr) {
		t.Fatalf("expected repository error, got %v", err)
	}
}