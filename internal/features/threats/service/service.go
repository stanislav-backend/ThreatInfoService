package threats_service

import (
	"context"

	"threatinfoservice/internal/core/domain"
)

type ThreatsRepository interface {
	CreateThreat(ctx context.Context, threat domain.Threat) (domain.Threat,error)
	GetThreat(ctx context.Context, md5 string) (domain.Threat,error)
	UpdateThreat(ctx context.Context, md5 string, name string) (domain.Threat, error)
}

type ThreatsService struct {
	repository ThreatsRepository
}

func NewThreatsService(repository ThreatsRepository) *ThreatsService {
	return &ThreatsService{
		repository: repository,
	}
}