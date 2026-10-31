package threats_service

import (
	"context"
	"fmt"

	"threatinfoservice/internal/core/domain"
)

func (s *ThreatsService) CreateThreat(ctx context.Context, md5 string, name string) (domain.Threat,error) {
	threat := domain.NewThreatInitialized(md5,name, nil, "",nil,nil)

	if err := threat.Validate(); err != nil {
		return domain.Threat{}, fmt.Errorf("validate threat: %w",err)
	}

	createdThreat, err := s.repository.CreateThreat(ctx, threat)
	if err != nil {
		return domain.Threat{}, fmt.Errorf("create threat: %w",err)
	}

	return createdThreat,nil
}