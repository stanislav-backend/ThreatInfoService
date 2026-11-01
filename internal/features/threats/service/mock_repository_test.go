package threats_service

import (
	"context"
	"threatinfoservice/internal/core/domain"
)

type mockThreatsRepository struct {
	createThreatFunc func(context.Context, domain.Threat) (domain.Threat,error)
	getThreatFunc    func(context.Context, string) (domain.Threat, error)
	updateThreatFunc func(context.Context, string, string) (domain.Threat, error)
}

func (m *mockThreatsRepository) CreateThreat(ctx context.Context, threat domain.Threat) (domain.Threat,error) {
	return m.createThreatFunc(ctx, threat)
}

func (m *mockThreatsRepository) GetThreat(ctx context.Context, md5 string) (domain.Threat, error) {
	return m.getThreatFunc(ctx, md5)
}

func (m *mockThreatsRepository) UpdateThreat(ctx context.Context, md5 string, name string) (domain.Threat,error) {
	return m.updateThreatFunc(ctx, md5, name)
}