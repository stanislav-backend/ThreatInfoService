package threats_postgres_repository

import (
	"time"

	"threatinfoservice/internal/core/domain"
)

type ThreatModel struct {
	MD5 string

	Name        string
	Description *string
	Severity    string
	ThreatType  *string

	DetectedAt *time.Time
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

func ThreatDomainFromModel(
	threatModel ThreatModel,
) domain.Threat {
	return domain.NewThreat(
		threatModel.MD5,
		threatModel.Name,
		threatModel.Description,
		threatModel.Severity,
		threatModel.ThreatType,
		threatModel.DetectedAt,
		threatModel.CreatedAt,
		threatModel.UpdatedAt,
	)
}

func threatDomainsFromModels(
	threatModels []ThreatModel,
) []domain.Threat {
	threatDomains := make(
		[]domain.Threat,
		len(threatModels),
	)

	for i, model := range threatModels {
		threatDomains[i] = ThreatDomainFromModel(model)
	}

	return threatDomains
}