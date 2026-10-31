package threats_http

import (
	"context"

	"threatinfoservice/internal/core/domain"
	core_logger "threatinfoservice/internal/core/logger"
)

type ThreatsService interface {
	CreateThreat(ctx context.Context, md5 string, name string) (domain.Threat,error)
	GetThreat(ctx context.Context, md5 string) (domain.Threat,error)
	UpdateThreat(ctx context.Context, md5 string, name string) (domain.Threat, error)
}
type ThreatsTransport struct {
	service ThreatsService
	log     *core_logger.Logger
}

func NewThreatsTransport(service ThreatsService, log *core_logger.Logger) *ThreatsTransport {
	return &ThreatsTransport{
		service: service,
		log:     log,
	}
}