package threats_service

import (
	"context"
	"fmt"
	"strings"

	"threatinfoservice/internal/core/domain"
	core_errors "threatinfoservice/internal/core/errors"
)

func (s *ThreatsService) UpdateThreat(ctx context.Context, md5 string, name string) (domain.Threat,error) {
	if !md5Pattern.MatchString(md5) {
		return domain.Threat{}, fmt.Errorf("invalid MD5 format: %w",core_errors.ErrInvalidArgument)
	}
	md5 = strings.ToLower(md5)
	nameLen := len([]rune(name))

	if nameLen < 1 ||
		nameLen > 100 ||
		strings.TrimSpace(name) == "" {

		return domain.Threat{}, fmt.Errorf("invalid threat name: %w",core_errors.ErrInvalidArgument)
	}

	updatedThreat, err := s.repository.UpdateThreat(ctx, md5, name)
	if err != nil {
		return domain.Threat{}, fmt.Errorf("update threat: %w",err)
	}
	return updatedThreat,nil
}