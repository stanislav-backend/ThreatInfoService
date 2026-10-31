package threats_service

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"threatinfoservice/internal/core/domain"
	core_errors "threatinfoservice/internal/core/errors"
)

var md5Pattern = regexp.MustCompile(`^[a-fA-F0-9]{32}$`)

func (s *ThreatsService) GetThreat(ctx context.Context, md5 string) (domain.Threat,error) {
	md5 = strings.ToLower(md5)

	if !md5Pattern.MatchString(md5) {
		return domain.Threat{}, fmt.Errorf("invalid MD5 format: %w",core_errors.ErrInvalidArgument)
	}

	threat, err := s.repository.GetThreat(ctx, md5)
	if err != nil {
		return domain.Threat{}, fmt.Errorf("get threat: %w",err)
	}

	return threat,nil
}