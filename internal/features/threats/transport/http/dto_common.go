package threats_http

import "threatinfoservice/internal/core/domain"

type ThreatCreateRequest struct {
	MD5  string `json:"md5"`
	Name string `json:"name"`
}
type ThreatUpdateRequest struct {
	Name string `json:"name"`
}
type ThreatResponse struct {
	MD5  string `json:"md5"`
	Name string `json:"name"`
}

func ThreatResponseFromDomain(threat domain.Threat) ThreatResponse {
	return ThreatResponse{
		MD5:  threat.MD5,
		Name: threat.Name,
	}
}