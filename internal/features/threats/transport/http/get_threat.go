package threats_http

import (
	"net/http"

	core_http_response "threatinfoservice/internal/core/transport/http/response"
)

func (t *ThreatsTransport) GetThreat(w http.ResponseWriter, r *http.Request) {
	responseHandler := core_http_response.NewHTTPResponseHandler(
		t.log,
		w,
	)

	md5 := r.PathValue("md5")

	threat, err := t.service.GetThreat(r.Context(), md5)
	if err != nil {
		responseHandler.ErrorResponse(err,"Failed to get threat")
		return
	}

	responseHandler.JSONResponse(ThreatResponseFromDomain(threat),http.StatusOK)
}