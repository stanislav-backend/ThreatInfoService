package threats_http

import (
	"net/http"

	core_http_request "threatinfoservice/internal/core/transport/http/request"
	core_http_response "threatinfoservice/internal/core/transport/http/response"
)

func (t *ThreatsTransport) UpdateThreat(w http.ResponseWriter, r *http.Request) {
	responseHandler := core_http_response.NewHTTPResponseHandler(
		t.log,
		w,
	)

	md5 := r.PathValue("md5")

	var request ThreatUpdateRequest

	if err := core_http_request.DecodeJSON(w, r, &request); err != nil {
		responseHandler.ErrorResponse(err,"Invalid request")
		return
	}

	threat, err := t.service.UpdateThreat(r.Context(), md5, request.Name)
	if err != nil {
		responseHandler.ErrorResponse(err,"Failed to update threat")
		return
	}

	responseHandler.JSONResponse(ThreatResponseFromDomain(threat),http.StatusOK)
}