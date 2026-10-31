package threats_http

import (
	"net/http"

	core_http_request "threatinfoservice/internal/core/transport/http/request"
	core_http_response "threatinfoservice/internal/core/transport/http/response"
)

func (t *ThreatsTransport) CreateThreat(w http.ResponseWriter, r *http.Request) {
	responseHandler := core_http_response.NewHTTPResponseHandler(
		t.log,
		w,
	)

	var request ThreatCreateRequest

	if err := core_http_request.DecodeJSON(w, r, &request); err != nil {
		responseHandler.ErrorResponse(err,"Invalid request")
		return
	}

	threat, err := t.service.CreateThreat(r.Context(), request.MD5, request.Name)
	if err != nil {
		responseHandler.ErrorResponse(err,"Failed to create threat")
		return
	}

	responseHandler.JSONResponse(ThreatResponseFromDomain(threat),http.StatusCreated)
}