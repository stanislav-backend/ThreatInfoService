package threats_http

import "net/http"

func (t *ThreatsTransport) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /info", t.CreateThreat)
	mux.HandleFunc("GET /info/{md5}", t.GetThreat)
	mux.HandleFunc("PUT /info/{md5}", t.UpdateThreat)
}