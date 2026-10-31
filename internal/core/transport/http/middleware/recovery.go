package core_http_middleware

import (
	"net/http"

	core_logger "threatinfoservice/internal/core/logger"
	core_http_response "threatinfoservice/internal/core/transport/http/response"
)

func Recovery(log *core_logger.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				defer func() {
					if recovered := recover(); recovered != nil {
						responseHandler := core_http_response.NewHTTPResponseHandler(
							log,
							w,
						)

						responseHandler.PanicResponse(recovered,"HTTP request panic")
					}
				}()
				next.ServeHTTP(w, r)
			},
		)
	}
}