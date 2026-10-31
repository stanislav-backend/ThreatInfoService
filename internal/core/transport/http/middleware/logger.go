package core_http_middleware

import (
	"net/http"
	"time"

	core_logger "threatinfoservice/internal/core/logger"
	core_http_response "threatinfoservice/internal/core/transport/http/response"

	"go.uber.org/zap"
)

func Logger(log *core_logger.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				start := time.Now()

				rw := core_http_response.NewResponseWriter(w)

				next.ServeHTTP(rw, r)

				duration := time.Since(start)
				statusCode := rw.GetStatusCode()

				log.Info(
					"HTTP request completed",
					zap.String("method", r.Method),
					zap.String("path", r.URL.Path),
					zap.Int("status", statusCode),
					zap.Duration("duration", duration),
				)
			},
		)
	}
}