package main

import (
	"context"
	"errors"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	core_logger "threatinfoservice/internal/core/logger"
	core_pgx_pool "threatinfoservice/internal/core/repository/postgres/pool/pgx"
	core_http_middleware "threatinfoservice/internal/core/transport/http/middleware"
	core_http_server "threatinfoservice/internal/core/transport/http/server"
	threats_postgres_repository "threatinfoservice/internal/features/threats/repository/postgres"
	threats_service "threatinfoservice/internal/features/threats/service"
	threats_http "threatinfoservice/internal/features/threats/transport/http"
	"go.uber.org/zap"
)

func main() {
	loggerConfig := core_logger.NewConfigMust()
	log, err := core_logger.NewLogger(loggerConfig)
	if err != nil {
		panic(err)
	}
	defer log.Close()

	postgresConfig := core_pgx_pool.NewConfigMust()
	httpConfig := core_http_server.NewConfigMust()

	ctx := context.Background()
	pool, err := core_pgx_pool.NewPool(ctx, postgresConfig)
	if err != nil {
		log.Fatal("failed to connect to PostgreSQL",zap.Error(err))
	}
	defer pool.Close()

	log.Info("PostgreSQL connection established")

	repository := threats_postgres_repository.NewThreatsRepository(pool)
	service := threats_service.NewThreatsService(repository)
	transport := threats_http.NewThreatsTransport(
		service,
		log,
	)

	mux := http.NewServeMux()
	transport.RegisterRoutes(mux)

	handler := core_http_middleware.ChainMiddleware(
		mux,
		core_http_middleware.Logger(log),
		core_http_middleware.Recovery(log),
	)

	server := core_http_server.NewServer(httpConfig.Addr, handler)
	serverErrors := make(chan error, 1)

	go func() {
		serverErrors <- server.Start()
	}()

	log.Info("HTTP server started",zap.String("address", httpConfig.Addr))

	signalCtx, stop := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer stop()
	select {
	case <-signalCtx.Done():
		log.Info("shutdown signal received")

	case err := <-serverErrors:
		if err != nil {
			log.Error(
				"HTTP server failed",
				zap.Error(err),
			)
		} else {
			log.Info("HTTP server stopped")
		}
		return
	}
	shutdownCtx, cancel := context.WithTimeout(
		context.Background(),
		httpConfig.ShutdownTimeout,
	)
	defer cancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		if !errors.Is(err, context.Canceled) {
			log.Error(
				"failed to shutdown HTTP server",
				zap.Error(err),
			)
		}
		return
	}
	log.Info("HTTP server stopped gracefully")
}