package integration_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	core_logger "threatinfoservice/internal/core/logger"
	core_pgx_pool "threatinfoservice/internal/core/repository/postgres/pool/pgx"
	threats_repository "threatinfoservice/internal/features/threats/repository/postgres"
	threats_service "threatinfoservice/internal/features/threats/service"
	threats_http "threatinfoservice/internal/features/threats/transport/http"
)

func setupTestAPI(t *testing.T) (http.Handler, *core_pgx_pool.Pool) {
	t.Helper()
	ctx := context.Background()

	config := core_pgx_pool.NewConfigMust()
	config.DataBase = "threatinfoservice_test"

	pool, err := core_pgx_pool.NewPool(ctx, config)
	if err != nil {
		t.Fatalf("connect to test database: %v", err)
	}
	t.Cleanup(func() {
		pool.Close()
	})
	log, err := core_logger.NewLogger(core_logger.NewConfigMust())
	if err != nil {
		t.Fatalf("create test logger: %v",err)
	}

	t.Cleanup(func() {
		log.Close()
	})

	repository := threats_repository.NewThreatsRepository(pool)
	service := threats_service.NewThreatsService(repository)
	transport := threats_http.NewThreatsTransport(service, log)

	mux := http.NewServeMux()
	transport.RegisterRoutes(mux)

	return mux, pool
}

func cleanupThreat(t *testing.T, pool *core_pgx_pool.Pool, md5 string) {
	t.Helper()

	t.Cleanup(func() {
		_, err := pool.Exec(
			context.Background(),
			"DELETE FROM threatinfoservice.threats WHERE md5 = $1",
			md5,
		)
		if err != nil {
			t.Errorf("cleanup test threat: %v", err)
		}
	})
}

func sendRequest(t *testing.T, handler http.Handler, method string, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var requestBody *bytes.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal request: %v", err)
		}
		requestBody = bytes.NewReader(data)
	} else {
		requestBody = bytes.NewReader(nil)
	}

	req := httptest.NewRequest(method, path, requestBody)
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	return rec
}

func TestHTTP_CreateThreat(t *testing.T) {
	handler, pool := setupTestAPI(t)
	md5 := "11111111111111111111111111111111"
	name := "HTTP.Integration.Create"

	cleanupThreat(t, pool, md5)

	rec := sendRequest(t, handler, http.MethodPost, "/info", map[string]string{
		"md5":  md5,
		"name": name,
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("expected HTTP 201, got %d: %s", rec.Code, rec.Body.String())
	}

	var response struct {
		MD5  string `json:"md5"`
		Name string `json:"name"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if response.MD5 != md5 || response.Name != name {
		t.Errorf("unexpected response: %+v", response)
	}
}

func TestHTTP_GetThreat(t *testing.T) {
	handler, pool := setupTestAPI(t)
	md5 := "22222222222222222222222222222222"
	name := "HTTP.Integration.Get"

	cleanupThreat(t, pool, md5)
	created := sendRequest(t, handler, http.MethodPost, "/info", map[string]string{
		"md5":  md5,
		"name": name,
	})

	if created.Code != http.StatusCreated {
		t.Fatalf("prepare threat: %s", created.Body.String())
	}

	rec := sendRequest(t, handler, http.MethodGet, "/info/"+md5, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var response struct {
		MD5  string `json:"md5"`
		Name string `json:"name"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.MD5 != md5 || response.Name != name {
		t.Errorf("unexpected response: %+v", response)
	}
}

func TestHTTP_UpdateThreat(t *testing.T) {
	handler, pool := setupTestAPI(t)

	md5 := "33333333333333333333333333333333"
	cleanupThreat(t, pool, md5)

	created := sendRequest(t, handler, http.MethodPost, "/info", map[string]string{
		"md5":  md5,
		"name": "Old.Name",
	})
	if created.Code != http.StatusCreated {
		t.Fatalf("prepare threat: %s", created.Body.String())
	}

	rec := sendRequest(t, handler, http.MethodPut, "/info/"+md5, map[string]string{
		"name": "New.Name",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d: %s", rec.Code, rec.Body.String())
	}

	stored := sendRequest(t, handler, http.MethodGet, "/info/"+md5, nil)

	if stored.Code != http.StatusOK {
		t.Fatalf("get updated threat: %s", stored.Body.String())
	}

	var response struct {
		MD5  string `json:"md5"`
		Name string `json:"name"`
	}
	if err := json.Unmarshal(stored.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.MD5 != md5 || response.Name != "New.Name" {
		t.Errorf("update was not saved: %+v", response)
	}
}

func TestHTTP_CreateThreat_Conflict(t *testing.T) {
	handler, pool := setupTestAPI(t)

	md5 := "44444444444444444444444444444444"
	cleanupThreat(t, pool, md5)
	body := map[string]string{
		"md5":  md5,
		"name": "Duplicate.Threat",
	}

	first := sendRequest(t, handler, http.MethodPost, "/info", body)

	if first.Code != http.StatusCreated {
		t.Fatalf("prepare threat: %s", first.Body.String())
	}
	second := sendRequest(t, handler, http.MethodPost, "/info", body)

	if second.Code != http.StatusConflict {
		t.Fatalf("expected HTTP 409, got %d: %s", second.Code, second.Body.String())
	}
}

func TestHTTP_GetThreat_NotFound(t *testing.T) {
	handler, _ := setupTestAPI(t)
	md5 := "55555555555555555555555555555555"

	rec := sendRequest(t, handler, http.MethodGet, "/info/"+md5, nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected HTTP 404, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHTTP_CreateThreat_InvalidData(t *testing.T) {
	handler, _ := setupTestAPI(t)

	rec := sendRequest(t, handler, http.MethodPost, "/info", map[string]string{
		"md5":  "invalid-md5",
		"name": "Invalid.Threat",
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected HTTP 400, got %d: %s", rec.Code, rec.Body.String())
	}
}