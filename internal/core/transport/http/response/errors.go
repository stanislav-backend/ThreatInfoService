package core_http_response
 

type ErrorResponse struct{
	Message string `json:"message"`
	Details string `json:"details"`
}