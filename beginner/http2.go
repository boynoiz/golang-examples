package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
)

type User struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
	Age  int    `json:"age"`
}

type UserService struct {
	apiBaseURL string
}

func NewUserService() *UserService {
	apiBaseURL := os.Getenv("API_BASE_URL")
	if apiBaseURL == "" {
		apiBaseURL = "http://localhost"
	}
	return &UserService{apiBaseURL: apiBaseURL}
}

func (s *UserService) doRequest(method string, url string, body interface{}) ([]byte, error) {
	// Convert the body into a byte array
	jsonData, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	reader := bytes.NewBuffer(jsonData)

	req, err := http.NewRequest(method, url, reader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Fatalf("status code error: %d %s", resp.StatusCode, resp.Status)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return data, nil
}

func (s *UserService) GetUser(userID int) {
	userURL := fmt.Sprintf("%s/users/%d", s.apiBaseURL, userID)
	data, err := s.doRequest("GET", userURL, nil)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(data)
}

func (s *UserService) CreateUser() {
	u := User{Name: "John Doe", Age: 42}
	createURL := fmt.Sprintf("%s/users/create", s.apiBaseURL)
	data, err := s.doRequest("POST", createURL, u)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(data)
}

func (s *UserService) UpdateUser(userID int) {
	u := User{ID: userID, Name: "Jane Doe", Age: 43}
	updateURL := fmt.Sprintf("%s/users/%d", s.apiBaseURL, userID)
	data, err := s.doRequest("PUT", updateURL, u)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(data)
}

func (s *UserService) DeleteUser(userID int) {
	deleteURL := fmt.Sprintf("%s/users/%d", s.apiBaseURL, userID)
	data, err := s.doRequest("DELETE", deleteURL, nil)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(data)
}

func main() {
	service := NewUserService()
	service.CreateUser()
	service.GetUser(1)
	service.UpdateUser(1)
	service.DeleteUser(1)
}
