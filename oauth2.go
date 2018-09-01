package oauth2

import (
	"context"
	"encoding/json"
	"errors"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/facebook"
	"golang.org/x/oauth2/github"
	"golang.org/x/oauth2/google"
	"golang.org/x/oauth2/odnoklassniki"
	"golang.org/x/oauth2/vk"
	"net/http"
	"os"
	"strings"
	"time"
)

type User struct {
	Name    string
	Email   string
	Picture string
}

type Config struct {
	DataURL string
	oauth2.Config
}

var httpClient *http.Client

var AuthConfigs = make(map[string]*Config)

func init() {
	// TODO add timeout settings as env
	httpClient = &http.Client{Timeout: 5 * time.Second}

	endpointNames := lookupEnv("oauth2.endpoint-names", "")

	if len(endpointNames) > 0 {
		split := strings.Split(endpointNames, ",")
		for _, endpointName := range split {
			config, err := NewConfig(endpointName)

			if err != nil {
				panic(err)
			}

			AuthConfigs[endpointName] = config
		}
	}
}

func lookupEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

func NewConfig(endpointName string) (*Config, error) {
	var endpoint oauth2.Endpoint

	switch endpointName {
	case "google":
		endpoint = google.Endpoint
	case "facebook":
		endpoint = facebook.Endpoint
	case "odnoklassniki":
		endpoint = odnoklassniki.Endpoint
	case "vk":
		endpoint = vk.Endpoint
	case "github":
		endpoint = github.Endpoint
	default:
		return nil, errors.New("Init unknown OAuth2.0 Endpoint : " + endpointName)
	}

	scopes := lookupEnv("oauth2."+endpointName+".scopes", "openid email")

	return &Config{
		DataURL: os.Getenv("oauth2." + endpointName + ".data-url"),
		Config: oauth2.Config{
			RedirectURL:  os.Getenv("oauth2.redirect-uri"),
			ClientID:     os.Getenv("oauth2." + endpointName + ".client-id"),
			ClientSecret: os.Getenv("oauth2." + endpointName + ".secret"),
			Endpoint:     endpoint,
			Scopes:       strings.Split(scopes, ",")}}, nil
}

func (cfg *Config) GetUser(endpointName string, code string) (*User, error) {
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, httpClient)
	token, err := cfg.Exchange(ctx, code)

	if err != nil {
		return nil, err
	}

	client := cfg.Client(ctx, token)
	response, err := client.Get(cfg.DataURL + token.AccessToken)

	if err != nil {
		return nil, err
	}

	defer response.Body.Close()

	var data map[string]interface{}

	err = json.NewDecoder(response.Body).Decode(&data)

	if err != nil {
		return nil, err
	}

	switch endpointName {
	case "google":
		return newGoogleUser(data), nil
	case "facebook":
		return newFacebookUser(data), nil
	case "github":
		return newGithubUser(data), nil
	default:
		return nil, errors.New("UserInfo unknown OAuth2.0 Endpoint : " + endpointName)
	}
}

func newGoogleUser(source map[string]interface{}) *User {
	return &User{
		Name:    source["name"].(string),
		Email:   source["email"].(string),
		Picture: source["picture"].(string)}
}

func newFacebookUser(source map[string]interface{}) *User {
	picture := source["picture"].(map[string]interface{})
	data := picture["data"].(map[string]interface{})

	return &User{
		Name:    source["name"].(string),
		Email:   source["email"].(string),
		Picture: data["url"].(string)}
}

func newGithubUser(source map[string]interface{}) *User {
	// TODO fix null values
	return &User{
		Name:    source["login"].(string),
		Picture: source["avatar_url"].(string)}
}
