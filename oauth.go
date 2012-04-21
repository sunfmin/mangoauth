package mangoauth

import (
	. "github.com/paulbellamy/mango"
	"github.com/sunfmin/goauth"
	"log"
)

type OAuthCredentialStorage interface {
	LoadTemporaryCredential(oauthToken string) (tc *goauth.TemporaryCredential, err error)
	SaveTemporaryCredential(tc *goauth.TemporaryCredential) (err error)
	SaveTokenCredential(env Env, tc *goauth.TokenCredential) (err error)
	UserByToken(env Env, tc *goauth.TokenCredential) (u User)
	OAuthClient(env Env) (c *goauth.Client)
}

type URLProvider interface {
	LoginURL(env Env) string
	OAuthReadyURL(env Env) string
	SuccessURL(env Env) string
}

var uprovider URLProvider
var userprovider UserProvider
var storage OAuthCredentialStorage

func SetupOAuth(loggedInUserSessionKey string, p URLProvider, cs OAuthCredentialStorage, up UserProvider) {
	uprovider = p
	storage = cs
	sessionKey = loggedInUserSessionKey
	userprovider = up
}

func OAuthLogin(env Env) (status Status, headers Headers, body Body) {
	client := storage.OAuthClient(env)
	if client == nil {
		status = 404
		return
	}

	readyURL := uprovider.OAuthReadyURL(env)

	url, tc, err := client.GetAuthorizeURL(readyURL)
	if err != nil {
		status = 404
		log.Printf("Error when OAuth with %s", err)
		return
	}
	storage.SaveTemporaryCredential(tc)

	return Redirect(302, url)
}

func OAuthReady(env Env) (status Status, headers Headers, body Body) {
	r := env.Request()
	client := storage.OAuthClient(env)
	if client == nil {
		status = 404
		return
	}
	oauthToken := r.URL.Query().Get("oauth_token")
	oauthVerifier := r.URL.Query().Get("oauth_verifier")

	if oauthToken == "" || oauthVerifier == "" {
		log.Printf("OAuth token or OAuth verifier empty")
		status = 404
		return
	}

	tempc, err := storage.LoadTemporaryCredential(oauthToken)
	if err != nil || tempc == nil {
		log.Printf("Loading OAuth temporary credential wrong %s\n", err)
		status = 404
		return
	}

	tempc.OAuthVerifier = oauthVerifier
	tc, err := client.GetTokenCredential(tempc)

	if err != nil {
		log.Printf("Error when get token credential: %s", err)
		status = 404
		return
	}
	storage.SaveTokenCredential(env, tc)

	u := storage.UserByToken(env, tc)
	s := env.Session()
	s[sessionKey] = u.IdForSession()

	return Redirect(302, uprovider.SuccessURL(env))
}
