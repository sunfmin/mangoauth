package mangoauth

import (
	"encoding/json"
	"fmt"
	. "github.com/paulbellamy/mango"
	"github.com/sunfmin/goauth"
	"github.com/sunfmin/integrationtest"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
)

var storageImpl = make(map[string]interface{})

type user struct {
	id string
}

func (u *user) IdForSession() string {
	return u.id
}

type urlp struct{}
type userp struct{}
type st struct{}

func (up *urlp) LoginURL(env Env) string {
	return "/login"
}

func (up *urlp) OAuthReadyURL(env Env) string {
	return "/oauthready"
}

func (up *urlp) SuccessURL(env Env) string {
	return "/profile"
}

func (up *userp) LoadUser(id string) (u User, err error) {
	u, _ = storageImpl["User:"+id].(User)
	return
}

func (up *st) LoadTemporaryCredential(oauthToken string) (tc *goauth.TemporaryCredential, err error) {
	tc, _ = storageImpl["TemporaryCredential:"+tc.OAuthToken].(*goauth.TemporaryCredential)
	return
}

func (up *st) SaveTemporaryCredential(tc *goauth.TemporaryCredential) (err error) {
	storageImpl["TemporaryCredential:"+tc.OAuthToken] = tc
	return
}

func (up *st) SaveTokenCredential(env Env, tc *goauth.TokenCredential) (err error) {
	storageImpl["Token:"+tc.UserId] = tc
	storageImpl["User:"+tc.UserId] = &user{tc.UserId}
	return
}

func (up *st) UserByToken(env Env, tc *goauth.TokenCredential) (u User) {
	u = storageImpl["User:"+tc.UserId].(*user)
	return
}

func (up *st) OAuthClient(env Env) (c *goauth.Client) {
	cc := getClientKeyMap()

	c = goauth.NewClient(cc["weibo"].Key, cc["weibo"].Secret, &goauth.Configuration{
		RequestTokenURL:        "http://api.t.sina.com.cn/oauth/request_token",
		AccessTokenURL:         "http://api.t.sina.com.cn/oauth/access_token",
		AuthorizeURL:           "http://api.t.sina.com.cn/oauth/authorize",
		UseAuthorizationHeader: true,
		UseBodyHash:            true,
		UserIdKey:              "user_id",
	})
	return
}

func getClientKeyMap() (cc map[string]*goauth.ClientCredential) {
	f, err := os.Open(os.Getenv("HOME") + "/.goauth.json")
	if err != nil {
		panic(err)
	}
	bs, _ := ioutil.ReadAll(f)

	json.Unmarshal(bs, &cc)

	return cc
}

func ExampleSetupOAuth() {
	SetupOAuth("userkey", new(urlp), new(st), new(userp))

	s := new(Stack)
	session := Sessions("123123123213", "mangoauth", &CookieOptions{Path: "/", MaxAge: 3600 * 24 * 7})
	s.Middleware(session)

	m := http.NewServeMux()
	m.HandleFunc("/login", s.HandlerFunc(OAuthLogin))
	m.HandleFunc("/logout", s.HandlerFunc(Logout))
	m.HandleFunc("/oauthready", s.HandlerFunc(OAuthReady))

	restrictedStack := new(Stack)
	restrictedStack.Middleware(session, MustLoggedIn)

	profile := func(env Env) (status Status, headers Headers, body Body) {
		return 200, Headers{}, Body("Hi, this is my profile")
	}

	m.HandleFunc("/profile", restrictedStack.HandlerFunc(profile))

	fakelogin := func(env Env) (status Status, headers Headers, body Body) {
		s := env.Session()
		s["userkey"] = "user1"
		return 200, Headers{}, Body("")
	}

	m.HandleFunc("/fakelogin", s.HandlerFunc(fakelogin))

	ts := httptest.NewServer(m)
	defer ts.Close()

	is := integrationtest.NewSession()

	is.Get(ts.URL + "/login")
	for k, _ := range storageImpl {
		fmt.Printf("have TemporaryCredential stored: %+v\n", strings.Contains(k, "TemporaryCredential"))
	}

	// logged in can access profile
	is.Get(ts.URL + "/fakelogin")
	storageImpl["User:user1"] = &user{"user1"}
	r, _ := is.Get(ts.URL + "/profile")
	b, _ := ioutil.ReadAll(r.Body)
	if strings.Contains(string(b), "Hi, this is my profile") {
		fmt.Println("can access profile when logged in")
	}

	// didn't log in can not access profile
	delete(storageImpl, "User:user1")
	r, _ = is.Get(ts.URL + "/profile")
	b, _ = ioutil.ReadAll(r.Body)
	if !strings.Contains(string(b), "Hi, this is my profile") {
		fmt.Println("yes, can not access profile if not logged in")
	}
	//Output:
	//have TemporaryCredential stored: true
	//can access profile when logged in
	//yes, can not access profile if not logged in
}
