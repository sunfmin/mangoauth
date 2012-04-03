package mangoauth

import (
	. "github.com/sunfmin/mango"
	"log"
)

func MustLoggedIn(env Env, app App) (status Status, headers Headers, body Body) {
	s := env.Session()
	userId := s[sessionKey].(string)
	if userId == "" {
		return Redirect(301, uprovider.LoginURL(env))
	}
	u, err := userprovider.LoadUser(userId)
	if err != nil || u == nil {
		log.Printf("mangoauth: can not load user %v", err)
		return Redirect(301, uprovider.LoginURL(env))
	}
	env[sessionKey] = u
	return app(env)
}

func WithUserLoaded(env Env, app App) (status Status, headers Headers, body Body) {
	s := env.Session()
	userId := s[sessionKey].(string)
	if userId != "" {
		u, err := userprovider.LoadUser(userId)
		if err == nil && u != nil {
			env[sessionKey] = u
		}
	}
	return app(env)
}
