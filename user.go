package mangoauth

import (
	. "github.com/sunfmin/mango"
)

type User interface {
	IdForSession() string
}

type UserProvider interface {
	LoadUser(id string) (u User, err error)
}

var sessionKey string

func Logout(env Env) (status Status, headers Headers, body Body) {

	s := env.Session()
	delete(s, sessionKey)
	return Redirect(301, uprovider.SuccessURL(env))
}
