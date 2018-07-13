package router

import (
    "github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/render"
	"net/http"
	"ideal/api"
	"log"
)
func rootHandler(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "./static/templates/home.html")
}

func loginPageHandler(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "./static/templates/login.html")
}

func logoutPageHandler(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "./static/templates/logout.html")
}
func registerPageHandler(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "./static/templates/register.html")
}
func InitRouter() *chi.Mux {
    r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.URLFormat)
	r.Use(render.SetContentType(render.ContentTypeJSON))

	r.Route("/api", func(r chi.Router) {
		r.Post("/login", api.LoginHandler)
		r.Post("/logout", api.LogoutHandler)
		r.Get("/session", api.SessionHandler)
		r.Get("/secret", api.SecretHandler)
		r.Post("/register", api.RegisterHandler)
	})

	r.Get("/", rootHandler)
	r.Get("/login", loginPageHandler)
	r.Get("/logout", logoutPageHandler)
	r.Get("/register", registerPageHandler)
	return r
}

func init(){
	log.Print("router.go loaded.")
}