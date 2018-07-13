package api

import (
	"github.com/alexedwards/scs"
	"github.com/alexedwards/scs/stores/mysqlstore"
	"golang.org/x/crypto/bcrypt"
	"net/http"

	"encoding/json"
	_ "fmt"
	"database/sql"
	_ "github.com/go-sql-driver/mysql"
	"log"
	"ideal/config"
)

var (
	Users          = map[string]string{"test": "pw"}
	SessionManager *scs.Manager
	db = config.DB
)

type SessionResponse struct {
	Auth     bool   `json:"Auth"`
	Username string `json:"Username"`
}

type HTTPResponse struct {
	//code	int		`json:"code,omitempty"`
	Errors  string `json:"Errors,omitempty"`
	Message string `json:"Message"`
}

func UserExist(username string) bool{
	var dbusername string
	err := db.QueryRow("SELECT username FROM user_account WHERE username = ?",username).Scan(&dbusername)
	return err != sql.ErrNoRows
}


func EmailUsed(email string) bool {
	var dbemail string
	err := db.QueryRow("SELECT email FROM user_account WHERE email = ?",email).Scan(&dbemail)
	return err != sql.ErrNoRows
}

func SessionHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	session := SessionManager.Load(r)
	username, _ := session.GetString("username")
	auth, _ := session.GetBool("auth")
	json.NewEncoder(w).Encode(&SessionResponse{
		Username: username,
		Auth:     auth,
	})
}
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	session := SessionManager.Load(r)
	auth, err := session.GetBool("auth")
	if auth == true {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(&HTTPResponse{
			Message: "Already logged in.",
		})
		return
	}
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(&HTTPResponse{
			Errors:  err.Error(),
			Message: "Error loading login status.",
		})
		return
	}
	
	username := r.FormValue("username")
	password := r.FormValue("password")
	var dbpassword string
	if username == "" || password == "" {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(&HTTPResponse{
			Message: "Blank fields.",
		})
		return
	}
	
	err = db.QueryRow("SELECT password FROM user_account WHERE username = ?",username).Scan(&dbpassword)
	if err == sql.ErrNoRows {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(&HTTPResponse{
			Message: "User not found.",
		})
		return
	}
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(&HTTPResponse{
			Errors: err.Error(),
			Message: "Database error",
		})
		return
	}
	if err = bcrypt.CompareHashAndPassword([]byte(dbpassword),[]byte(password)); err!=nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(&HTTPResponse{
			Message: "Wrong Password.",
		})
		return
	}
	if err := session.PutBool(w, "auth", true); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(&HTTPResponse{
			Message: "Login unsuccessful.",
		})
		return
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(&HTTPResponse{
		Message: username + " login successful",
	})
	session.PutString(w, "username", username)
}

func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	session := SessionManager.Load(r)
	auth, _ := session.GetBool("auth")
	if auth == true {
		if err := session.PutBool(w, "auth", false); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(&HTTPResponse{
				Errors:  err.Error(),
				Message: "Logout unsuccessful.",
			})
		} else {
			session.Destroy(w)
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(&HTTPResponse{
				Message: "Logout successful",
			})
			return
		}
	} else {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(&HTTPResponse{
			Message: "Not logged in.",
		})
	}
}

func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	session := SessionManager.Load(r)
	auth, err := session.GetBool("auth")
	if auth == true {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(&HTTPResponse{
			Message: "Already logged in.",
		})
		return
	}
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(&HTTPResponse{
			Errors:  err.Error(),
			Message: "Error loading login status.",
		})
		return
	}
	
	username := r.FormValue("username")
	password, _:= bcrypt.GenerateFromPassword([]byte(r.FormValue("password")),10)
	email	 := r.FormValue("email")
	
	if UserExist(username) || EmailUsed(email){
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(&HTTPResponse{
			Message: "User exists.",
		})
		return
	}
	_, err = db.Exec("INSERT INTO user_account (username, password, email) VALUES (?, ?, ?)", username, password, email)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(&HTTPResponse{
			Errors:  err.Error(),
			Message: "Database error.",
		})
		return
	}
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(&HTTPResponse{
		Message: username+" Registration success.",
	})
}
func SecretHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	session := SessionManager.Load(r)
	auth, err := session.GetBool("auth")
	if auth != true {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(&HTTPResponse{
			Message: "Only viewable by logged in users.",
		})
		return
	}
	username, err := session.GetString("username")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(&HTTPResponse{
			Errors:  err.Error(),
			Message: "Error loading login status.",
		})
		return
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(&HTTPResponse{
		Message: "Welcome, " + username,
	})
}

func init() {
	
	SessionManager = scs.NewManager(mysqlstore.New(db, 0))
	log.Print("api.go loaded.")
}
