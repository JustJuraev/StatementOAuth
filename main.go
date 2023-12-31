package main

import (
	"bytes"
	"context"
	"crypto/md5"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"net/http"

	_ "github.com/lib/pq"
	"github.com/redis/go-redis/v9"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

type User struct {
	Id       int    `json:"id"`
	Login    string `json:"login"`
	Password string `json:"password"`
	Token    string `json:"token"`
	Name     string `json:"name"`
	LastName string `json:"lastname"`
	Role     int
	OrgId    int
}

type UserGoogleInfo struct {
	Id         int    `json:"id"`
	Email      string `json:"email"`
	Name       string `json:"name"`
	GivenName  string `json:"given_name"`
	FamilyName string `json:"family_name"`
}

type RedirectURLs struct {
	Id        int
	Cliend_id string
	RedirectU string
}

var users = map[string]int{}
var postusers = []User{}

func Login(page http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFiles("html_files/login.html")
	if err != nil {
		panic(err)
	}
	cliend_id := r.URL.Query().Get("cliend_id")
	//	fmt.Println(cliend_id)

	connStr := "user=postgres password=123456 dbname=mygovdb sslmode=disable"
	db, err := sql.Open("postgres", connStr)

	if err != nil {
		fmt.Println(err)
	}

	defer db.Close()

	if cliend_id != "" {
		res := db.QueryRow("SELECT * FROM public.redirecturls WHERE cliend_id = $1", cliend_id)
		rdu := RedirectURLs{}
		err3 := res.Scan(&rdu.Id, &rdu.Cliend_id, &rdu.RedirectU)
		if err3 != nil {
			fmt.Println(err3)
		}
		//str := rdu.RedirectU
		tmpl.ExecuteTemplate(page, "login", rdu.RedirectU)
	} else {
		tmpl.ExecuteTemplate(page, "login", nil)
	}

}

func LoginPost(page http.ResponseWriter, r *http.Request) {

	connStr := "user=postgres password=123456 dbname=mygovdb sslmode=disable"
	db, err := sql.Open("postgres", connStr)

	if err != nil {
		fmt.Println(err)
	}

	defer db.Close()

	login := r.FormValue("login")
	password := r.FormValue("password")
	redirectu := r.FormValue("redirectu")
	hash := md5.Sum([]byte(password))
	hashedPass := hex.EncodeToString(hash[:])

	token := login + password
	hashToken := md5.Sum([]byte(token))
	hashedToken := hex.EncodeToString(hashToken[:])

	res := db.QueryRow("SELECT * FROM public.users WHERE login = $1 AND password = $2", login, hashedPass)
	user := User{}
	err = res.Scan(&user.Id, &user.Login, &user.Password, &user.Name, &user.LastName, &user.Role, &user.OrgId)

	if login == "" || password == "" {
		tmpl, err2 := template.ParseFiles("html_files/login.html")
		if err2 != nil {
			panic(err2)
		}
		message := "поле логина или пароля не может быть пустым"
		tmpl.ExecuteTemplate(page, "login", message)
	}

	if user.Id != 0 && redirectu != "" {

		u := User{
			Id:       user.Id,
			Login:    user.Login,
			Name:     user.Name,
			LastName: user.LastName,
			Password: user.Password,
			Token:    hashedToken,
			Role:     user.Role,
			OrgId:    user.OrgId,
		}

		jb, errr := json.Marshal(&u)

		if errr != nil {
			panic(errr)
		}

		req2, err4 := http.NewRequest("POST", redirectu, bytes.NewBuffer(jb))
		req2.Header.Set("Content-Type", "application/json")
		if err4 != nil {
			panic(err4)
		}
		cli2 := &http.Client{}
		re2, err5 := cli2.Do(req2)
		if err5 != nil {
			panic(err5)
		}
		defer re2.Body.Close()

		http.Redirect(page, r, redirectu, http.StatusSeeOther)
	}
}

func RegisterPage(page http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFiles("html_files/register.html")
	if err != nil {
		panic(err)
	}
	tmpl.ExecuteTemplate(page, "register", nil)
}

func RegisterCheck(page http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	lastname := r.FormValue("lastname")
	login := r.FormValue("login")
	password := r.FormValue("password")
	confirmpassword := r.FormValue("confirmpassword")

	if login == "" || password == "" || confirmpassword == "" || name == "" {
		tmpl, err := template.ParseFiles("html_files/register.html")
		if err != nil {
			panic(err)
		}
		message := "все поля должны быть заполнены!"
		tmpl.ExecuteTemplate(page, "register", message)
		return
	}

	if password != confirmpassword {
		tmpl, err := template.ParseFiles("html_files/register.html")
		if err != nil {
			panic(err)
		}
		message := "пароли не совпадают"
		tmpl.ExecuteTemplate(page, "register", message)
		return
	}

	hash := md5.Sum([]byte(password))
	hashedPass := hex.EncodeToString(hash[:])

	connStr := "user=postgres password=123456 dbname=mygovdb sslmode=disable"
	db, err := sql.Open("postgres", connStr)

	if err != nil {
		panic(err)
	}

	defer db.Close()

	_, err = db.Exec("INSERT INTO public.users (name, lastname, login, password, role) VALUES ($1, $2, $3, $4, $5)", name, lastname, login, hashedPass, 3)

	http.Redirect(page, r, "/", http.StatusSeeOther)
}

var (
	googleOAuthConfig = &oauth2.Config{
		RedirectURL:  "http://localhost:8081/index2",
		ClientID:     "729735064343-pj5ja0brmhqlsarb4u6cmfb1eoi21lfd.apps.googleusercontent.com",
		ClientSecret: "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",
		Scopes:       []string{"https://www.googleapis.com/auth/userinfo.email", "https://www.googleapis.com/auth/userinfo.profile"},
		Endpoint:     google.Endpoint,
	}

	randomState = "random"
)

func handleGoogleLogin(w http.ResponseWriter, r *http.Request) {
	url := googleOAuthConfig.AuthCodeURL(randomState)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func HandleIndex(page http.ResponseWriter, r *http.Request) {
	if r.FormValue("state") != randomState {
		fmt.Println("state in not valid")
		return
	}

	token, err := googleOAuthConfig.Exchange(oauth2.NoContext, r.FormValue("code"))
	if err != nil {
		panic(err)
	}

	resp, err2 := http.Get("https://www.googleapis.com/oauth2/v2/userinfo?access_token=" + token.AccessToken)
	if err2 != nil {
		panic(err2)
	}

	defer resp.Body.Close()
	cont, err3 := ioutil.ReadAll(resp.Body)
	if err3 != nil {
		panic(err3)
	}

	deserializedUser := UserGoogleInfo{}
	err = json.Unmarshal([]byte(string(cont)), &deserializedUser)

	connStr := "user=postgres password=123456 dbname=mygovdb sslmode=disable"
	db, err := sql.Open("postgres", connStr)

	if err != nil {
		panic(err)
	}

	defer db.Close()

	res := db.QueryRow("SELECT * FROM public.users WHERE login = $1", deserializedUser.Name)
	user := User{}
	err = res.Scan(&user.Id, &user.Login, &user.Password, &user.Name, &user.LastName, &user.Role, &user.OrgId)
	if err != nil {
		fmt.Println(err)
	}

	client := redis.NewClient(&redis.Options{
		Addr:     "localhost:2222",
		Password: "", // no password set
		DB:       0,  // use default DB
	})

	token2 := user.Login + user.Password
	hashToken := md5.Sum([]byte(token2))
	hashedToken := hex.EncodeToString(hashToken[:])
	fmt.Println(user.Login)
	if user.Login != "" {
		u := User{
			Id:       user.Id,
			Login:    user.Login,
			Name:     user.Name,
			LastName: user.LastName,
			Password: user.Password,
			Token:    hashedToken,
		}
		users[u.Token] = u.Id
		ctx := context.Background()
		for k, v := range users {
			err := client.HSet(ctx, "user-session:1234", k, v).Err()
			if err != nil {
				panic(err)
			}
		}
		jb, errr := json.Marshal(&u)

		if errr != nil {
			panic(errr)
		}
		//fmt.Println(bytes.NewBuffer(jb))
		req2, err4 := http.NewRequest("POST", "http://localhost:8080/index", bytes.NewBuffer(jb))
		req2.Header.Set("Content-Type", "application/json")
		if err4 != nil {
			panic(err4)
		}
		cli2 := &http.Client{}
		re2, err5 := cli2.Do(req2)
		if err5 != nil {
			panic(err5)
		}
		defer re2.Body.Close()

		http.Redirect(page, r, "http://localhost:8080/index", http.StatusSeeOther)
	} else {
		tmpl, err := template.ParseFiles("html_files/register.html")
		if err != nil {
			panic(err)
		}
		tmpl.ExecuteTemplate(page, "register", deserializedUser)
	}
}

func main() {
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("./static/"))))
	http.HandleFunc("/", Login)
	http.HandleFunc("/login_check", LoginPost)

	http.HandleFunc("/logingoogle", handleGoogleLogin)
	http.HandleFunc("/index2", HandleIndex)
	http.HandleFunc("/register", RegisterPage)
	http.HandleFunc("/register_check", RegisterCheck)
	http.ListenAndServe(":8081", nil)
}
