package main

import (
	"os"
	"log"
	"fmt"
	"net/http"

	"golang.org/x/oauth2"
	"github.com/joho/godotenv"
	"github.com/coreos/go-oidc"
	"github.com/google/uuid"
)

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal(err)
	}

	CLIENT_ID := os.Getenv("CLIENT_ID")
	CLIENT_SECRET := os.Getenv("CLIENT_SECRET")
	REDIRECT_URL := os.Getenv("REDIRECT_URL")

	issuer := "https://accounts.google.com"

	//	セッションにIDを保存するべきですが、セッションについて知識不足のため、できていません。
	var uu string	

	http.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request){
		provider, err := oidc.NewProvider(r.Context(), issuer)

		if err != nil {
			log.Fatal(err)
		}

		config := oauth2.Config{
			ClientID:		CLIENT_ID,
			ClientSecret:	CLIENT_SECRET,
			Endpoint:		provider.Endpoint(),
			RedirectURL:	REDIRECT_URL,
			Scopes:			[]string{oidc.ScopeOpenID},
		}
		
		u, err := uuid.NewRandom()
		if err != nil {
			fmt.Println(err)
			return 
		}
		uu = u.String()

		authURL := config.AuthCodeURL(uu)
		http.Redirect(w, r, authURL, http.StatusFound)
	})

	http.HandleFunc("/auth/google/callback", func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		
		provider, err := oidc.NewProvider(ctx, issuer)

		if err != nil {
			log.Fatal(err)
		}

		config := oauth2.Config{
			ClientID:		CLIENT_ID,
			ClientSecret:	CLIENT_SECRET,
			Endpoint:		provider.Endpoint(),
			RedirectURL:	REDIRECT_URL,
			Scopes:			[]string{oidc.ScopeOpenID},
		}

		state := r.URL.Query().Get("state")
		fmt.Println(state)
		if state != uu {
			http.Error(w, "This request is not allowed.", http.StatusForbidden)
			return 
		} else {
			fmt.Println("ok")
		}

		code := r.URL.Query().Get("code")
		oauth2Token, err := config.Exchange(ctx, code)
		if err != nil {
			http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
			return
		}

		rawIDToken, ok := oauth2Token.Extra("id_token").(string)
		if !ok {
			http.Error(w, "missing token", http.StatusInternalServerError)
			return
		}

		oidcConfig := &oidc.Config {
			ClientID:		CLIENT_ID,
		}

		verifier := provider.Verifier(oidcConfig)

		//	IDトークンの正当性の検証
		idToken, err := verifier.Verify(ctx, rawIDToken)
		if err != nil {
			http.Error(w, "Failed to verify ID Token: "+err.Error(), http.StatusInternalServerError)
			return 
		}

		idTokenClaims := map[string]interface{}{}
		if err := idToken.Claims(&idTokenClaims); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return 
		}

		fmt.Printf("%#v", idTokenClaims)

		fmt.Fprintf(w, "認証成功")
	})

	http.ListenAndServe(":3000", nil)
}