package models

type Application struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Subdomain string `json:"subdomain"`
	Groups    []int  `json:"groups"`
}
