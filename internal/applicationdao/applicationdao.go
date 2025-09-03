package applicationdao

import (
	"errors"
	"fmt"

	"github.com/NH-Homelab/auth-service/internal/database"
	"github.com/NH-Homelab/auth-service/internal/models"
)

var (
	ErrQueryApplication = errors.New("failed to query application from db")
	ErrScanApplication  = errors.New("failed to scan application from db response")
)

const (
	getApplicationBySubdomainQuery = "SELECT id, name, subdomain FROM applications WHERE subdomain = $1;"
	getGroupsByApplicationQuery    = "SELECT group_id FROM group_permissions WHERE application_id = $1;"
)

func GetApplicationBySubdomain(db database.DatabaseConnection, subdomain string) (models.Application, error) {
	
	
	res, err := db.Query(getApplicationBySubdomainQuery, subdomain)
	if err != nil {
		return models.Application{}, fmt.Errorf("getApplicationsBySubdomain: %w -- %v", ErrQueryApplication, err)
	}
	defer res.Close()

	if ok := res.Next(); !ok {
		return models.Application{}, fmt.Errorf("getApplicationsBySubdomain: %w -- no rows found", ErrScanApplication)
	}

	var app models.Application
	if err := res.Scan(&app.ID, &app.Name, &app.Subdomain); err != nil {
		return models.Application{}, fmt.Errorf("getApplicationsBySubdomain: %w -- %v", ErrScanApplication, err)
	}

	// Fetch Groups
	groups, err := getGroupsByApplication(db, app.ID)
	if err != nil {
		return models.Application{}, fmt.Errorf("getApplicationsBySubdomain: %w -- %v", ErrQueryApplication, err)
	}
	app.Groups = groups

	return app, nil
}

func getGroupsByApplication(db database.DatabaseConnection, appid string) ([]int, error) {
	res, err := db.Query(getGroupsByApplicationQuery, appid)
	if err != nil {
		return nil, fmt.Errorf("getGroupsByApplication: %w -- %v", ErrQueryApplication, err)
	}
	defer res.Close()

	var groupIDs []int
	for res.Next() {
		var groupID int
		if err := res.Scan(&groupID); err != nil {
			return nil, fmt.Errorf("getGroupsByApplication: %w -- %v", ErrScanApplication, err)
		}
		groupIDs = append(groupIDs, groupID)
	}

	return groupIDs, nil
}
