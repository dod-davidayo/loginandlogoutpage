package database

import (
	"log"

	"fiber-auth/models"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

var DB *gorm.DB

func Connect() {
	db, err := gorm.Open(sqlite.Open("app.db"), &gorm.Config{})
	if err != nil {
		log.Fatal("failed to connect to database: ", err)
	}

	if err := db.AutoMigrate(&models.User{}); err != nil {
		log.Fatal("failed to migrate: ", err)
	}

	DB = db
}