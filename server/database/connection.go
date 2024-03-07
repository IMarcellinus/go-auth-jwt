package database

import (
	"log"

	"github.com/IMarcellinus/go-auth-jwt/models"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var DB *gorm.DB

func Connect() {
	connection, err := gorm.Open(mysql.Open("root:root123@/perpustakaan"), &gorm.Config{Logger: logger.Default.LogMode(logger.Error)})

	if err != nil {
		panic("gagal konek database")
	}

	log.Println("Connection Successfull.")

	connection.AutoMigrate(&models.User{})

	DB = connection
}
