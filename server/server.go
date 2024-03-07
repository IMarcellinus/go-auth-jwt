package main

import (
	"github.com/IMarcellinus/go-auth-jwt/database"
	"github.com/IMarcellinus/go-auth-jwt/routes"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
)

func main() {
	database.Connect()

	app := fiber.New()

	app.Use(cors.New(cors.Config{
		AllowHeaders: "Origin, Content-Type, Accept",
		AllowOrigins: "*",
	}))

	routes.Setup(app)

	app.Listen(":8000")
}
