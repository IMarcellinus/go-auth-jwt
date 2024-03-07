package controllers

import (
	"log"

	"strconv"
	"time"

	"github.com/IMarcellinus/go-auth-jwt/database"
	"github.com/IMarcellinus/go-auth-jwt/helper"
	"github.com/IMarcellinus/go-auth-jwt/models"
	"github.com/dgrijalva/jwt-go"
	"github.com/gofiber/fiber/v2"
	"golang.org/x/crypto/bcrypt"
)

const SecretKey = "secret"

type formData struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func Hello(c *fiber.Ctx) error {
	return c.SendString("Hello")
}

func Login(c *fiber.Ctx) error {
	returnObject := fiber.Map{
		"status": "Ok",
		"msg":    "Something went wrong.",
	}

	// Check user for the given credentials

	var formData formData

	// Parse JSON request body
	if err := c.BodyParser(&formData); err != nil {
		log.Println("Error in json binding.")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status": "Error",
			"msg":    "Invalid JSON format",
		})
	}

	// Add formdata to model
	user := new(models.User)
	// var user model.User

	database.DB.First(&user, "username = ?", formData.Username)

	if user.ID == 0 {
		returnObject["msg"] = "User not found."
		returnObject["status"] = "Error."
		return c.Status(fiber.StatusBadRequest).JSON(returnObject)
	}

	err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(formData.Password))

	if err != nil {
		log.Println("Invalid Password.")
		returnObject["msg"] = "Invalid Password."
		returnObject["status"] = "Error."
		return c.Status(fiber.StatusUnauthorized).JSON(returnObject)
	}

	claims := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.StandardClaims{
		Issuer:    strconv.Itoa(int(user.ID)),
		ExpiresAt: time.Now().Add(time.Hour * 24).Unix(), //1 day
	})

	token, err := claims.SignedString([]byte(SecretKey))

	if err != nil {
		c.Status(fiber.StatusInternalServerError)
		return c.JSON(fiber.Map{
			"message": "could not login",
		})
	}

	cookie := fiber.Cookie{
		Name:     "jwt",
		Value:    token,
		Expires:  time.Now().Add(time.Hour * 24),
		HTTPOnly: true,
	}

	c.Cookie(&cookie)

	returnObject["token"] = token
	returnObject["user"] = user
	returnObject["msg"] = "Success Login."
	returnObject["status"] = "Ok."

	c.Status(200)
	return c.JSON(returnObject)
}

func Register(c *fiber.Ctx) error {
	returnObject := fiber.Map{
		"status": "Ok",
	}

	// Collect form data
	var formData formData

	// Parse JSON request body
	if err := c.BodyParser(&formData); err != nil {
		log.Println("Error in json binding.")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status": "Error",
			"msg":    "Invalid JSON format",
		})
	}

	// Validate input
	if formData.Username == "" || formData.Password == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status": "Error",
			"msg":    "Username and password cannot be empty",
		})
	}

	// Check if the username already exists
	existingUser := models.User{}
	if err := database.DB.Where("username = ?", formData.Username).First(&existingUser).Error; err == nil {
		// Username already exists
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status": "Error",
			"msg":    "Account already exists",
		})
	}

	// Add formdata to model
	user := new(models.User)

	user.Username = formData.Username
	user.Password = helper.HashPassword(formData.Password)

	result := database.DB.Create(&user)

	if result.Error != nil {
		log.Println(result.Error)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status": "Error",
			"msg":    "Failed to create user",
		})
	}

	returnObject["data"] = user
	returnObject["msg"] = "Register Successfully"

	// Return success response
	return c.Status(fiber.StatusOK).JSON(returnObject)

}

func User(c *fiber.Ctx) error {
	cookie := c.Cookies("jwt")

	token, err := jwt.ParseWithClaims(cookie, &jwt.StandardClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(SecretKey), nil
	})

	if err != nil {
		c.Status(fiber.StatusUnauthorized)
		return c.JSON(fiber.Map{
			"message": "unauthenticated",
		})
	}

	claims := token.Claims.(*jwt.StandardClaims)

	var user models.User

	database.DB.Where("id = ?", claims.Issuer).First(&user)

	return c.JSON(user)
}

func Logout(c *fiber.Ctx) error {
	cookie := fiber.Cookie{
		Name:     "jwt",
		Value:    "",
		Expires:  time.Now().Add(-time.Hour),
		HTTPOnly: true,
	}

	c.Cookie(&cookie)

	return c.JSON(fiber.Map{
		"message": "success logout",
	})
}
