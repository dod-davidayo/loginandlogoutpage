package middleware

import (
	"os"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
)

type CurrentUser struct {
	ID    uint
	Name  string
	Email string
}

// Identify runs on EVERY request. It never blocks; it only works out
// who the user is (if anyone) and stores it in c.Locals("User").
func Identify(c *fiber.Ctx) error {
	tokenStr := c.Cookies("token")
	if tokenStr == "" {
		if h := c.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
			tokenStr = strings.TrimPrefix(h, "Bearer ")
		}
	}
	if tokenStr == "" {
		return c.Next()
	}

	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("JWT_SECRET")), nil
	}, jwt.WithValidMethods([]string{"HS256"}))
	if err != nil || !token.Valid {
		return c.Next()
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return c.Next()
	}

	id, _ := claims["sub"].(float64) // JSON numbers decode as float64
	name, _ := claims["name"].(string)
	email, _ := claims["email"].(string)
	if id == 0 {
		return c.Next()
	}

	c.Locals("User", &CurrentUser{ID: uint(id), Name: name, Email: email})
	return c.Next()
}

// RequireAuth blocks anyone Identify didn't recognise.
func RequireAuth(c *fiber.Ctx) error {
	if c.Locals("User") != nil {
		return c.Next()
	}
	// API clients get JSON, browsers get redirected
	if c.Get("Authorization") != "" || strings.HasPrefix(c.Path(), "/api/") {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized"})
	}
	return c.Redirect("/login")
}

// RedirectIfLoggedIn keeps logged-in users off login/register.
func RedirectIfLoggedIn(c *fiber.Ctx) error {
	if c.Locals("User") != nil {
		return c.Redirect("/dashboard")
	}
	return c.Next()
}