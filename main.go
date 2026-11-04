package main

import (
	"log"
	"time"

	"fiber-auth/database"
	"fiber-auth/handlers"
	"fiber-auth/middleware"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/limiter"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/gofiber/template/html/v2"
	"github.com/joho/godotenv"
)

func main() {
	if err := godotenv.Load(); err != nil {
		log.Println("no .env file found, using system environment")
	}

	database.Connect()

	engine := html.New("./views", ".html")
	app := fiber.New(fiber.Config{Views: engine})

	app.Use(recover.New())
	app.Use(logger.New())
	app.Static("/", "./public")

	// Limit brute-force attempts: 5 per minute per IP on auth POSTs
	authLimiter := limiter.New(limiter.Config{
		Max:        5,
		Expiration: 1 * time.Minute,
		LimitReached: func(c *fiber.Ctx) error {
			return c.Status(fiber.StatusTooManyRequests).SendString("Too many attempts, try again in a minute")
		},
	})

	app.Get("/", func(c *fiber.Ctx) error { return c.Redirect("/login") })

	// Public routes
	app.Get("/register", middleware.RedirectIfLoggedIn, handlers.ShowRegister)
	app.Post("/register", authLimiter, handlers.Register)
	app.Get("/login", middleware.RedirectIfLoggedIn, handlers.ShowLogin)
	app.Post("/login", authLimiter, handlers.Login)

	// Protected routes
	app.Get("/dashboard", middleware.RequireAuth, handlers.Dashboard)
	app.Post("/logout", handlers.Logout)

	log.Fatal(app.Listen(":3000"))
}

