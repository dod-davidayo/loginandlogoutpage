package handlers

import (
	"os"
	"strings"
	"time"

	"fiber-auth/database"
	"fiber-auth/models"

	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"fiber-auth/middleware"
)

var validate = validator.New()

type registerInput struct {
	Name            string `form:"name" validate:"required,min=2"`
	Email           string `form:"email" validate:"required,email"`
	Password        string `form:"password" validate:"required,min=8"`
	ConfirmPassword string `form:"confirm_password" validate:"required,eqfield=Password"`
}

type loginInput struct {
	Email    string `form:"email" validate:"required,email"`
	Password string `form:"password" validate:"required"`
}

// ---------- Registration ----------

func ShowRegister(c *fiber.Ctx) error {
	return c.Render("register", fiber.Map{})
}

func Register(c *fiber.Ctx) error {
	var in registerInput
	if err := c.BodyParser(&in); err != nil {
		return c.Status(fiber.StatusBadRequest).Render("register", fiber.Map{
			"Error": "Invalid form data",
		})
	}

	in.Name = strings.TrimSpace(in.Name)
	in.Email = strings.ToLower(strings.TrimSpace(in.Email))

	if err := validate.Struct(in); err != nil {
		return c.Status(fiber.StatusBadRequest).Render("register", fiber.Map{
			"Error": "Please check your details: name required, valid email, password of at least 8 characters, and matching confirmation.",
			"Name":  in.Name,
			"Email": in.Email,
		})
	}

	// Check if the email is already taken
	var existing models.User
	if err := database.DB.Where("email = ?", in.Email).First(&existing).Error; err == nil {
		return c.Status(fiber.StatusConflict).Render("register", fiber.Map{
			"Error": "An account with this email already exists",
			"Name":  in.Name,
		})
	}

	// Hash the password
	hash, err := bcrypt.GenerateFromPassword([]byte(in.Password), bcrypt.DefaultCost)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).Render("register", fiber.Map{
			"Error": "Something went wrong, please try again",
		})
	}

	user := models.User{Name: in.Name, Email: in.Email, Password: string(hash)}
	if err := database.DB.Create(&user).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).Render("register", fiber.Map{
			"Error": "Could not create account",
		})
	}

	return c.Redirect("/login?registered=1")
}

// ---------- Login ----------

func ShowLogin(c *fiber.Ctx) error {
	return c.Render("login", fiber.Map{
		"Success": c.Query("registered") == "1",
	})
}

func Login(c *fiber.Ctx) error {
	var in loginInput
	if err := c.BodyParser(&in); err != nil {
		return c.Status(fiber.StatusBadRequest).Render("login", fiber.Map{
			"Error": "Invalid form data",
		})
	}

	in.Email = strings.ToLower(strings.TrimSpace(in.Email))

	if err := validate.Struct(in); err != nil {
		return c.Status(fiber.StatusBadRequest).Render("login", fiber.Map{
			"Error": "Enter a valid email and password",
			"Email": in.Email,
		})
	}

	// Same message for "no such user" and "wrong password"
	// so attackers can't discover which emails are registered.
	invalid := func() error {
		return c.Status(fiber.StatusUnauthorized).Render("login", fiber.Map{
			"Error": "Invalid email or password",
			"Email": in.Email,
		})
	}

	var user models.User
	if err := database.DB.Where("email = ?", in.Email).First(&user).Error; err != nil {
		return invalid()
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(in.Password)); err != nil {
		return invalid()
	}

	token, err := createToken(user)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).Render("login", fiber.Map{
			"Error": "Could not log you in, please try again",
		})
	}

	c.Cookie(&fiber.Cookie{
		Name:     "token",
		Value:    token,
		Expires:  time.Now().Add(24 * time.Hour),
		HTTPOnly: true,   // JavaScript can't read it, which blocks token theft via XSS
		Secure:   false,  // set to true in production (HTTPS)
		SameSite: "Lax",  // basic CSRF protection
	})

	return c.Redirect("/dashboard")
}

// ---------- Logout ----------

func Logout(c *fiber.Ctx) error {
	c.Cookie(&fiber.Cookie{
		Name:     "token",
		Value:    "",
		Expires:  time.Now().Add(-time.Hour),
		HTTPOnly: true,
	})
	return c.Redirect("/login")
}

// ---------- Protected page ----------

func Dashboard(c *fiber.Ctx) error {
	userID := c.Locals("userID").(uint)

	var user models.User
	if err := database.DB.First(&user, userID).Error; err != nil {
		return c.Redirect("/login")
	}

	return c.Render("dashboard", fiber.Map{"Name": user.Name, "Email": user.Email})
}

// ---------- Helpers ----------

func createToken(user models.User) (string, error) {
	claims := jwt.MapClaims{
		"sub":   user.ID,
		"name":  user.Name,
		"email": user.Email,
		"exp":   time.Now().Add(24 * time.Hour).Unix(),
		"iat":   time.Now().Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(os.Getenv("JWT_SECRET")))
}