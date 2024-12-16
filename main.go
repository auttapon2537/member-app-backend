package main

import (
	"database/sql"
	"log"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

var jwtSecretKey = []byte("your-secret-key") // เปลี่ยนเป็น key ที่ปลอดภัยกว่า

// Struct สำหรับรับข้อมูลจากฟอร์ม Login
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// Struct สำหรับเก็บข้อมูลของ JWT claims
type Claims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

// Database instance
var db *sql.DB

// User struct
type User struct {
	Fullname string `json:"fullname"`
	Username string `json:"username"`
	Password string `json:"password"`
}

func main() {
	// Connect to MySQL
	var err error
	db, err = sql.Open("mysql", "root:passwd@tcp(db:3306)/member")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// Test connection
	if err := db.Ping(); err != nil {
		log.Fatal(err)
	}

	// Initialize Fiber app
	app := fiber.New()

	// Routes
	// Route สำหรับ Health Check
	app.Get("/", func(c *fiber.Ctx) error {
		return c.Status(fiber.StatusOK).JSON(fiber.Map{
			"status":  "success",
			"message": "Server is running",
		})
	})
	app.Post("/register", registerUser)
	app.Post("/login", loginUser)

	// Start server
	log.Fatal(app.Listen(":3000"))
}

// Register user
func registerUser(c *fiber.Ctx) error {
	// Parse body
	var user User
	if err := c.BodyParser(&user); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid input"})
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to hash password"})
	}

	// Insert user into database
	_, err = db.Exec("INSERT INTO users (fullname, username, password) VALUES (?, ?, ?)",
		user.Fullname, user.Username, string(hashedPassword))
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to register user"})
	}

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{"message": "User registered successfully"})
}

// Login user
func loginUser(c *fiber.Ctx) error {
	// Parse body
	var user User
	if err := c.BodyParser(&user); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid input"})
	}

	// Get user from database
	var storedPassword string
	err := db.QueryRow("SELECT password FROM users WHERE username = ?", user.Username).Scan(&storedPassword)
	if err != nil {
		if err == sql.ErrNoRows {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid username or password"})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to query user"})
	}

	// Compare password
	if err := bcrypt.CompareHashAndPassword([]byte(storedPassword), []byte(user.Password)); err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid username or password"})
	}

	// สร้าง JWT token
	claims := Claims{
		Username: user.Username,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "member-app",                                       // ชื่อของผู้สร้าง token
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)), // ระยะเวลาหมดอายุ
		},
	}

	// สร้าง JWT token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// ลงลายเซ็นต์ JWT token
	signedToken, err := token.SignedString(jwtSecretKey)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Could not create token",
		})
	}

	// ส่งกลับ JWT token
	return c.JSON(fiber.Map{
		"token": signedToken,
	})
}
