package main

import (
	"database/sql"
	"fmt"
	"log"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

// กำหนด Struct สำหรับ Privileges และ UsersPrivilegesMap
type Privilege struct {
	ID             uint   `json:"id"`
	ProductName    string `json:"product_name"`
	PointsRequired int    `json:"points_required"`
	ExpirationDate string `json:"expiration_date"`
	Redeemed       bool   `json:"redeemed"`
}

type UserPrivilege struct {
	ID             uint   `json:"id"`
	UserID         uint   `json:"user_id"`
	PrivilegeID    uint   `json:"privilege_id"`
	PointsRedeemed int    `json:"points_redeemed"`
	RedeemedAt     string `json:"redeemed_at"`
}

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
	// Privileges
	app.Get("/privileges/:user_id", getPrivileges)

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
	_, err = db.Exec("INSERT INTO users (fullname, username, password, points) VALUES (?, ?, ?, 10000)",
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

// ฟังก์ชันสำหรับดึงข้อมูล privileges ตาม user_id โดยใช้ query string ธรรมดา
func getPrivileges(c *fiber.Ctx) error {
	userID := c.Params("user_id")

	// สร้าง query SQL raw string สำหรับ join ระหว่าง privileges กับ users_privileges_map
	query := `
		SELECT privileges.id, 
		       privileges.product_name, 
		       privileges.points_required, 
		       privileges.expiration_date,
		       IF(users_privileges_map.user_id IS NOT NULL, true, false) AS redeemed
		FROM privileges
		LEFT JOIN users_privileges_map ON users_privileges_map.privilege_id = privileges.id 
		AND users_privileges_map.user_id = ?
	`

	// ใช้ db.Query เพื่อ execute query
	rows, err := db.Query(query, userID)
	if err != nil {
		return c.Status(500).SendString(fmt.Sprintf("Error: %v", err))
	}
	defer rows.Close()

	// สร้าง slice ของ Privilege เพื่อเก็บข้อมูลที่ดึงมา
	var privileges []Privilege

	// อ่านข้อมูลจาก rows
	for rows.Next() {
		var privilege Privilege
		if err := rows.Scan(&privilege.ID, &privilege.ProductName, &privilege.PointsRequired, &privilege.ExpirationDate, &privilege.Redeemed); err != nil {
			return c.Status(500).SendString(fmt.Sprintf("Error: %v", err))
		}
		privileges = append(privileges, privilege)
	}

	// ตรวจสอบข้อผิดพลาดหลังจากการวน loop
	if err := rows.Err(); err != nil {
		return c.Status(500).SendString(fmt.Sprintf("Error: %v", err))
	}

	// ส่งผลลัพธ์กลับไปยัง client
	return c.JSON(privileges)
}
