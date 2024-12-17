package main

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

// กำหนด Struct สำหรับ Privileges และ UsersPrivilegesMap
type Privilege struct {
	ID             uint   `json:"id"`
	ProductName    string `json:"product_name"`
	Image          string `json:"image"`
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

// โครงสร้างข้อมูลสำหรับรับ JSON payload
type RedeemRequest struct {
	UserID      uint `json:"user_id"`
	PrivilegeID uint `json:"privilege_id"`
}

// Struct สำหรับรับข้อมูลจากฟอร์ม Login
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// Struct สำหรับเก็บข้อมูลของ JWT claims
type Claims struct {
	UserID   string `json:"user_id"`
	Username string `json:"username"`
	FullName string `json:"fullname"`
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
	app := fiber.New(fiber.Config{
		AppName:        "Member App API",
		BodyLimit:      50 * 1024 * 1024,
		ReadBufferSize: 16 * 1024,
	})

	// Use global middleware.
	app.Use(cors.New(cors.Config{
		AllowOrigins: "*",
	}))

	app.Use(recover.New())

	// Define a route to serve files
	app.Static("/public", "./storage", fiber.Static{
		Compress:      true,
		ByteRange:     true,
		Browse:        false,
		CacheDuration: 10 * time.Second,
		MaxAge:        3600,
	})

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

	// ใช้ Middleware สำหรับตรวจสอบ JWT
	app.Use(JWTMiddleware())

	// profile
	app.Get("/profile", getProfile)

	// Privileges
	app.Get("/privileges/user/:user_id", getPrivileges)
	app.Get("/privileges/:privilege_id/user/:user_id", getPrivilegeByID)
	app.Post("/privileges/redeem", redeemPrivilege)

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
	var storedPassword, fullname, id string
	err := db.QueryRow("SELECT id, password, fullname FROM users WHERE username = ?", user.Username).Scan(&id, &storedPassword, &fullname)
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
	jwtSecretKey := []byte(os.Getenv("JWT_SECRET"))
	claims := Claims{
		UserID:   id,
		Username: user.Username,
		FullName: fullname,
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

// API สำหรับดึงโปรไฟล์
func getProfile(c *fiber.Ctx) error {
	// ดึง username จาก context ที่เราเก็บไว้ใน JWTMiddleware
	username := c.Locals("username").(string)

	// ดึงข้อมูลโปรไฟล์จากฐานข้อมูลโดยใช้ query string
	var fullName string
	var points int

	// ใช้ query string ปกติ
	query := "SELECT fullname, points FROM users WHERE username = ?"
	err := db.QueryRow(query, username).Scan(&fullName, &points)
	if err != nil {
		if err == sql.ErrNoRows {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"error": "User not found",
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Error querying the database",
		})
	}

	// ส่งข้อมูลโปรไฟล์กลับไปยังผู้ใช้
	return c.JSON(fiber.Map{
		"username": username,
		"fullname": fullName,
		"points":   points,
	})
}

// ฟังก์ชันสำหรับดึงข้อมูล privileges ตาม user_id
func getPrivileges(c *fiber.Ctx) error {
	userID := c.Params("user_id")

	// สร้าง query SQL raw string สำหรับ join ระหว่าง privileges กับ users_privileges_map
	query := `
		SELECT privileges.id, 
		       privileges.product_name, 
		       IFNULL(privileges.image,""), 
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
		if err := rows.Scan(&privilege.ID, &privilege.ProductName, &privilege.Image, &privilege.PointsRequired, &privilege.ExpirationDate, &privilege.Redeemed); err != nil {
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

// ฟังก์ชันสำหรับดึงข้อมูล privileges By ID ตาม user_id
func getPrivilegeByID(c *fiber.Ctx) error {
	privilegeID := c.Params("privilege_id")
	userID := c.Params("user_id")

	// สร้าง query SQL raw string สำหรับ join ระหว่าง privileges กับ users_privileges_map
	query := `
		SELECT privileges.id, 
		       privileges.product_name, 
		       IFNULL(privileges.image,""), 
		       privileges.points_required, 
		       privileges.expiration_date,
		       IF(users_privileges_map.user_id IS NOT NULL, true, false) AS redeemed
		FROM privileges
		LEFT JOIN users_privileges_map ON users_privileges_map.privilege_id = privileges.id 
		AND users_privileges_map.user_id = ? 
		WHERE privileges.id = ?
	`

	// ใช้ db.Query เพื่อ execute query
	row := db.QueryRow(query, userID, privilegeID)
	// defer row.Close()

	// อ่านข้อมูลจาก rows
	var privilege Privilege
	if err := row.Scan(&privilege.ID, &privilege.ProductName, &privilege.Image, &privilege.PointsRequired, &privilege.ExpirationDate, &privilege.Redeemed); err != nil {
		return c.Status(500).SendString(fmt.Sprintf("Error: %v", err))
	}

	// ตรวจสอบข้อผิดพลาดหลังจากการวน loop
	if err := row.Err(); err != nil {
		return c.Status(500).SendString(fmt.Sprintf("Error: %v", err))
	}

	// ส่งผลลัพธ์กลับไปยัง client
	return c.JSON(privilege)
}

// ฟังก์ชันสำหรับ redeem
func redeemPrivilege(c *fiber.Ctx) error {
	var req RedeemRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).SendString("Invalid request payload")
	}

	// ตรวจสอบว่า user และ privilege มีอยู่ในระบบหรือไม่
	var userPoints, pointsRequired int
	var expirationDateRaw []uint8

	err := db.QueryRow(`
		SELECT u.points, p.points_required, p.expiration_date
		FROM users u
		JOIN privileges p ON p.id = ?
		WHERE u.id = ?
	`, req.PrivilegeID, req.UserID).Scan(&userPoints, &pointsRequired, &expirationDateRaw)

	if err == sql.ErrNoRows {
		return c.Status(404).SendString("User or privilege not found")
	} else if err != nil {
		return c.Status(500).SendString(fmt.Sprintf("Error querying database: %v", err))
	}

	// แปลง expiration_date จาก []uint8 เป็น time.Time โดยใช้รูปแบบ DATE
	expirationDate, err := time.Parse("2006-01-02", string(expirationDateRaw))
	if err != nil {
		return c.Status(500).SendString(fmt.Sprintf("Error parsing expiration date: %v", err))
	}

	// ใช้ Time Zone เดียวกันในการเปรียบเทียบ
	expirationDate = expirationDate.In(time.Local) // เปลี่ยนเขตเวลา Expiration Date ให้เป็น Local
	currentTime := time.Now().In(time.Local)       // ทำให้ Current Time ใช้เขตเวลา Local เช่นกัน

	fmt.Printf("Expiration Date: %v\n", expirationDate)
	fmt.Printf("Current Time: %v\n", currentTime)

	if currentTime.After(expirationDate) {
		return c.Status(400).SendString("Privilege has expired")
	}

	// ตรวจสอบคะแนนเพียงพอหรือไม่
	if userPoints < pointsRequired {
		return c.Status(400).SendString("Insufficient points")
	}

	// บันทึกการ redeem ลงในตาราง users_privileges_map
	tx, err := db.Begin()
	if err != nil {
		return c.Status(500).SendString(fmt.Sprintf("Error starting transaction: %v", err))
	}

	_, err = tx.Exec(`
		INSERT INTO users_privileges_map (user_id, privilege_id, points_redeemed, redeemed_at)
		VALUES (?, ?, ?, ?)
	`, req.UserID, req.PrivilegeID, pointsRequired, time.Now())
	if err != nil {
		tx.Rollback()
		return c.Status(500).SendString(fmt.Sprintf("Error inserting into users_privileges_map: %v", err))
	}

	// อัปเดตคะแนนในตาราง users
	_, err = tx.Exec(`
		UPDATE users
		SET points = points - ?
		WHERE id = ?
	`, pointsRequired, req.UserID)
	if err != nil {
		tx.Rollback()
		return c.Status(500).SendString(fmt.Sprintf("Error updating user points: %v", err))
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return c.Status(500).SendString(fmt.Sprintf("Error committing transaction: %v", err))
	}

	return c.Status(200).JSON(fiber.Map{
		"message":      "Redeem successful",
		"user_id":      req.UserID,
		"privilege_id": req.PrivilegeID,
		"points_used":  pointsRequired,
		"points_left":  userPoints - pointsRequired,
	})
}

func JWTMiddleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		// เส้นทางที่อนุญาตโดยไม่ต้องใช้ JWT
		allowedPaths := []string{"/register", "/login", "/", "/public"}

		// ข้ามการตรวจสอบ JWT สำหรับเส้นทางที่อนุญาต
		for _, path := range allowedPaths {
			if c.Path() == path || strings.HasPrefix(c.Path(), "/public/") {
				return c.Next()
			}
		}

		// รับค่า Token จาก Header
		tokenString := c.Get("Authorization")
		if tokenString == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Missing or invalid token",
			})
		}

		// ตัดคำว่า "Bearer " ออกจาก tokenString (ถ้ามี)
		if len(tokenString) > 7 && tokenString[:7] == "Bearer " {
			tokenString = tokenString[7:]
		}

		// ตรวจสอบ JWT
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			// ตรวจสอบ Method Signing Algorithm
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			// คืน Secret Key
			return []byte(os.Getenv("JWT_SECRET")), nil
		})

		if err != nil || !token.Valid {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Invalid or expired token",
			})
		}

		// ดึง username จาก token
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Invalid token claims",
			})
		}

		// เก็บ username ลงใน context เพื่อใช้ใน handler ถัดไป
		c.Locals("username", claims["username"])

		// ดำเนินการต่อไปยัง Handler
		return c.Next()
	}
}
