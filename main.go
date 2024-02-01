package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	_ "github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/bcrypt"
)

const (
	DBHost     = "localhost"
	DBPort     = 3306
	DBUser     = "root"
	DBPassword = ""
	DBName     = "db_mnc"
)

var db *sql.DB

type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Password string `json:"-"`
	Saldo    int    `json:"saldo"`
}

func main() {
	dbInfo := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s", DBUser, DBPassword, DBHost, DBPort, DBName)
	var err error
	db, err = sql.Open("mysql", dbInfo)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	createTable()

	router := gin.Default()

	router.POST("/register", registerHandler)
	router.POST("/login", loginHandler)
	router.POST("/payment", authenticationMiddleware(), paymentHandler)

	router.Run(":8081")
}

func createTable() {
	createTableQuery := `
    CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(50) NOT NULL,
        password VARCHAR(60) NOT NULL,
		saldo INT DEFAULT 0
    );
    `

	_, err := db.Exec(createTableQuery)
	if err != nil {
		log.Fatal(err)
	}
}

func registerHandler(c *gin.Context) {
	var user User

	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
		return
	}

	user.Password = string(hashedPassword)

	insertQuery := "INSERT INTO users (username, password, saldo) VALUES (?, ?, ?)"
	_, err = db.Exec(insertQuery, user.Username, user.Password, user.Saldo)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to register user"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User registered successfully"})
}

func loginHandler(c *gin.Context) {
	var user User

	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	selectQuery := "SELECT id, password FROM users WHERE username = ?"
	row := db.QueryRow(selectQuery, user.Username)

	var storedID int
	var storedPassword string

	err := row.Scan(&storedID, &storedPassword)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(storedPassword), []byte(user.Password))
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Login successful"})
}

func authenticationMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		username := c.PostForm("username")

		c.Set("username", username)

		c.Next()
	}
}

func paymentHandler(c *gin.Context) {

	username, exists := c.Get("username")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Username not found"})
		return
	}

	selectQuery := "SELECT id, saldo FROM users WHERE username = ?"
	row := db.QueryRow(selectQuery, username)

	var userID, userSaldo int

	err := row.Scan(&userID, &userSaldo)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid user"})
		return
	}

	var paymentInfo struct {
		RecipientUsername string `json:"recipient_username"`
		Amount            int    `json:"amount"`
	}

	if err := c.ShouldBindJSON(&paymentInfo); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	selectRecipientQuery := "SELECT id, saldo FROM users WHERE username = ?"
	row = db.QueryRow(selectRecipientQuery, paymentInfo.RecipientUsername)

	var recipientID, recipientSaldo int

	err = row.Scan(&recipientID, &recipientSaldo)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Recipient not found"})
		return
	}

	if userSaldo < paymentInfo.Amount {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Insufficient balance"})
		return
	}

	userSaldo -= paymentInfo.Amount
	updateSenderQuery := "UPDATE users SET saldo = ? WHERE id = ?"
	_, err = db.Exec(updateSenderQuery, userSaldo, userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update sender's balance"})
		return
	}

	recipientSaldo += paymentInfo.Amount
	updateRecipientQuery := "UPDATE users SET saldo = ? WHERE id = ?"
	_, err = db.Exec(updateRecipientQuery, recipientSaldo, recipientID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update recipient's balance"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Payment successful"})
}
