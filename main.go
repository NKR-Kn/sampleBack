package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"log"
	"math/rand"
	"net/http"
)

type User struct {
	ID        string `json:"id,omitempty" bson:"_id,omitempty"`
	FirstName string `json:"firstName,omitempty" bson:"first_name,omitempty"`
	LastName  string `json:"lastName,omitempty" bson:"last_name,omitempty"`
	Username  string `json:"username,omitempty" bson:"username,omitempty"`
	Password  string `json:"password,omitempty" bson:"password,omitempty"`
}

var client *mongo.Client

func connectMongo() {
	var err error
	clientOptions := options.Client().ApplyURI("mongodb://localhost:27017")
	client, err = mongo.Connect(context.TODO(), clientOptions)
	if err != nil {
		panic(err)
	}
	err = client.Ping(context.TODO(), nil)
	if err != nil {
		panic(err)
	}
	fmt.Println("Connected to MongoDB!")
}

func pad(data []byte) []byte {
	padding := aes.BlockSize - len(data)%aes.BlockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padtext...)
}

func encrypt(plainText, key string) (string, error) {
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}

	// แพดข้อมูล
	plainTextBytes := pad([]byte(plainText))
	ciphertext := make([]byte, aes.BlockSize+len(plainTextBytes))
	iv := ciphertext[:aes.BlockSize]
	if _, err := rand.Read(iv); err != nil {
		return "", err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], plainTextBytes)

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func unpad(data []byte) ([]byte, error) {
	length := len(data)
	unpadding := int(data[length-1])
	if unpadding > length {
		return nil, fmt.Errorf("invalid padding")
	}
	return data[:(length - unpadding)], nil
}

func decrypt(cipherText, key string) (string, error) {
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}

	ciphertext, _ := base64.StdEncoding.DecodeString(cipherText)
	if len(ciphertext) < aes.BlockSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(ciphertext, ciphertext)

	unpaddedText, err := unpad(ciphertext)
	if err != nil {
		return "", err
	}

	return string(unpaddedText), nil
}

func enableCORS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	// หากเป็นคำขอ OPTIONS ให้ส่งการตอบสนองทันที
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
}

func createUser(w http.ResponseWriter, r *http.Request) {
	enableCORS(w, r)
	if r.Method == http.MethodOptions {
		return // Respond to preflight request
	}

	var user User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	if user.Username == "" || user.Password == "" || user.FirstName == "" || user.LastName == "" {
		http.Error(w, "Missing required fieldsss", http.StatusBadRequest)
		return
	}

	encryptedPassword, err := encrypt(user.Password, "1849846546846846")
	if err != nil {
		http.Error(w, "Error encrypting password", http.StatusInternalServerError)
		return
	}
	user.Password = encryptedPassword

	collection := client.Database("testdb").Collection("users")
	insertResult, err := collection.InsertOne(context.TODO(), user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "User created successfully",
		"user_id": insertResult.InsertedID,
	})
}

func getUser(w http.ResponseWriter, r *http.Request) {
	enableCORS(w, r)
	if r.Method == http.MethodOptions {
		return
	}

	var requestBody struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&requestBody); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	collection := client.Database("testdb").Collection("users")
	var user User
	err := collection.FindOne(context.TODO(), bson.M{"username": requestBody.Username}).Decode(&user)

	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	decryptedPassword, err := decrypt(user.Password, "1849846546846846")
	if err != nil || decryptedPassword != requestBody.Password {
		http.Error(w, "Username or password Invalid", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user)
}

func main() {
	connectMongo()
	r := mux.NewRouter()

	r.HandleFunc("/api/create_users", createUser).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/get_users", getUser).Methods("POST", "OPTIONS")

	http.Handle("/", r)
	fmt.Println("Server is running on port 8080...")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
