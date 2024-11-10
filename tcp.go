package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"io"
	"log"
	"net"
	"os"
)

const rsaKeySize = 2048

var rsaPrivateKey, _ = rsa.GenerateKey(rand.Reader, rsaKeySize)
var rsaPublicKey = &rsaPrivateKey.PublicKey
var logger *log.Logger

var httpStatusTexts = map[int]string{
	400: "Bad Request",
	401: "Unauthorized",
	403: "Forbidden",
	404: "Not Found",
	500: "Internal Server Error",
	502: "Bad Gateway",
	503: "Service Unavailable",
	504: "Gateway Timeout",
}


type handlerPostAES func(cipher.AEAD, []byte, *log.Logger, net.Conn)

type InitTcpOptions struct {
    expectAuthKeyPre bool
	authValidate func([]byte) (bool, error)
}

func initLogger() {
	logFile, err := os.OpenFile("server.log", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0666)
	if err != nil {
		log.Fatalf("Failed to open log file: %v", err)
	}
	logger = log.New(logFile, "", log.LstdFlags)
	logger.Println("Server logging started.")
}

func InitTcp(handlerPost handlerPostAES, authOptions *InitTcpOptions) {
	if authOptions == nil {
		authOptions = &InitTcpOptions{expectAuthKeyPre: false, authValidate: nil}
	}
	initLogger()
	listener, err := net.Listen("tcp", ":8080")
	if err != nil {
		logger.Fatalf("Failed to start server: %v", err)
	}
	defer listener.Close()

	logger.Println("Server is listening on port 8080")

	for {
		conn, err := listener.Accept()
		if err != nil {
			logger.Printf("Failed to accept connection: %v", err)
			continue
		}

		go handleConnection(conn, handlerPost, authOptions)
	}
}

func handleConnection(conn net.Conn, handlerPost handlerPostAES, authOptions *InitTcpOptions) {
	defer conn.Close()
	sendPublicKey(conn)

	if authOptions.expectAuthKeyPre {
		encryptedAuthKey := make([]byte, rsaKeySize/8)
		if _, err := conn.Read(encryptedAuthKey); err != nil {
			logger.Printf("Failed to read Auth key: %v", err)
			sendHttpError(conn, 400, "")
			return
		}
		encryptedAuthKeyHash := make([]byte, rsaKeySize/8)
		if _, err := conn.Read(encryptedAuthKeyHash); err != nil {
			logger.Printf("Failed to read Auth key hash: %v", err)
			sendHttpError(conn, 400, "")
			return
		}
		authKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, rsaPrivateKey, encryptedAuthKey, nil)
		if err != nil {
			logger.Printf("Failed to decrypt Auth key: %v", err)
			sendHttpError(conn, 400, "")
			return
		}
		authKeyHash, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, rsaPrivateKey, encryptedAuthKeyHash, nil)
		if err != nil {
			logger.Printf("Failed to decrypt Auth key Hash: %v", err)
			sendHttpError(conn, 400, "")
			return
		}
		authKeyPostHash := sha256.Sum256(authKey)

		if !compareHashes(authKeyPostHash[:], authKeyHash) {
			logger.Printf("Auth key hash mismatch!")
			sendHttpError(conn, 403, "")
			return
		}
		b, err := authOptions.authValidate(authKey)
		if !b {
			logger.Printf("Failed to verify Auth Key: %v", err)
			sendHttpError(conn, 403, "")
			return
		}

	}

	encryptedAESKey := make([]byte, rsaKeySize/8)
	if _, err := conn.Read(encryptedAESKey); err != nil {
		logger.Printf("Failed to read AES key: %v", err)
		sendHttpError(conn, 400, "")
		return
	}

	aesKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, rsaPrivateKey, encryptedAESKey, nil)
	if err != nil {
		logger.Printf("Failed to decrypt AES key: %v", err)
		sendHttpError(conn, 400, "")
		return
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		logger.Printf("Failed to create cipher: %v", err)
		sendHttpError(conn, 500, "")
		return
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		logger.Printf("Failed to create GCM: %v", err)
		sendHttpError(conn, 500, "")
		return
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		logger.Printf("Failed to generate nonce: %v", err)
		sendHttpError(conn, 500, "")
		return
	}

	logger.Println("Connection secured. Ready to exchange encrypted data.")
	
	handlerPost(aesGCM, nonce, logger, conn)

}

func compareHashes(hash1 []byte, hash2 []byte) bool {
	if len(hash1) != len(hash2) {
		return false
	}
	for i := range hash1 {
		if hash1[i] != hash2[i] {
			return false
		}
	}
	return true
}

func sendPublicKey(conn net.Conn) {
    pubASN1, err := x509.MarshalPKIXPublicKey(rsaPublicKey)
    if err != nil {
        log.Printf("Failed to marshal public key: %v", err)
        return
    }

    pubPEM := pem.EncodeToMemory(&pem.Block{
        Type:  "PUBLIC KEY",
        Bytes: pubASN1,
    })

    if _, err := conn.Write(pubPEM); err != nil {
        log.Printf("Failed to send public key: %v", err)
    }
}