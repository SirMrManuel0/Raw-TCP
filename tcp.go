package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"os"
)

const rsaKeySize = 2048

type Server struct {
	rsaPrivateKey *rsa.PrivateKey
	rsaPublicKey  *rsa.PublicKey
	logger *log.Logger
	handler handlerPostAES
	tcpOptions *TcpOptions
	options *ServerOptions
}

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


type handlerPostAES func(cipher.AEAD, []byte, net.Conn)

type TcpOptions struct {
    expectAuthKeyPre bool
	authValidate func([]byte) (bool, error)
}

type ServerOptions struct {
	loggerFile string
}

func NewServer(handler handlerPostAES, tcpOptions *TcpOptions, serverOptions *ServerOptions) (*Server, error) {
	if handler == nil {
		return nil, fmt.Errorf("Handler can not be nil!")
	}
	if tcpOptions == nil {
		tcpOptions = &TcpOptions{
			expectAuthKeyPre: false,
			authValidate: nil,
		}
	}
	if serverOptions == nil {
		serverOptions = &ServerOptions{
			loggerFile: "server.log",
		}
	}
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA keys: %v", err)
	}
	s := &Server{
		rsaPrivateKey: privateKey,
		rsaPublicKey:  &privateKey.PublicKey,
		handler: handler,
		tcpOptions: tcpOptions,
		options: serverOptions,
	}
	s.initLogger()
	return s, nil
}



func (s *Server) initLogger() {
	logFile, err := os.OpenFile(s.options.loggerFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0666)
	if err != nil {
		log.Fatalf("Failed to open log file: %v", err)
	}
	s.logger = log.New(logFile, "", log.LstdFlags)
	s.logger.Println("Server logging started.")
}

func (s *Server) InitTcp() {
	listener, err := net.Listen("tcp", ":8080")
	if err != nil {
		s.logger.Fatalf("Failed to start server: %v", err)
	}
	defer listener.Close()

	s.logger.Println("Server is listening on port 8080")

	for {
		conn, err := listener.Accept()
		if err != nil {
			s.logger.Printf("Failed to accept connection: %v", err)
			continue
		}

		go s.handleConnection(conn)
	}
}

func (s *Server) handleConnection(conn net.Conn) {
	defer conn.Close()
	s.sendPublicKey(conn)

	if s.tcpOptions.expectAuthKeyPre {
		encryptedAuthKey := make([]byte, rsaKeySize/8)
		if _, err := conn.Read(encryptedAuthKey); err != nil {
			s.logger.Printf("Failed to read Auth key: %v", err)
			s.sendHttpError(conn, 400, "")
			return
		}
		encryptedAuthKeyHash := make([]byte, rsaKeySize/8)
		if _, err := conn.Read(encryptedAuthKeyHash); err != nil {
			s.logger.Printf("Failed to read Auth key hash: %v", err)
			s.sendHttpError(conn, 400, "")
			return
		}
		authKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, s.rsaPrivateKey, encryptedAuthKey, nil)
		if err != nil {
			s.logger.Printf("Failed to decrypt Auth key: %v", err)
			s.sendHttpError(conn, 400, "")
			return
		}
		authKeyHash, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, s.rsaPrivateKey, encryptedAuthKeyHash, nil)
		if err != nil {
			s.logger.Printf("Failed to decrypt Auth key Hash: %v", err)
			s.sendHttpError(conn, 400, "")
			return
		}
		authKeyPostHash := sha256.Sum256(authKey)

		if !compareHashes(authKeyPostHash[:], authKeyHash) {
			s.logger.Printf("Auth key hash mismatch!")
			s.sendHttpError(conn, 403, "")
			return
		}
		b, err := s.tcpOptions.authValidate(authKey)
		if !b {
			s.logger.Printf("Failed to verify Auth Key: %v", err)
			s.sendHttpError(conn, 403, "")
			return
		}

	}

	encryptedAESKey := make([]byte, rsaKeySize/8)
	if _, err := conn.Read(encryptedAESKey); err != nil {
		s.logger.Printf("Failed to read AES key: %v", err)
		s.sendHttpError(conn, 400, "")
		return
	}

	aesKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, s.rsaPrivateKey, encryptedAESKey, nil)
	if err != nil {
		s.logger.Printf("Failed to decrypt AES key: %v", err)
		s.sendHttpError(conn, 400, "")
		return
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		s.logger.Printf("Failed to create cipher: %v", err)
		s.sendHttpError(conn, 500, "")
		return
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		s.logger.Printf("Failed to create GCM: %v", err)
		s.sendHttpError(conn, 500, "")
		return
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		s.logger.Printf("Failed to generate nonce: %v", err)
		s.sendHttpError(conn, 500, "")
		return
	}

	s.logger.Println("Connection secured. Ready to exchange encrypted data.")
	
	s.handler(aesGCM, nonce, conn)

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

func (s *Server) sendPublicKey(conn net.Conn) {
    pubASN1, err := x509.MarshalPKIXPublicKey(s.rsaPublicKey)
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


func (s *Server) Send(aesGCM cipher.AEAD, nonce []byte, conn net.Conn, plaintext []byte) error {
	ciphertext := aesGCM.Seal(nil, nonce, plaintext, nil)

	if _, err := conn.Write(nonce); err != nil {
		return fmt.Errorf("failed to send nonce: %v", err)
	}

	if _, err := conn.Write(ciphertext); err != nil {
		return fmt.Errorf("failed to send ciphertext: %v", err)
	}

	return nil
}

func (s *Server) Receive(aesGCM cipher.AEAD, conn net.Conn) ([]byte, error) {
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(conn, nonce); err != nil {
		return nil, fmt.Errorf("failed to read nonce: %v", err)
	}

	ciphertext := make([]byte, 1024)
	n, err := conn.Read(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("failed to read ciphertext: %v", err)
	}

	decryptedPlaintext, err := aesGCM.Open(nil, nonce, ciphertext[:n], nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data: %v", err)
	}

	return decryptedPlaintext, nil
}

func (s *Server) sendHttpError(conn net.Conn, statusCode int, errorMessage string) {
	statusText, ok := httpStatusTexts[statusCode]
	if !ok {
		statusText = "Unknown Status"
	}

	response := fmt.Sprintf("HTTP/1.1 %d %s\r\n", statusCode, statusText) +
		"Content-Type: text/plain\r\n" +
		fmt.Sprintf("Content-Length: %d\r\n", len(errorMessage)) +
		"\r\n" +
		errorMessage

	if _, err := conn.Write([]byte(response)); err != nil {
		s.logger.Printf("Failed to send HTTP error response: %v", err)
	}
}