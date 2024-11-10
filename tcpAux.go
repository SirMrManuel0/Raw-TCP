package main

import (
	"crypto/cipher"
	"fmt"
	"io"
	"net"
)

func Send(aesGCM cipher.AEAD, nonce []byte, conn net.Conn, plaintext []byte) error {
	ciphertext := aesGCM.Seal(nil, nonce, plaintext, nil)

	if _, err := conn.Write(nonce); err != nil {
		return fmt.Errorf("failed to send nonce: %v", err)
	}

	if _, err := conn.Write(ciphertext); err != nil {
		return fmt.Errorf("failed to send ciphertext: %v", err)
	}

	return nil
}

func Receive(aesGCM cipher.AEAD, conn net.Conn) ([]byte, error) {
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

func sendHttpError(conn net.Conn, statusCode int, errorMessage string) {
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
		logger.Printf("Failed to send HTTP error response: %v", err)
	}
}