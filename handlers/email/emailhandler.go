/*Package email is an email handler used for sending email messages like sign up verifications and password reset requests.
 */
package email

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/smtp"

	"github.com/dadamssolutions/authentic/handlers/email/smtpauth"
)

// Recipient interface represents someone who can receive an email message.
type Recipient interface {
	GetEmail() string
	Greeting() string
}

// Sender handles all the sending of email messages like password reset and sign up.
type Sender struct {
	hostname, port, username string
	// You can include {{.Organization}} in you templates and get the name of the organization in your messages.
	Organization string
	auth         smtp.Auth

	// A function used to send an individual message.
	// This should almost never be used. SendMessage should be used instead.
	SendMail func(string, smtp.Auth, string, []string, []byte) error
}

// NewSender returns an email handler for sending messages from a single address.
func NewSender(organization, hostname, port, username, password string) *Sender {
	return NewSenderAuth(organization, hostname, port, username, smtpauth.NewLoginAuth(username, password))
}

// NewSenderAuth returns an email handler for sending messages from a single address provided an smtp.Auth.
func NewSenderAuth(organization, hostname, port, email string, auth smtp.Auth) *Sender {
	return &Sender{
		Organization: organization,
		hostname:     hostname,
		port:         port,
		username:     email,
		auth:         auth,
		SendMail:     SendMailSSL}
}

// SendMessage sends the message (as an HTML template) to the recipients
// Then template may include .Greeting or .Email for the information for the corresponding recipient.
func (e *Sender) SendMessage(tmpl *template.Template, subject string, data map[string]interface{}, recipientList ...Recipient) error {
	// Headers for HTML message and subject info
	headers := []byte(fmt.Sprintf("Subject: %v\r\nFrom: %v\r\nMIME-version: 1.0; \r\nContent-Type: text/html; charset=\"UTF-8\";\r\n\r\n", subject, e.username))
	buf := new(bytes.Buffer)
	// Add Organization info in case the template wants it
	data["Organization"] = e.Organization
	for _, r := range recipientList {
		// Reset the buffer and add the header info with To:...
		buf.Reset()
		buf.Write(append([]byte("To: "+r.GetEmail()+"\r\n"), headers...))
		// Add Greeting and Email info if the template wants it.
		data["Greeting"] = r.Greeting()
		data["Email"] = r.GetEmail()
		// Execute the template and send the message
		err := tmpl.Execute(buf, data)
		if err != nil {
			log.Printf("Error executing template: %v", err)
			return err
		}
		log.Printf("Sending message to %v\n", r.GetEmail())
		err = e.SendMail(e.hostname+":"+e.port, e.auth, e.username, []string{r.GetEmail()}, buf.Bytes())

		if err != nil {
			log.Printf("Error sending message to %v\n", r.GetEmail())
			return err
		}
		log.Printf("Message sent to %v!\n", r.GetEmail())
	}
	return nil
}

// SendPasswordResetMessage sends a password reset message to the given email address.
func (e *Sender) SendPasswordResetMessage(temp *template.Template, receiver Recipient, resetURL string) error {
	data := make(map[string]interface{})
	data["Link"] = resetURL
	return e.SendMessage(temp, "Password Reset", data, receiver)
}

// SendSignUpMessage sends a password reset message to the given email address.
func (e *Sender) SendSignUpMessage(temp *template.Template, receiver Recipient, resetURL string) error {
	data := make(map[string]interface{})
	data["Link"] = resetURL
	return e.SendMessage(temp, "Welcome! One more step", data, receiver)
}

// SendMailSSL dials an SSL connection to send messages.
func SendMailSSL(addr string, auth smtp.Auth, username string, recpts []string, message []byte) error {
	// TLS config
	host, _, _ := net.SplitHostPort(addr)
	tlsconfig := &tls.Config{
		InsecureSkipVerify: false,
		ServerName:         host,
		MinVersion:         tls.VersionTLS12,
	}

	conn, err := tls.Dial("tcp", addr, tlsconfig)
	if err != nil {
		return err
	}

	c, err := smtp.NewClient(conn, host)
	if err != nil {
		return err
	}

	// Auth
	if err = c.Auth(auth); err != nil {
		return err
	}

	// To && From
	if err = c.Mail(username); err != nil {
		return err
	}

	if err = c.Rcpt(recpts[0]); err != nil {
		return err
	}

	// Data
	w, err := c.Data()
	if err != nil {
		return err
	}

	_, err = w.Write(message)
	if err != nil {
		return err
	}

	err = w.Close()
	if err != nil {
		return err
	}

	return c.Quit()
}
