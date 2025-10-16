package strategies

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/gliderlabs/ssh"
	"github.com/google/uuid"
	"github.com/mariocandela/beelzebub/v3/parser"
	"github.com/mariocandela/beelzebub/v3/plugins"
	"github.com/mariocandela/beelzebub/v3/tracer"
	log "github.com/sirupsen/logrus"
	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

type SSHStrategy struct{}

var sshBanner string = `Welcome to Ubuntu 24.04.3 LTS (GNU/Linux 6.8.0-85-generic aarch64)
 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Last login: Mon Oct 13 00:56:37 2025 from 10.0.2.2
`

func (sshStrategy *SSHStrategy) Init(beelzebubServiceConfiguration parser.BeelzebubServiceConfiguration, tr tracer.Tracer) error {
	file, err := os.OpenFile("./configurations/log/beelzebub.json", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0770)
	if err != nil {
		log.Fatalf("Failed to open log file: %v", err)
	}
	multiWriter := io.MultiWriter(os.Stdout, file)
	log.SetOutput(multiWriter)
	log.SetFormatter(&log.JSONFormatter{
		TimestampFormat: time.RFC3339Nano,
		FieldMap: log.FieldMap{
			log.FieldKeyTime: "timestamp",
		},
	})
	log.SetLevel(log.InfoLevel)
	go func() {
		// Load or generate SSH host key
		hostKey, err := loadOrGenerateHostKey("./configurations/key/ssh_host_key")
		if err != nil {
			log.Fatalf("Failed to load or generate host key: %v", err)
		}

		server := &ssh.Server{
			Addr:        beelzebubServiceConfiguration.Address,
			MaxTimeout:  time.Duration(beelzebubServiceConfiguration.DeadlineTimeoutSeconds) * time.Second,
			IdleTimeout: time.Duration(beelzebubServiceConfiguration.DeadlineTimeoutSeconds) * time.Second,
			Version:     beelzebubServiceConfiguration.ServerVersion,
			Banner:      sshBanner,
			Handler: func(sess ssh.Session) {
				sessionStart := time.Now()
				uuidSession := uuid.New()

				newRoot := "mnt"

				srcIP, srcPort, _ := net.SplitHostPort(sess.RemoteAddr().String())
				_, destPort, _ := net.SplitHostPort(beelzebubServiceConfiguration.Address)
				clientVersion := sess.Context().ClientVersion()

				// SSH Inline Sessions

				if sess.RawCommand() != "" {
					for _, command := range beelzebubServiceConfiguration.Commands {
						matched, err := regexp.MatchString(command.RegexStr, sess.RawCommand())
						if err != nil {
							log.Errorf("Error regex: %s, %s", command.RegexStr, err.Error())
							continue
						}

						if matched {
							commandOutput := command.Handler

							if command.Plugin == plugins.LLMPluginName {

								llmProvider, err := plugins.FromStringToLLMProvider(beelzebubServiceConfiguration.Plugin.LLMProvider)
								if err != nil {
									log.Errorf("Error fromString: %s", err.Error())
									commandOutput = "command not found"
								}

								llmHoneypot := plugins.LLMHoneypot{
									Histories: make([]plugins.Message, 0),
									OpenAIKey: beelzebubServiceConfiguration.Plugin.OpenAISecretKey,
									Protocol:  tracer.SSH,
									Host:      beelzebubServiceConfiguration.Plugin.Host,
									Model:     beelzebubServiceConfiguration.Plugin.LLMModel,
									Provider:  llmProvider,
								}

								llmHoneypotInstance := plugins.InitLLMHoneypot(llmHoneypot)

								if commandOutput, err = llmHoneypotInstance.ExecuteModel(sess.RawCommand()); err != nil {
									log.Errorf("Error ExecuteModel: %s, %s", sess.RawCommand(), err.Error())
									commandOutput = "command not found"
								}
							}

							sess.Write(append([]byte(commandOutput), '\n'))
							sessionDuration := time.Since(sessionStart).Seconds()
							log.WithFields(log.Fields{
								"message":   "New SSH Inline Session",
								"protocol":  tracer.SSH.String(),
								"src_ip":    srcIP,
								"src_port":  srcPort,
								"dest_port": destPort,
								"status":    tracer.Start.String(),
								"session":   uuidSession.String(),
								"environ":   strings.Join(sess.Environ(), ","),
								"username":  sess.User(),
								"service":   beelzebubServiceConfiguration.Description,
								"input":     sess.RawCommand(),
								"output":    commandOutput,
							}).Info("New SSH Inline Session")
							log.WithFields(log.Fields{
								"message":          "End SSH Inline Session",
								"src_ip":           srcIP,
								"src_port":         srcPort,
								"dest_port":        destPort,
								"status":           tracer.End.String(),
								"protocol":         tracer.SSH.String(),
								"session":          uuidSession.String(),
								"session_duration": fmt.Sprintf("%.2fs", sessionDuration), // Log seconds
							}).Info("End SSH Inline Session")
							return
						}
					}
				}

				// SSH Inline Sessions

				log.WithFields(log.Fields{
					"message":        "New SSH Session",
					"protocol":       tracer.SSH.String(),
					"src_ip":         srcIP,
					"src_port":       srcPort,
					"dest_port":      destPort,
					"status":         tracer.Start.String(),
					"session":        uuidSession.String(),
					"environ":        strings.Join(sess.Environ(), ","),
					"username":       sess.User(),
					"service":        beelzebubServiceConfiguration.Description,
					"input":          sess.RawCommand(),
					"client_version": clientVersion,
				}).Info("New SSH Session")

				term := term.NewTerminal(sess, buildPrompt(sess.User(), beelzebubServiceConfiguration.ServerName))
				var histories []plugins.Message
				for {
					commandStart := time.Now()
					commandInput, err := term.ReadLine()
					commandDuration := time.Since(commandStart).Seconds()

					if err != nil {
						break
					}

					if commandInput == "exit" {
						break
					}
					for _, command := range beelzebubServiceConfiguration.Commands {
						matched, err := regexp.MatchString(command.RegexStr, commandInput)
						if err != nil {
							log.Errorf("Error regex: %s, %s", command.RegexStr, err.Error())
							continue
						}

						if matched {
							commandOutput := command.Handler

							commands := strings.Fields(commandInput)
							overriddenCmds := []string{
								"echo",
								"cat",
							}

							if slices.Contains(overriddenCmds, commands[0]) {
								bash := exec.Command("bash")

								if bash.SysProcAttr == nil {
									bash.SysProcAttr = &syscall.SysProcAttr{
										Chroot:     newRoot,
										Credential: &syscall.Credential{Uid: 2000, Gid: 2000},
									}
								} else {
									bash.SysProcAttr.Chroot = newRoot
								}
								bash.Stdin = strings.NewReader(commandInput)

								output, err := bash.Output()
								if err != nil {
									log.Errorf("Error executing command: %s", err.Error())
									commandOutput = "command not found"
								}

								commandOutput = string(output)
								commandOutput = strings.TrimSuffix(commandOutput, "\n")
							} else if command.Plugin == plugins.LLMPluginName {
								llmProvider, err := plugins.FromStringToLLMProvider(beelzebubServiceConfiguration.Plugin.LLMProvider)
								if err != nil {
									log.Errorf("Error fromString: %s", err.Error())
									commandOutput = "command not found"
								}

								llmHoneypot := plugins.LLMHoneypot{
									Histories: histories,
									OpenAIKey: beelzebubServiceConfiguration.Plugin.OpenAISecretKey,
									Protocol:  tracer.SSH,
									Host:      beelzebubServiceConfiguration.Plugin.Host,
									Model:     beelzebubServiceConfiguration.Plugin.LLMModel,
									Provider:  llmProvider,
								}

								llmHoneypotInstance := plugins.InitLLMHoneypot(llmHoneypot)

								if commandOutput, err = llmHoneypotInstance.ExecuteModel(commandInput); err != nil {
									log.Errorf("Error ExecuteModel: %s, %s", commandInput, err.Error())
									commandOutput = "command not found"
								}
							}

							histories = append(histories, plugins.Message{Role: plugins.USER.String(), Content: commandInput})
							histories = append(histories, plugins.Message{Role: plugins.ASSISTANT.String(), Content: commandOutput})

							term.Write(append([]byte(commandOutput), '\n'))

							log.WithFields(log.Fields{
								"message":        "New SSH Terminal Session",
								"src_ip":         srcIP,
								"src_port":       srcPort,
								"dest_port":      destPort,
								"status":         tracer.Interaction.String(),
								"input":          commandInput,
								"input_duration": fmt.Sprintf("%.2fs", commandDuration), // Log seconds
								"output":         commandOutput,
								"session":        uuidSession.String(),
								"protocol":       tracer.SSH.String(),
								"service":        beelzebubServiceConfiguration.Description,
							}).Info("New SSH Terminal Session")
							break
						}
					}
				}

				sessionDuration := time.Since(sessionStart).Seconds()
				log.WithFields(log.Fields{
					"message":          "End SSH Session",
					"src_ip":           srcIP,
					"src_port":         srcPort,
					"dest_port":        destPort,
					"status":           tracer.End.String(),
					"protocol":         tracer.SSH.String(),
					"session":          uuidSession.String(),
					"session_duration": fmt.Sprintf("%.2fs", sessionDuration), // Log seconds
				}).Info("End SSH Session")
			},
			PasswordHandler: func(ctx ssh.Context, password string) bool {
				srcIP, srcPort, _ := net.SplitHostPort(ctx.RemoteAddr().String())
				_, destPort, _ := net.SplitHostPort(beelzebubServiceConfiguration.Address)
				clientVersion := ctx.ClientVersion()

				log.WithFields(log.Fields{
					"message":   "New SSH attempt",
					"protocol":  tracer.SSH.String(),
					"status":    tracer.Stateless.String(),
					"username":  ctx.User(),
					"password":  password,
					"client":    clientVersion,
					"src_ip":    srcIP,
					"src_port":  srcPort,
					"dest_port": destPort,
					"session":   uuid.New().String(),
					"service":   beelzebubServiceConfiguration.Description,
				}).Info("New SSH attempt")
				matched, err := regexp.MatchString(beelzebubServiceConfiguration.PasswordRegex, password)
				if err != nil {
					log.Errorf("Error regex: %s, %s", beelzebubServiceConfiguration.PasswordRegex, err.Error())
					return false
				}
				return matched
			},
			HostSigners: []ssh.Signer{hostKey},
		}

		err = server.ListenAndServe()
		if err != nil {
			log.Errorf("Error during init SSH Protocol: %s", err.Error())
		}
	}()

	log.WithFields(log.Fields{
		"port":     beelzebubServiceConfiguration.Address,
		"commands": len(beelzebubServiceConfiguration.Commands),
	}).Infof("GetInstance service %s", beelzebubServiceConfiguration.Protocol)
	return nil
}

func loadOrGenerateHostKey(path string) (ssh.Signer, error) {
	// Try to read an existing private key file
	privateBytes, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			// Generate a new private key
			privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				return nil, fmt.Errorf("failed to generate private key: %v", err)
			}

			privateBytes = pem.EncodeToMemory(&pem.Block{
				Type:  "RSA PRIVATE KEY",
				Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
			})

			// Save the newly generated key to a file
			err = os.WriteFile(path, privateBytes, 0770)
			if err != nil {
				return nil, fmt.Errorf("failed to save private key: %v", err)
			}
		} else {
			return nil, fmt.Errorf("failed to read private key file: %v", err)
		}
	}

	// Parse the private key
	private, err := gossh.ParsePrivateKey(privateBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %v", err)
	}

	return private, nil
}

func buildPrompt(user string, serverName string) string {
	return fmt.Sprintf("%s@%s:~$ ", user, serverName)
}
