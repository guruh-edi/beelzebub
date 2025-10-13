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
	"regexp"
	"strings"
	"time"

	"github.com/gliderlabs/ssh"
	"github.com/google/uuid"
	"github.com/mariocandela/beelzebub/v3/parser"
	"github.com/mariocandela/beelzebub/v3/plugins"
	"github.com/mariocandela/beelzebub/v3/tracer"
	"github.com/pkg/sftp"
	log "github.com/sirupsen/logrus"
	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

type SSHStrategy struct{}

type LLMInterceptedSFTPServer struct {
	*sftp.RequestServer
}

// LoggingFileSystem wraps the default filesystem with logging
type LoggingFileSystem struct {
	root string
}

// Fileread implements FileReader interface
func (fs *LoggingFileSystem) Fileread(r *sftp.Request) (io.ReaderAt, error) {
	log.Printf("READ: %s (flags: %v)", r.Filepath, r.Flags)

	// Perform the actual operation
	file, err := os.Open(r.Filepath)
	if err != nil {
		log.Printf("READ ERROR: %s - %v", r.Filepath, err)
		return nil, err
	}

	return file, nil
}

// Filewrite implements FileWriter interface
func (fs *LoggingFileSystem) Filewrite(r *sftp.Request) (io.WriterAt, error) {
	log.Printf("WRITE: %s (flags: %v)", r.Filepath, r.Flags)

	file, err := os.OpenFile(r.Filepath, int(r.Flags), 0644)
	if err != nil {
		log.Printf("WRITE ERROR: %s - %v", r.Filepath, err)
		return nil, err
	}

	return file, nil
}

// Filecmd implements FileCmder interface
func (fs *LoggingFileSystem) Filecmd(r *sftp.Request) error {
	log.Printf("COMMAND: %s on %s (target: %s)", r.Method, r.Filepath, r.Target)

	switch r.Method {
	case "Remove":
		err := os.Remove(r.Filepath)
		if err != nil {
			log.Printf("REMOVE ERROR: %s - %v", r.Filepath, err)
		}
		return err

	case "Rename":
		err := os.Rename(r.Filepath, r.Target)
		if err != nil {
			log.Printf("RENAME ERROR: %s -> %s - %v", r.Filepath, r.Target, err)
		}
		return err

	case "Mkdir":
		err := os.Mkdir(r.Filepath, 0755)
		if err != nil {
			log.Printf("MKDIR ERROR: %s - %v", r.Filepath, err)
		}
		return err

	case "Rmdir":
		err := os.Remove(r.Filepath)
		if err != nil {
			log.Printf("RMDIR ERROR: %s - %v", r.Filepath, err)
		}
		return err
	}

	return sftp.ErrSSHFxOpUnsupported
}

// Filelist implements FileLister interface
func (fs *LoggingFileSystem) Filelist(r *sftp.Request) (sftp.ListerAt, error) {
	log.Printf("LIST: %s", r.Filepath)

	switch r.Method {
	case "List":
		dir, err := os.Open(r.Filepath)
		if err != nil {
			log.Printf("LIST ERROR: %s - %v", r.Filepath, err)
			return nil, err
		}
		return dirLister{dir}, nil

	case "Stat":
		fi, err := os.Stat(r.Filepath)
		if err != nil {
			log.Printf("STAT ERROR: %s - %v", r.Filepath, err)
			return nil, err
		}
		return listerat{fi}, nil

	case "Readlink":
		target, err := os.Readlink(r.Filepath)
		if err != nil {
			log.Printf("READLINK ERROR: %s - %v", r.Filepath, err)
			return nil, err
		}
		fi, _ := os.Stat(target)
		return listerat{fi}, nil
	}

	return nil, sftp.ErrSSHFxOpUnsupported
}

// Helper types for directory listing
type dirLister struct {
	*os.File
}

func (d dirLister) ListAt(f []os.FileInfo, offset int64) (int, error) {
	entries, err := d.Readdir(0)
	if err != nil {
		return 0, err
	}

	if offset >= int64(len(entries)) {
		return 0, io.EOF
	}

	n := copy(f, entries[offset:])
	if n < len(f) {
		return n, io.EOF
	}
	return n, nil
}

type listerat struct {
	os.FileInfo
}

func (l listerat) ListAt(f []os.FileInfo, offset int64) (int, error) {
	if offset > 0 {
		return 0, io.EOF
	}
	f[0] = l.FileInfo
	return 1, io.EOF
}

func NewLLMInterceptedSFTPServer(rwc io.ReadWriteCloser, options ...sftp.ServerOption) (*LLMInterceptedSFTPServer, error) {
	handlers := sftp.Handlers{
		FileGet:  &LoggingFileSystem{root: "/"},
		FilePut:  &LoggingFileSystem{root: "/"},
		FileCmd:  &LoggingFileSystem{root: "/"},
		FileList: &LoggingFileSystem{root: "/"},
	}
	s := sftp.NewRequestServer(rwc, handlers)
	server := &LLMInterceptedSFTPServer{
		s,
	}

	return server, nil
}

var sshBanner string = `Welcome to Ubuntu 24.04.3 LTS (GNU/Linux 6.8.0-85-generic aarch64)
 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Last login: Mon Oct 13 00:56:37 2025 from 10.0.2.2`

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
			SubsystemHandlers: map[string]ssh.SubsystemHandler{
				"sftp": sftpSubSysHandler,
			},
			Banner: sshBanner,
			Handler: func(sess ssh.Session) {
				sessionStart := time.Now()
				uuidSession := uuid.New()

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

							if command.Plugin == plugins.LLMPluginName {

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

func sftpSubSysHandler(s ssh.Session) {
	debugStream := io.Discard
	serverOptions := []sftp.ServerOption{
		sftp.WithDebug(debugStream),
	}
	server, err := NewLLMInterceptedSFTPServer(
		s,
		serverOptions...,
	)
	if err != nil {
		log.Printf("sftp server init error: %s\n", err)
		return
	}
	if err := server.Serve(); err == io.EOF {
		server.Close()
		fmt.Println("sftp client exited session.")
	} else if err != nil {
		fmt.Println("sftp server completed with error:", err)
	}
}
