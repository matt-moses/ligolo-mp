package agents

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log/slog"
	"net"
	"time"

	"github.com/hashicorp/yamux"
	"github.com/ttpreport/ligolo-mp/v2/internal/certificate"
	"github.com/ttpreport/ligolo-mp/v2/internal/config"
	"github.com/ttpreport/ligolo-mp/v2/internal/events"
	"github.com/ttpreport/ligolo-mp/v2/internal/session"
)

type AgentApiHandler struct {
	config         *config.Config
	certService    *certificate.CertificateService
	sessionService *session.SessionService

	connections chan net.Conn
	quit        chan error
}

func Run(config *config.Config, certService *certificate.CertificateService, sessionService *session.SessionService) error {
	CACert := certService.GetCA()
	certpool, err := CACert.CertPool()
	if err != nil {
		return err
	}

	agentCert := certService.GetAgentServerCert()
	tlsCert, err := agentCert.KeyPair()
	if err != nil {
		return err
	}

	handler := &AgentApiHandler{
		config:         config,
		certService:    certService,
		sessionService: sessionService,
		connections:    make(chan net.Conn, 4096),
		quit:           make(chan error, 1),
	}

	var clientAuth = tls.RequireAndVerifyClientCert
	if config.InsecureAgents {
		slog.Warn("InsecureAgents is TRUE - not requiring client certificates!")
		clientAuth = tls.NoClientCert
	} else {
		slog.Info("InsecureAgents is FALSE - requiring client certificates")
	}

	tlsConfig := &tls.Config{
		ClientAuth:         clientAuth,
		Certificates:       []tls.Certificate{tlsCert},
		ClientCAs:          certpool,
		RootCAs:            certpool,
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true, // For server side, this doesn't affect client cert requirement
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			// When using a custom VerifyPeerCertificate callback, we must manually enforce
			// client certificate requirement since the callback replaces normal verification
			if !config.InsecureAgents {
				if len(rawCerts) == 0 {
					slog.Warn("Client connected without certificate (rejected)")
					return errors.New("client certificate required but not provided")
				}
			}

			// If InsecureAgents is true or if certs were provided, continue with verification
			if len(rawCerts) == 0 {
				return nil // No cert provided but InsecureAgents allows it
			}

			cert, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return err
			}

			options := x509.VerifyOptions{
				Roots: certpool,
			}
			if options.Roots == nil {
				return errors.New("no root certificate")
			}

			if _, err := cert.Verify(options); err != nil {
				return err
			}

			return nil
		},
	}

	go handler.serve("tcp", config.ListenInterface, tlsConfig)

	return <-handler.quit
}

func (aah *AgentApiHandler) serve(protocol string, listenIface string, tlsConfig *tls.Config) {
	defer func() { aah.quit <- nil }()

	server, err := tls.Listen(protocol, listenIface, tlsConfig)
	if err != nil {
		slog.Error("Could not start agent server",
			slog.Any("error", err),
		)
		return
	}
	defer server.Close()

	slog.Info("Agent server started",
		slog.Any("address", listenIface),
	)

	err = aah.sessionService.CleanUp()
	if err != nil {
		slog.Error("Could not clean up sessions",
			slog.Any("error", err),
		)
	}

	go aah.startHandler()

	for {
		conn, err := server.Accept()
		if err != nil {
			slog.Error("Agent server encountered an error",
				slog.Any("error", err),
			)

			if err == net.ErrClosed {
				return
			}

			continue
		}

		// TLS connections accepted - team info will come via protocol, not certificates
		slog.Debug("Accepted connection")

		aah.connections <- conn
	}
}

func (aah *AgentApiHandler) startHandler() {
	for {
		remoteConn := <-aah.connections
		slog.Debug("agent connection received")

		// Extract certificate information from TLS connection
		var certOrg, certCN string
		if tlsConn, ok := remoteConn.(*tls.Conn); ok {
			slog.Debug("connection is TLS")
			state := tlsConn.ConnectionState()
			slog.Debug("TLS connection state", slog.Int("peer_certs", len(state.PeerCertificates)))
			if len(state.PeerCertificates) > 0 {
				cert := state.PeerCertificates[0]
				slog.Debug("peer certificate found",
					slog.Int("org_count", len(cert.Subject.Organization)),
					slog.String("cn", cert.Subject.CommonName))
				if len(cert.Subject.Organization) > 0 {
					certOrg = cert.Subject.Organization[0]
				}
				certCN = cert.Subject.CommonName
				slog.Info("Agent certificate extracted", slog.String("org", certOrg), slog.String("cn", certCN))
			} else {
				slog.Warn("No peer certificates in TLS connection")
			}
		} else {
			slog.Warn("Connection is not TLS!")
		}

		config := yamux.DefaultConfig()
		config.LogOutput = io.Discard
		// Match agent-side yamux settings to prevent keepalive mismatches
		config.KeepAliveInterval = 60 * time.Second
		config.ConnectionWriteTimeout = 30 * time.Second
		yamuxConn, err := yamux.Client(remoteConn, config)
		if err != nil {
			slog.Error("could not open multiplexed connection with agent")
			continue
		}
		slog.Debug("established multiplexed connection with agent")

		newSession, err := aah.sessionService.NewSessionWithCert(yamuxConn, certOrg, certCN)
		if err != nil {
			slog.Error("could not initialize new session", slog.Any("error", err))
			yamuxConn.Close()
			continue
		}
		slog.Debug("new session created", slog.Any("session", newSession))

		go aah.startSessionMonitor(newSession)

		slog.Debug("session initialized")

		events.Publish(events.OK, "new session with '%s' established", newSession.GetName())
	}

}

func (aah *AgentApiHandler) startSessionMonitor(sess *session.Session) {
	tick := time.NewTicker(1 * time.Second)
	for {
		select {
		case <-tick.C:
			aah.sessionService.UpdateLastSeen(sess.ID)
		case <-sess.Multiplex.CloseChan():
			slog.Debug("session multiplexer closed", slog.Any("session", sess))
			aah.sessionService.DisconnectSession(sess.ID)
			events.Publish(events.ERROR, "session with '%s' disconnected", sess.GetName())
			return
		}
	}

}

func (aah *AgentApiHandler) Close() {
	aah.quit <- nil
}
