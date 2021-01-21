package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var (
	optBind             string
	optTarget           string
	optTargetServerName string
	optTargetSSL        bool
	optExtraIPs         []net.IP

	certificates = map[string]*tls.Certificate{}

	serverTLSConfig = &tls.Config{
		GetCertificate: func(info *tls.ClientHelloInfo) (cert *tls.Certificate, err error) {
			var cacheKey string
			if info.ServerName == "" {
				cacheKey = "__DEFAULT__"
			} else {
				cacheKey = info.ServerName
			}
			cert = certificates[cacheKey]
			if cert == nil {
				var key *rsa.PrivateKey
				if key, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
					return
				}
				keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
				tmpl := &x509.Certificate{
					SerialNumber: big.NewInt(time.Now().Unix()),
					Subject: pkix.Name{
						Country:      []string{"CN"},
						Organization: []string{"ACICN"},
						CommonName:   "Oddesy Proxy",
					},
					NotBefore:   time.Now().Add(-10 * time.Second),
					NotAfter:    time.Now().AddDate(30, 0, 0),
					KeyUsage:    x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
					ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
					IsCA:        true,
					MaxPathLen:  1,
				}
				if info.ServerName != "" {
					tmpl.DNSNames = append(tmpl.DNSNames, info.ServerName)
				}
				tmpl.IPAddresses = optExtraIPs
				var certRaw []byte
				if certRaw, err = x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key); err != nil {
					return
				}
				certPEM := pem.EncodeToMemory(&pem.Block{
					Type:  "CERTIFICATE",
					Bytes: certRaw,
				})

				var _cert tls.Certificate
				if _cert, err = tls.X509KeyPair(certPEM, keyPEM); err != nil {
					return
				}

				cert = &_cert
				certificates[cacheKey] = &_cert
			}
			return
		},
	}
)

func main() {
	var err error
	defer func(err *error) {
		if *err != nil {
			log.Println("exited with error:", (*err).Error())
			os.Exit(1)
		} else {
			log.Println("exited")
		}
	}(&err)

	var ()

	optBind = strings.TrimSpace(os.Getenv("CFG_BIND"))
	optTarget = strings.TrimSpace(os.Getenv("CFG_TARGET"))
	optTargetServerName = strings.TrimSpace(os.Getenv("CFG_TARGET_SERVER_NAME"))
	optTargetSSL, _ = strconv.ParseBool(strings.TrimSpace(os.Getenv("CFG_TARGET_SSL")))
	envExtraIPs := strings.Split(strings.TrimSpace(os.Getenv("CFG_EXTRA_IPS")), ",")

	if optBind == "" {
		optBind = ":7000"
	}
	if optTarget == "" {
		err = errors.New("missing env CFG_TARGET")
		return
	}
	if optTargetServerName == "" {
		if optTargetServerName, _, err = net.SplitHostPort(optTarget); err != nil {
			return
		}
	}
	for _, rawIP := range envExtraIPs {
		optExtraIPs = append(optExtraIPs, net.ParseIP(strings.TrimSpace(rawIP)))
	}

	log.Println("listening at:", optBind)

	var l net.Listener
	if l, err = net.Listen("tcp", optBind); err != nil {
		return
	}

	go func() {
		chSig := make(chan os.Signal, 1)
		signal.Notify(chSig, syscall.SIGTERM, syscall.SIGINT)
		sig := <-chSig
		log.Println("signal caught:", sig.String())
		l.Close()
	}()

	for {
		var c net.Conn
		if c, err = l.Accept(); err != nil {
			log.Println(err.Error())
			break
		}
		go handle(c)
	}
}

func handle(srcConn net.Conn) {
	srcTLSConn := tls.Server(srcConn, serverTLSConfig)
	defer srcTLSConn.Close()

	var err error
	var dstConn net.Conn
	if dstConn, err = net.Dial("tcp", optTarget); err != nil {
		log.Printf("failed to connect %s: %s", optTarget, err.Error())
		return
	}

	var finalDstConn io.ReadWriteCloser

	if optTargetSSL {
		dstTLSConn := tls.Client(dstConn, &tls.Config{ServerName: optTargetServerName, InsecureSkipVerify: true})
		finalDstConn = dstTLSConn
	} else {
		finalDstConn = dstConn
	}

	defer finalDstConn.Close()

	go io.Copy(finalDstConn, srcTLSConn)
	io.Copy(srcTLSConn, finalDstConn)
}
