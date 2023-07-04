package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	mrand "math/rand"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/ThalesIgnite/crypto11"
	"github.com/micromdm/scep/v2/csrverifier"
	executablecsrverifier "github.com/micromdm/scep/v2/csrverifier/executable"
	scepdepot "github.com/micromdm/scep/v2/depot"
	"github.com/micromdm/scep/v2/depot/file"
	scepserver "github.com/micromdm/scep/v2/server"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
)

// version info
var (
	version = "unknown"
)

func main() {
	var caCMD = flag.NewFlagSet("ca", flag.ExitOnError)
	{
		if len(os.Args) >= 2 {
			if os.Args[1] == "ca" {
				status := caMain(caCMD)
				os.Exit(status)
			}
		}
	}

	//main flags
	var (
		flVersion           = flag.Bool("version", false, "prints version information")
		flHTTPAddr          = flag.String("http-addr", envString("SCEP_HTTP_ADDR", ""), "http listen address. defaults to \":8080\"")
		flPort              = flag.String("port", envString("SCEP_HTTP_LISTEN_PORT", "8080"), "http port to listen on (if you want to specify an address, use -http-addr instead)")
		flDepotPath         = flag.String("depot", envString("SCEP_FILE_DEPOT", "depot"), "path to ca folder")
		flCAPass            = flag.String("capass", envString("SCEP_CA_PASS", ""), "passwd for the ca.key")
		flClDuration        = flag.String("crtvalid", envString("SCEP_CERT_VALID", "365"), "validity for new client certificates in days")
		flClAllowRenewal    = flag.String("allowrenew", envString("SCEP_CERT_RENEW", "14"), "do not allow renewal until n days before expiry, set to 0 to always allow")
		flChallengePassword = flag.String("challenge", envString("SCEP_CHALLENGE_PASSWORD", ""), "enforce a challenge password")
		flCSRVerifierExec   = flag.String("csrverifierexec", envString("SCEP_CSR_VERIFIER_EXEC", ""), "will be passed the CSRs for verification")
		flPkcs11ConfigFile  = flag.String("pkcs11-config", envString("SCEP_PKCS11_CONFIGFILE", ""), "location of json config for pkcs11 external signer")
		flDebug             = flag.Bool("debug", envBool("SCEP_LOG_DEBUG"), "enable debug logging")
		flLogJSON           = flag.Bool("log-json", envBool("SCEP_LOG_JSON"), "output JSON logs")
		flSignServerAttrs   = flag.Bool("sign-server-attrs", envBool("SCEP_SIGN_SERVER_ATTRS"), "sign cert attrs for server usage")
		flDynamoDbBucket    = flag.String("dyndb", envString("DYNAMODB_BUCKET", ""), "name of a dynamodb bucket to save certs to.")
		flAiaUrl            = flag.String("aiaurl", envString("AIA_URL", ""), "authority information access url. optional, ignore if this makes no sense.")
		flOcspUrl           = flag.String("ocsp", envString("OCSP_URL", ""), "ocsp server url. optional, ignore if this makes no sense.")
	)
	flag.Usage = func() {
		flag.PrintDefaults()

		fmt.Println("usage: scep [<command>] [<args>]")
		fmt.Println(" ca <args> create/manage a CA")
		fmt.Println("type <command> --help to see usage for each subcommand")
	}
	flag.Parse()

	// print version information
	if *flVersion {
		fmt.Println(version)
		os.Exit(0)
	}

	// -http-addr and -port conflict. Don't allow the user to set both.
	httpAddrSet := setByUser("http-addr", "SCEP_HTTP_ADDR")
	portSet := setByUser("port", "SCEP_HTTP_LISTEN_PORT")
	var httpAddr string
	if httpAddrSet && portSet {
		fmt.Fprintln(os.Stderr, "cannot set both -http-addr and -port")
		os.Exit(1)
	} else if httpAddrSet {
		httpAddr = *flHTTPAddr
	} else {
		httpAddr = ":" + *flPort
	}

	var logger log.Logger
	{

		if *flLogJSON {
			logger = log.NewJSONLogger(os.Stderr)
		} else {
			logger = log.NewLogfmtLogger(os.Stderr)
		}
		if !*flDebug {
			logger = level.NewFilter(logger, level.AllowInfo())
		}
		logger = log.With(logger, "ts", log.DefaultTimestampUTC)
		logger = log.With(logger, "caller", log.DefaultCaller)
	}
	lginfo := level.Info(logger)

	var err error
	var depot scepdepot.Depot // cert storage
	{
		depot, err = file.NewFileDepot(*flDepotPath)
		if err != nil {
			lginfo.Log("err", err)
			os.Exit(1)
		}
	}
	allowRenewal, err := strconv.Atoi(*flClAllowRenewal)
	if err != nil {
		lginfo.Log("err", err, "msg", "No valid number for allowed renewal time")
		os.Exit(1)
	}
	clientValidity, err := strconv.Atoi(*flClDuration)
	if err != nil {
		lginfo.Log("err", err, "msg", "No valid number for client cert validity")
		os.Exit(1)
	}
	var csrVerifier csrverifier.CSRVerifier
	if *flCSRVerifierExec > "" {
		executableCSRVerifier, err := executablecsrverifier.New(*flCSRVerifierExec, lginfo)
		if err != nil {
			lginfo.Log("err", err, "msg", "Could not instantiate CSR verifier")
			os.Exit(1)
		}
		csrVerifier = executableCSRVerifier
	}

	var svc scepserver.Service // scep service
	{
		crts, key, err := depot.CA([]byte(*flCAPass))
		if err != nil {
			lginfo.Log("err", err)
			os.Exit(1)
		}
		if len(crts) < 1 {
			lginfo.Log("err", "missing CA certificate")
			os.Exit(1)
		}
		// add a non-secure random int to expiry to avoid everyone renewing at the same time.
		// This gives us certs with a validity of anywhere in 1-2 years.
		s1 := mrand.NewSource(time.Now().UnixNano())
		r1 := mrand.New(s1)

		signerOpts := []scepdepot.Option{
			scepdepot.WithAllowRenewalDays(allowRenewal),
			scepdepot.WithValidityDays(clientValidity + r1.Intn(365)),
			scepdepot.WithCAPass(*flCAPass),
		}
		if *flSignServerAttrs {
			signerOpts = append(signerOpts, scepdepot.WithSeverAttrs())
		}
		if *flDynamoDbBucket != "" {
			//lginfo.Log("info", "Will use %v as my dynamodb bucket", &flDynamoDbBucket)
			signerOpts = append(signerOpts, scepdepot.WithDynamoDbBucket(*flDynamoDbBucket))
		}
		if *flAiaUrl != "" {
			signerOpts = append(signerOpts, scepdepot.WithAiaUrl(*flAiaUrl))
		}

		if *flOcspUrl != "" {
			signerOpts = append(signerOpts, scepdepot.WithOcspUrl(*flOcspUrl))
		}
		if *flPkcs11ConfigFile != "" {
			fcontents, err := os.ReadFile(*flPkcs11ConfigFile)
			if err != nil {
				lginfo.Log("err", err)
				os.Exit(1)
			}
			lginfo.Log("err", "pkcs11-config: %#v", string(fcontents))
			// Test config?
			ctx, err := crypto11.ConfigureFromFile(*flPkcs11ConfigFile)
			if err != nil {
				lginfo.Log("err", "cannot configure crypto11 library using provided config")
				lginfo.Log("err", err)
				os.Exit(1)
			}
			signerOpts = append(signerOpts, scepdepot.WithPkcs11Ctx(ctx))
		}
		var signer scepserver.CSRSigner = scepdepot.NewSigner(depot, signerOpts...)
		if *flChallengePassword != "" {
			signer = scepserver.ChallengeMiddleware(*flChallengePassword, signer)
		}
		if csrVerifier != nil {
			signer = csrverifier.Middleware(csrVerifier, signer)
		}
		svc, err = scepserver.NewService(crts[0], key, signer, scepserver.WithLogger(logger))
		if err != nil {
			lginfo.Log("err", err)
			os.Exit(1)
		}
		svc = scepserver.NewLoggingService(log.With(lginfo, "component", "scep_service"), svc)
	}

	var h http.Handler // http handler
	{
		e := scepserver.MakeServerEndpoints(svc)
		e.GetEndpoint = scepserver.EndpointLoggingMiddleware(lginfo)(e.GetEndpoint)
		e.PostEndpoint = scepserver.EndpointLoggingMiddleware(lginfo)(e.PostEndpoint)
		h = scepserver.MakeHTTPHandler(e, svc, log.With(lginfo, "component", "http"))
	}

	// start http server
	errs := make(chan error, 2)
	go func() {
		lginfo.Log("transport", "http", "address", httpAddr, "msg", "listening")
		errs <- http.ListenAndServe(httpAddr, h)
	}()
	go func() {
		c := make(chan os.Signal)
		signal.Notify(c, syscall.SIGINT)
		errs <- fmt.Errorf("%s", <-c)
	}()

	lginfo.Log("terminated", <-errs)
}

func caMain(cmd *flag.FlagSet) int {
	var (
		flDepotPath        = cmd.String("depot", "depot", "path to ca folder")
		flInit             = cmd.Bool("init", false, "create a new CA")
		flYears            = cmd.Int("years", 10, "default CA years")
		flKeySize          = cmd.Int("keySize", 4096, "rsa key size")
		flCommonName       = cmd.String("common_name", "MICROMDM SCEP CA", "common name (CN) for CA cert")
		flOrg              = cmd.String("organization", "scep-ca", "organization for CA cert")
		flOrgUnit          = cmd.String("organizational_unit", "SCEP CA", "organizational unit (OU) for CA cert")
		flPassword         = cmd.String("key-password", "", "password to store rsa key")
		flCountry          = cmd.String("country", "US", "country for CA cert")
		flPkcs11ConfigFile = cmd.String("pkcs11-config", envString("SCEP_PKCS11_CONFIGFILE", ""), "location of json config for pkcs11 external signer")
	)
	cmd.Parse(os.Args[2:])
	if *flInit {
		fmt.Println("Initializing new CA")
		key, err := createKey(*flKeySize, []byte(*flPassword), *flDepotPath)
		if err != nil {
			fmt.Println(err)
			return 1
		}
		if err := createCertificateAuthority(key, *flYears, *flCommonName, *flOrg, *flOrgUnit, *flCountry, *flDepotPath); err != nil {
			fmt.Println(err)
			return 1
		}
		if *flPkcs11ConfigFile != "" {
			// using pkcs11, let's create a new CA cert
			ctx, err := crypto11.ConfigureFromFile(*flPkcs11ConfigFile)
			if err != nil {
				fmt.Println(err)
				return 1
			}
			signers, err := ctx.FindAllKeyPairs()
			if err != nil {
				fmt.Println(err)
				return 1
			}
			// test we can use to sign and verify
			data := []byte("mary had a little lamb")
			h := sha256.New()
			_, err = h.Write(data)
			if err != nil {
				fmt.Println(err)
				return 1
			}
			hash := h.Sum([]byte{})
			sig, err := signers[0].Sign(rand.Reader, hash, crypto.SHA256)
			if err != nil {
				fmt.Println(err)
				return 1
			}
			err = rsa.VerifyPKCS1v15(signers[0].Public().(crypto.PublicKey).(*rsa.PublicKey), crypto.SHA256, hash, sig)
			if err != nil {
				fmt.Println(err)
				return 1
			}
			// now attempt to create the 'real' ca certificate
			if err := createExternalCertificateAuthority(signers[0], *flYears, *flCommonName, *flOrg, *flOrgUnit, *flCountry, *flDepotPath); err != nil {
				fmt.Println(err)
				return 1
			}
		}
	}

	return 0
}

// create a key, save it to depot and return it for further usage.
func createKey(bits int, password []byte, depot string) (*rsa.PrivateKey, error) {
	// create depot folder if missing
	if err := os.MkdirAll(depot, 0755); err != nil {
		return nil, err
	}
	name := filepath.Join(depot, "ca.key")
	file, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0400)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// create RSA key and save as PEM file
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}
	privPEMBlock, err := x509.EncryptPEMBlock(
		rand.Reader,
		rsaPrivateKeyPEMBlockType,
		x509.MarshalPKCS1PrivateKey(key),
		password,
		x509.PEMCipherAES256,
	)
	if err != nil {
		return nil, err
	}
	if err := pem.Encode(file, privPEMBlock); err != nil {
		os.Remove(name)
		return nil, err
	}

	return key, nil
}

func createCertificateAuthority(key *rsa.PrivateKey, years int, commonName string, organization string, organizationalUnit string, country string, depot string) error {
	cert := scepdepot.NewCACert(
		scepdepot.WithYears(years),
		scepdepot.WithCommonName(commonName+" (Internal Service)"),
		scepdepot.WithOrganization(organization),
		scepdepot.WithOrganizationalUnit(organizationalUnit),
		scepdepot.WithCountry(country),
	)
	crtBytes, err := cert.SelfSign(rand.Reader, &key.PublicKey, key)
	if err != nil {
		return err
	}

	name := filepath.Join(depot, "ca.pem")
	file, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0400)
	if err != nil {
		return err
	}
	defer file.Close()

	if _, err := file.Write(pemCert(crtBytes)); err != nil {
		file.Close()
		os.Remove(name)
		return err
	}

	return nil
}

func createExternalCertificateAuthority(signer crypto11.Signer, years int, commonName string, organization string, organizationalUnit string, country string, depot string) error {
	cert := scepdepot.NewCACert(
		scepdepot.WithYears(years),
		scepdepot.WithCommonName(commonName+" (Client CA)"),
		scepdepot.WithOrganization(organization),
		scepdepot.WithOrganizationalUnit(organizationalUnit),
		scepdepot.WithCountry(country),
	)
	crtBytes, err := cert.SelfSign(rand.Reader, signer.Public().(crypto.PublicKey).(*rsa.PublicKey), signer)
	if err != nil {
		return err
	}
	name := filepath.Join(depot, "external-ca.pem")
	file, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0400)
	if err != nil {
		return err
	}
	defer file.Close()

	if _, err := file.Write(pemCert(crtBytes)); err != nil {
		file.Close()
		os.Remove(name)
		return err
	}
	return nil
}

const (
	rsaPrivateKeyPEMBlockType = "RSA PRIVATE KEY"
	certificatePEMBlockType   = "CERTIFICATE"
)

func pemCert(derBytes []byte) []byte {
	pemBlock := &pem.Block{
		Type:    certificatePEMBlockType,
		Headers: nil,
		Bytes:   derBytes,
	}
	out := pem.EncodeToMemory(pemBlock)
	return out
}

func envString(key, def string) string {
	if env := os.Getenv(key); env != "" {
		return env
	}
	return def
}

func envBool(key string) bool {
	if env := os.Getenv(key); env == "true" {
		return true
	}
	return false
}

func setByUser(flagName, envName string) bool {
	userDefinedFlags := make(map[string]bool)
	flag.Visit(func(f *flag.Flag) {
		userDefinedFlags[f.Name] = true
	})
	flagSet := userDefinedFlags[flagName]
	_, envSet := os.LookupEnv(envName)
	return flagSet || envSet
}
