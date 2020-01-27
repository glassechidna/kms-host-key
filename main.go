package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/aws/aws-sdk-go/service/kms/kmsiface"
	"github.com/glassechidna/go-kms-signer/kmssigner"
	"github.com/glassechidna/kms-host-key/myssh"
	"github.com/pkg/errors"
	"github.com/spf13/pflag"
	"golang.org/x/crypto/ssh"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"
)

var version = "unknown"

func main() {
	keyIdPtr := pflag.String("kms-key", "alias/hostkeysigner", "KMS key ID")
	sshKeyPathPtr := pflag.String("ssh-key-path", "/etc/ssh/ssh_host_rsa_key.pub", "Path to SSH host key to sign")
	printCa := pflag.BoolP("ca", "c", false, "Retrieve and print to stdout SSH CA public key")
	generate := pflag.BoolP("generate", "g", false, "Generate and print to stdout SSH host certificate")
	pflag.Parse()

	keyId := *keyIdPtr
	region, err := awsRegion(keyId)
	checkerr(err)
	api := kmsApi(err, region)

	if *printCa {
		printCertificateAuthority(api, keyId)
	} else if *generate {
		generateHostCertificate(*sshKeyPathPtr, api, keyId)
	} else {
		fmt.Fprintln(os.Stderr, "You must provide one of -g or -c")
		pflag.PrintDefaults()
	}
}

func kmsApi(err error, region string) kmsiface.KMSAPI {
	sess, err := session.NewSessionWithOptions(session.Options{
		Config:                  *aws.NewConfig().WithRegion(region),
		SharedConfigState:       session.SharedConfigEnable,
		AssumeRoleTokenProvider: stscreds.StdinTokenProvider,
	})
	checkerr(err)
	sess.Handlers.Build.PushBack(request.MakeAddToUserAgentHandler("kms-host-key", version))

	return kms.New(sess)
}

func generateHostCertificate(sshKeyPath string, api kmsiface.KMSAPI, keyId string) {
	sshKeyBytes, err := ioutil.ReadFile(sshKeyPath)
	checkerr(err)

	pubkey, _, _, _, err := ssh.ParseAuthorizedKey(sshKeyBytes)
	checkerr(err)

	var mode kmssigner.Mode
	if pubkey.Type() == ssh.KeyAlgoRSA {
		mode = kmssigner.ModeRsaPkcs1v15
	} else if strings.HasPrefix("ecdsa-sha2-", pubkey.Type()) {
		mode = kmssigner.ModeEcdsa
	} else {
		fmt.Fprintf(os.Stderr, "Unsupported ssh key type: %s\n", pubkey.Type())
		os.Exit(1)
	}

	signer := kmssigner.New(api, keyId, mode)
	sshsigner, err := myssh.NewSignerFromSigner(signer)
	checkerr(err)

	certKeyId, err := hostArn()
	checkerr(err)

	cert := &ssh.Certificate{
		Key:         pubkey,
		KeyId:       certKeyId,
		CertType:    ssh.HostCert,
		ValidBefore: ssh.CertTimeInfinity,
		ValidAfter:  uint64(time.Now().Unix()),
	}

	err = myssh.SignCert(cert, rand.Reader, sshsigner)
	checkerr(err)

	signed := cert.Marshal()
	b64 := base64.StdEncoding.EncodeToString(signed)
	formatted := fmt.Sprintf("%s %s", cert.Type(), b64)
	fmt.Println(formatted)
}

func printCertificateAuthority(api kmsiface.KMSAPI, keyId string) {
	out, err := api.GetPublicKey(&kms.GetPublicKeyInput{KeyId: &keyId})
	checkerr(err)

	key, err := kmssigner.ParseCryptoKey(out)
	checkerr(err)

	sshkey, err := ssh.NewPublicKey(key)
	checkerr(err)

	authKey := ssh.MarshalAuthorizedKey(sshkey)
	fmt.Printf("@cert-authority * %s\n", string(authKey))
}

func hostArn() (string, error) {
	meta, err := metadata()
	if err != nil {
		return "", err
	}

	doc, err := meta.GetInstanceIdentityDocument()
	if err != nil {
		return "", errors.WithStack(err)
	}

	return fmt.Sprintf("arn:aws:%s:%s:instance/%s", doc.Region, doc.AccountID, doc.InstanceID), nil
}

func checkerr(err error) {
	if err != nil {
		panic(fmt.Sprintf("%+v", err))
	}
}

func awsRegion(kmsKey string) (string, error) {
	parts := strings.Split(kmsKey, ":")
	if len(parts) == 5 {
		return parts[2], nil
	}

	if region, found := os.LookupEnv("AWS_REGION"); found {
		return region, nil
	}

	if region, found := os.LookupEnv("AWS_DEFAULT_REGION"); found {
		return region, nil
	}

	meta, err := metadata()
	if err == nil {
		return meta.Region()
	}

	return "", errors.New("Unknown AWS region. Neither AWS_REGION nor AWS_DEFAULT_REGION provided and EC2 metadata service unavailable")
}

func metadata() (*ec2metadata.EC2Metadata, error) {
	config := aws.NewConfig().
		WithHTTPClient(&http.Client{Timeout: 2 * time.Second}).
		WithMaxRetries(1)

	sess := session.Must(session.NewSession(config))
	meta := ec2metadata.New(sess)

	if meta.Available() {
		return meta, nil
	} else {
		return nil, errors.New("metadata service unavailable")
	}
}
