// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package http

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"math/rand"
	"strings"
	"time"

	"github.com/absmach/certs"
	"github.com/go-kit/kit/endpoint"
	"golang.org/x/crypto/ocsp"
)

func renewCertEndpoint(svc certs.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(viewReq)
		if err := req.validate(); err != nil {
			return renewCertRes{}, err
		}

		if err = svc.RenewCert(ctx, req.id); err != nil {
			return renewCertRes{}, err
		}

		return renewCertRes{renewed: true}, nil
	}
}

func revokeCertEndpoint(svc certs.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(viewReq)
		if err := req.validate(); err != nil {
			return revokeCertRes{revoked: false}, err
		}

		if err = svc.RevokeCert(ctx, req.id); err != nil {
			return revokeCertRes{revoked: false}, err
		}

		return revokeCertRes{revoked: true}, nil
	}
}

func deleteCertEndpoint(svc certs.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(deleteReq)
		if err := req.validate(); err != nil {
			return deleteCertRes{deleted: false}, err
		}

		if err = svc.RemoveCert(ctx, req.entityID); err != nil {
			return deleteCertRes{deleted: false}, err
		}

		return deleteCertRes{deleted: true}, nil
	}
}

func requestCertDownloadTokenEndpoint(svc certs.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(viewReq)
		if err := req.validate(); err != nil {
			return requestCertDownloadTokenRes{}, err
		}

		token, err := svc.RetrieveCertDownloadToken(ctx, req.id)
		if err != nil {
			return requestCertDownloadTokenRes{}, err
		}

		return requestCertDownloadTokenRes{Token: token}, nil
	}
}

func downloadCertEndpoint(svc certs.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(downloadReq)
		if err := req.validate(); err != nil {
			return fileDownloadRes{}, err
		}
		cert, ca, err := svc.RetrieveCert(ctx, req.token, req.id)
		if err != nil {
			return fileDownloadRes{}, err
		}

		return fileDownloadRes{
			Certificate: cert.Certificate,
			PrivateKey:  cert.Key,
			CA:          ca,
			Filename:    "certificates.zip",
			ContentType: "application/zip",
		}, nil
	}
}

func issueCertEndpoint(svc certs.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(issueCertReq)
		if err := req.validate(); err != nil {
			return issueCertRes{}, err
		}

		cert, err := svc.IssueCert(ctx, req.entityID, req.TTL, req.IpAddrs, req.Options)
		if err != nil {
			return issueCertRes{}, err
		}

		return issueCertRes{
			SerialNumber: cert.SerialNumber,
			Certificate:  string(cert.Certificate),
			ExpiryTime:   cert.ExpiryTime,
			EntityID:     cert.EntityID,
			Revoked:      cert.Revoked,
			issued:       true,
		}, nil
	}
}

func listCertsEndpoint(svc certs.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(listCertsReq)
		if err := req.validate(); err != nil {
			return listCertsRes{}, err
		}

		certPage, err := svc.ListCerts(ctx, req.pm)
		if err != nil {
			return listCertsRes{}, err
		}

		var crts []viewCertRes
		for _, c := range certPage.Certificates {
			crts = append(crts, viewCertRes{
				SerialNumber: c.SerialNumber,
				Revoked:      c.Revoked,
				EntityID:     c.EntityID,
				ExpiryTime:   c.ExpiryTime,
			})
		}

		return listCertsRes{
			Total:        certPage.Total,
			Offset:       certPage.Offset,
			Limit:        certPage.Limit,
			Certificates: crts,
		}, nil
	}
}

func viewCertEndpoint(svc certs.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(viewReq)
		if err := req.validate(); err != nil {
			return viewCertRes{}, err
		}
		cert, err := svc.ViewCert(ctx, req.id)
		if err != nil {
			return viewCertRes{}, err
		}

		return viewCertRes{
			SerialNumber: cert.SerialNumber,
			Certificate:  string(cert.Certificate),
			Key:          string(cert.Key),
			Revoked:      cert.Revoked,
			ExpiryTime:   cert.ExpiryTime,
			EntityID:     cert.EntityID,
		}, nil
	}
}

func ocspEndpoint(svc certs.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(ocspReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		cert, status, issuerCert, err := svc.OCSP(ctx, req.req.SerialNumber.String())
		if err != nil {
			return nil, err
		}

		switch strings.ToUpper(req.statusParam) {
		case "REVOKE":
			status = ocsp.Revoked
		case "GOOD":
			status = ocsp.Good
		case "SERVERFAILED":
			status = ocsp.ServerFailed
		case "RANDOM":
			r := rand.New(rand.NewSource(int64(time.Now().Nanosecond())))
			status = r.Intn(ocsp.ServerFailed)
		}

		template := ocsp.Response{
			Status:       status,
			SerialNumber: req.req.SerialNumber,
			ThisUpdate:   time.Now().UTC(),
			NextUpdate:   time.Now().UTC(),
			IssuerHash:   req.req.HashAlgorithm,
		}
		if template.Status == ocsp.Revoked {
			template.RevokedAt = time.Now().UTC()
		}
		var signer crypto.Signer

		if cert != nil {
			if cert.Revoked {
				template.RevokedAt = cert.ExpiryTime
				template.RevocationReason = ocsp.Unspecified
			}
			pemBlock, _ := pem.Decode(cert.Certificate)
			parsedCert, err := x509.ParseCertificate(pemBlock.Bytes)
			if err != nil {
				return nil, err
			}
			template.Certificate = parsedCert
			keyBlock, _ := pem.Decode(cert.Key)
			privKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
			if err != nil {
				return nil, err
			}
			signer = privKey
			if !parsedCert.NotAfter.After(time.Now().UTC()) {
				template.Status = ocsp.Revoked
				template.RevocationReason = ocsp.CessationOfOperation
			}
		}

		return ocspRes{
			template:   template,
			issuerCert: issuerCert,
			signer:     signer,
		}, nil
	}
}

func generateCRLEndpoint(svc certs.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(crlReq)
		if err := req.validate(); err != nil {
			return crlRes{}, err
		}
		crlBytes, err := svc.GenerateCRL(ctx, req.certtype)
		if err != nil {
			return crlRes{}, err
		}

		return crlRes{
			CrlBytes: crlBytes,
		}, nil
	}
}

func getDownloadCATokenEndpoint(svc certs.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		token, err := svc.RetrieveCAToken(ctx)
		if err != nil {
			return requestCertDownloadTokenRes{}, err
		}

		return requestCertDownloadTokenRes{Token: token}, nil
	}
}

func downloadCAEndpoint(svc certs.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(downloadReq)
		if err := req.validate(); err != nil {
			return fileDownloadRes{}, err
		}

		cert, err := svc.GetChainCA(ctx, req.token)
		if err != nil {
			return fileDownloadRes{}, err
		}

		return fileDownloadRes{
			Certificate: cert.Certificate,
			PrivateKey:  cert.Key,
			Filename:    "ca.zip",
			ContentType: "application/zip",
		}, nil
	}
}

func viewCAEndpoint(svc certs.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(downloadReq)
		if err := req.validate(); err != nil {
			return viewCertRes{}, err
		}

		cert, err := svc.GetChainCA(ctx, req.token)
		if err != nil {
			return viewCertRes{}, err
		}

		return viewCertRes{
			Certificate: string(cert.Certificate),
			Key:         string(cert.Key),
		}, nil
	}
}

func issueFromCSREndpoint(svc certs.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(IssueFromCSRReq)
		if err := req.validate(); err != nil {
			return issueFromCSRRes{}, err
		}

		cert, err := svc.IssueFromCSR(ctx, req.entityID, req.ttl, certs.CSR{CSR: []byte(req.CSR)})
		if err != nil {
			return issueFromCSRRes{}, err
		}

		return issueFromCSRRes{
			SerialNumber: cert.SerialNumber,
			Certificate:  string(cert.Certificate),
			Revoked:      cert.Revoked,
			ExpiryTime:   cert.ExpiryTime,
			EntityID:     cert.EntityID,
		}, nil
	}
}
