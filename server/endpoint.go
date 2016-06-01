package scepserver

import "github.com/micromdm/scep/scep"

// SCEPRequest is a SCEP server request.
type SCEPRequest struct {
	Operation  string
	Message    []byte
	PKIMessage *scep.PKIMessage
	Err        error // request error
}

// SCEPResponse is a SCEP server response.
// Business errors will be encoded as a CertRep message
// with pkiStatus FAILURE and a failInfo attribute.
type SCEPResponse struct {
	PKIMessage *scep.PKIMessage
	Data       []byte // a non pkiMessage response
	Err        error  // resposne error
}
