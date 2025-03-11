const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const fs = require('fs');
const path = require('path');

function generateSAMLRequest() {
    const id = '_' + uuidv4();
    const instant = new Date().toISOString();
    const request = `
        <samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                           xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                           ID="${id}"
                           Version="2.0"
                           IssueInstant="${instant}"
                           Destination="${process.env.IDP_SSO_URL}"
                           AssertionConsumerServiceURL="${process.env.SP_ACS_URL}"
                           ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">
            <saml:Issuer>${process.env.SP_ENTITY_ID}</saml:Issuer>
            <samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
                              AllowCreate="true"/>
        </samlp:AuthnRequest>
    `.trim();

    // Base64 encode the request
    const base64Request = Buffer.from(request).toString('base64');
    
    // Create the redirect URL with the SAML request
    const params = new URLSearchParams();
    params.append('SAMLRequest', base64Request);
    params.append('RelayState', process.env.SP_ACS_URL);
    
    // Sign the request parameters
    const sigAlg = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
    params.append('SigAlg', sigAlg);
    
    const stringToSign = `SAMLRequest=${encodeURIComponent(base64Request)}&RelayState=${encodeURIComponent(process.env.SP_ACS_URL)}&SigAlg=${encodeURIComponent(sigAlg)}`;
    const signature = signString(stringToSign);
    params.append('Signature', signature);

    return process.env.IDP_SSO_URL + '?' + params.toString();
}

function generateLogoutRequest(nameID, sessionIndex) {
    const id = '_' + uuidv4();
    const instant = new Date().toISOString();
    const request = `
        <samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                            xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                            ID="${id}"
                            Version="2.0"
                            IssueInstant="${instant}"
                            Destination="${process.env.IDP_LOGOUT_URL}">
            <saml:Issuer>${process.env.SP_ENTITY_ID}</saml:Issuer>
            <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">${nameID}</saml:NameID>
            <samlp:SessionIndex>${sessionIndex}</samlp:SessionIndex>
        </samlp:LogoutRequest>
    `.trim();

    // Base64 encode the request
    const base64Request = Buffer.from(request).toString('base64');
    
    // Create the redirect URL with the SAML request
    const params = new URLSearchParams();
    params.append('SAMLRequest', base64Request);
    params.append('RelayState', process.env.SP_SLO_URL);
    
    // Sign the request parameters
    const sigAlg = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
    params.append('SigAlg', sigAlg);
    
    const stringToSign = `SAMLRequest=${encodeURIComponent(base64Request)}&RelayState=${encodeURIComponent(process.env.SP_SLO_URL)}&SigAlg=${encodeURIComponent(sigAlg)}`;
    const signature = signString(stringToSign);
    params.append('Signature', signature);

    return process.env.IDP_LOGOUT_URL + '?' + params.toString();
}

function generateLogoutResponse(inResponseTo, status) {
    const id = '_' + uuidv4();
    const instant = new Date().toISOString();
    const response = `
        <samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                             xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                             ID="${id}"
                             Version="2.0"
                             IssueInstant="${instant}"
                             Destination="${process.env.IDP_LOGOUT_URL}"
                             InResponseTo="${inResponseTo}">
            <saml:Issuer>${process.env.SP_ENTITY_ID}</saml:Issuer>
            <samlp:Status>
                <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:${status}"/>
            </samlp:Status>
        </samlp:LogoutResponse>
    `.trim();

    // Base64 encode the response
    const base64Response = Buffer.from(response).toString('base64');
    
    // Create the redirect URL with the SAML response
    const params = new URLSearchParams();
    params.append('SAMLResponse', base64Response);
    
    // Sign the response parameters
    const sigAlg = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
    params.append('SigAlg', sigAlg);
    
    const stringToSign = `SAMLResponse=${encodeURIComponent(base64Response)}&SigAlg=${encodeURIComponent(sigAlg)}`;
    const signature = signString(stringToSign);
    params.append('Signature', signature);

    return process.env.IDP_LOGOUT_URL + '?' + params.toString();
}

function signXML(xml) {
    const privateKey = fs.readFileSync(process.env.SP_PRIVATE_KEY_PATH);
    const signer = crypto.createSign('RSA-SHA256');
    signer.update(xml);
    return signer.sign(privateKey, 'base64');
}

function signString(str) {
    const privateKey = fs.readFileSync(process.env.SP_PRIVATE_KEY_PATH);
    const signer = crypto.createSign('RSA-SHA256');
    signer.update(str);
    return signer.sign(privateKey, 'base64');
}

module.exports = {
    generateSAMLRequest,
    generateLogoutRequest,
    generateLogoutResponse,
    signXML
}; 