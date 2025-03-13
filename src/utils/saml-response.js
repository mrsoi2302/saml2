const crypto = require('crypto');
const xml2js = require('xml2js');
const fs = require('fs');
const xmldom = require('xmldom');
const xpath = require('xpath');
const SignedXml = require('xml-crypto').SignedXml;
const FileKeyInfo = require('xml-crypto').FileKeyInfo;

async function processSAMLResponse(samlResponse) {
    // Giải mã Base64
    const decodedResponse = Buffer.from(samlResponse, 'base64').toString();
    console.log('Decoded SAML Response:', decodedResponse);
    
    // Parse XML với namespace
    const parser = new xml2js.Parser({
        explicitArray: false,
        tagNameProcessors: [xml2js.processors.stripPrefix],
        attrNameProcessors: [xml2js.processors.stripPrefix],
        xmlns: true
    });
    
    const parsedResponse = await parser.parseStringPromise(decodedResponse);
    console.log('Parsed SAML Response:', JSON.stringify(parsedResponse, null, 2));

    // Xác thực chữ ký
    try {
        await verifySignature(decodedResponse);
    } catch (error) {
        console.error('Signature verification error:', error);
        throw new Error('Invalid signature: ' + error.message);
    }

    // Kiểm tra cấu trúc Response
    if (!parsedResponse['Response']) {
        throw new Error('Invalid SAML Response format: Missing Response element');
    }

    if (!parsedResponse['Response']['Assertion']) {
        throw new Error('Invalid SAML Response format: Missing Assertion element');
    }

    // Lấy thông tin người dùng từ Assertion
    const assertion = parsedResponse['Response']['Assertion'];
    
    // Kiểm tra cấu trúc Assertion
    if (!assertion['Subject'] || !assertion['Subject']['NameID']) {
        throw new Error('Invalid Assertion format: Missing Subject or NameID');
    }

    const nameID = assertion['Subject']['NameID']._;
    const attributes = assertion['AttributeStatement'] ? 
        assertion['AttributeStatement']['Attribute'] : [];
    const sessionIndex = assertion['AuthnStatement'] ? 
        assertion['AuthnStatement'].$.SessionIndex : null;

    // Xử lý các thuộc tính
    const userInfo = {
        nameID,
        sessionIndex,
        attributes: {}
    };

    if (Array.isArray(attributes)) {
        attributes.forEach(attr => {
            const name = attr.$.Name;
            const value = attr['AttributeValue']._ || attr['AttributeValue'];
            userInfo.attributes[name] = value;
        });
    }

    return userInfo;
}

async function processLogoutResponse(logoutResponse) {
    // Giải mã Base64
    const decodedResponse = Buffer.from(logoutResponse, 'base64').toString();
    console.log('Decoded Logout Response:', decodedResponse);
    
    // Parse XML với namespace
    const parser = new xml2js.Parser({
        explicitArray: false,
        tagNameProcessors: [xml2js.processors.stripPrefix],
        attrNameProcessors: [xml2js.processors.stripPrefix],
        xmlns: true
    });
    const parsedResponse = await parser.parseStringPromise(decodedResponse);
    console.log('Parsed Logout Response:', JSON.stringify(parsedResponse, null, 2));

    // Xác thực chữ ký
    try {
        await verifySignature(decodedResponse);
    } catch (error) {
        console.error('Logout signature verification error:', error);
        throw new Error('Invalid logout signature: ' + error.message);
    }

    // Kiểm tra status của logout response
    if (!parsedResponse['LogoutResponse'] || 
        !parsedResponse['LogoutResponse']['Status'] || 
        !parsedResponse['LogoutResponse']['Status']['StatusCode']) {
        throw new Error('Invalid logout response format');
    }

    const statusCode = parsedResponse['LogoutResponse']['Status']['StatusCode'];
    const statusValue = statusCode.Value || statusCode.$.Value;
    
    console.log('Logout Status:', statusValue);

    if (statusValue.value !== 'urn:oasis:names:tc:SAML:2.0:status:Success') {
        throw new Error(`Logout failed with status: ${statusValue}`);
    }

    return true;
}

async function processLogoutRequest(logoutRequest) {
    // Giải mã Base64
    const decodedRequest = Buffer.from(logoutRequest, 'base64').toString();
    console.log('Decoded Logout Request:', decodedRequest);
    
    // Parse XML với namespace
    const parser = new xml2js.Parser({
        explicitArray: false,
        tagNameProcessors: [xml2js.processors.stripPrefix],
        attrNameProcessors: [xml2js.processors.stripPrefix],
        xmlns: true
    });
    const parsedRequest = await parser.parseStringPromise(decodedRequest);
    console.log('Parsed Logout Request:', JSON.stringify(parsedRequest, null, 2));

    // Xác thực chữ ký
    try {
        await verifySignature(decodedRequest);
    } catch (error) {
        console.error('Logout signature verification error:', error);
        throw new Error('Invalid logout signature: ' + error.message);
    }

    // Kiểm tra cấu trúc logout request
    if (!parsedRequest['LogoutRequest']) {
        throw new Error('Invalid logout request format');
    }

    // Lấy ID của request để trả về trong response
    const requestId = parsedRequest['LogoutRequest'].$.ID;
    if (!requestId) {
        throw new Error('Missing request ID in logout request');
    }

    return requestId;
}

function verifySignature(xml) {
    try {
        const doc = new xmldom.DOMParser().parseFromString(xml);
        
        // Tạo chứng chỉ từ biến môi trường
        const certPem = `-----BEGIN CERTIFICATE-----\n${process.env.IDP_CERTIFICATE}\n-----END CERTIFICATE-----`;
        
        // Định nghĩa namespace
        const namespaces = {
            samlp: 'urn:oasis:names:tc:SAML:2.0:protocol',
            saml: 'urn:oasis:names:tc:SAML:2.0:assertion',
            ds: 'http://www.w3.org/2000/09/xmldsig#'
        };
        
        // Tạo select function với namespace
        const select = xpath.useNamespaces(namespaces);

        // Kiểm tra loại message
        const isLogoutResponse = select("//samlp:LogoutResponse", doc).length > 0;
        const isLogoutRequest = select("//samlp:LogoutRequest", doc).length > 0;
        const isSamlResponse = select("//samlp:Response", doc).length > 0;
        
        let signatureNode;
        let nodeToVerify;
        
        if (isLogoutResponse) {
            // Đối với Logout Response, lấy signature từ LogoutResponse
            nodeToVerify = select("//samlp:LogoutResponse", doc)[0];
            signatureNode = select(".//ds:Signature", nodeToVerify)[0];
        } else if (isLogoutRequest) {
            // Đối với Logout Request, lấy signature từ LogoutRequest
            nodeToVerify = select("//samlp:LogoutRequest", doc)[0];
            signatureNode = select(".//ds:Signature", nodeToVerify)[0];
        } else if (isSamlResponse) {
            // Đối với SAML Response, kiểm tra signature trong Response hoặc Assertion
            const assertion = select("//saml:Assertion", doc)[0];
            const response = select("//samlp:Response", doc)[0];
            
            // Ưu tiên kiểm tra signature trong Assertion nếu có
            if (assertion && select(".//ds:Signature", assertion)[0]) {
                nodeToVerify = assertion;
                signatureNode = select(".//ds:Signature", assertion)[0];
            } else {
                // Nếu không có signature trong Assertion, kiểm tra trong Response
                nodeToVerify = response;
                signatureNode = select(".//ds:Signature", response)[0];
            }
        } else {
            throw new Error('Unknown SAML message type');
        }

        if (!signatureNode) {
            throw new Error('No signature found');
        }

        // Tạo SignedXml object với ID attribute
        class IdSignedXml extends SignedXml {
            constructor() {
                super();
                this.idMode = 'wssecurity';
                this.publicCert = certPem;
            }

            getReference(doc) {
                const ref = super.getReference(doc);
                ref.transforms = [
                    'http://www.w3.org/2000/09/xmldsig#enveloped-signature',
                    'http://www.w3.org/2001/10/xml-exc-c14n#'
                ];
                return ref;
            }
        }

        const sig = new IdSignedXml();
        
        // Load signature
        sig.loadSignature(signatureNode);
        
        // Verify signature với node tương ứng
        const isValid = sig.checkSignature(nodeToVerify.toString());
        
        if (!isValid) {
            throw new Error('Invalid signature');
        }
        
        return true;
    } catch (error) {
        console.error('Signature verification failed:', error);
        throw new Error('Invalid signature: ' + error.message);
    }
}

module.exports = {
    processSAMLResponse,
    processLogoutResponse,
    processLogoutRequest
}; 