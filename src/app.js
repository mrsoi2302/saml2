require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const { generateSAMLRequest, generateLogoutRequest, generateLogoutResponse } = require('./utils/saml');
const { processSAMLResponse, processLogoutResponse, processLogoutRequest } = require('./utils/saml-response');
const { generateMetadata } = require('./utils/metadata');

const app = express();

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.raw({ type: 'application/x-www-form-urlencoded' }));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Session để lưu trữ thông tin người dùng
const session = require('express-session');
app.use(session({
    secret: 'your-secret-key',
    resave: false,
    saveUninitialized: true
}));

// Endpoint để lấy metadata của SP
app.get('/metadata', (req, res) => {
    const metadata = generateMetadata();
    res.header('Content-Type', 'application/xml');
    res.send(metadata);
});

// Endpoint hiển thị trang login
app.get('/login', (req, res) => {
    res.render('login');
});

// Endpoint bắt đầu quá trình đăng nhập SAML
app.get('/auth/saml', (req, res) => {
    const redirectUrl = generateSAMLRequest();
    res.redirect(redirectUrl);
});

// Endpoint xử lý SAML Response
app.post('/acs', async (req, res) => {
    try {
        const samlResponse = req.body.SAMLResponse;
        const userInfo = await processSAMLResponse(samlResponse);
        req.session.user = userInfo;
        res.render('profile', { user: userInfo });
    } catch (error) {
        console.error('Error processing SAML response:', error);
        let errorMessage = 'An error occurred during authentication.';
        let errorDetails = null;

        if (error.message === 'Invalid signature') {
            errorMessage = 'Invalid security signature detected. This could be a security risk.';
            errorDetails = 'The digital signature in the SAML response is not valid. This might indicate that the response has been tampered with or is not from a trusted source.';
        } else if (error.message.includes('Assertion')) {
            errorMessage = 'Invalid SAML assertion format.';
            errorDetails = error.message;
        }

        res.render('error', {
            message: errorMessage,
            details: errorDetails
        });
    }
});

// Endpoint bắt đầu quá trình logout
app.get('/logout', (req, res) => {
    if (!req.session.user) {
        return res.redirect('/');
    }
    const redirectUrl = generateLogoutRequest(req.session.user.nameID, req.session.user.sessionIndex);
    res.redirect(redirectUrl);
});

// Endpoint xử lý Single Logout (GET)
app.get('/logout/saml2/slo', handleLogout);

// Endpoint xử lý Single Logout (POST)
app.post('/logout/saml2/slo', handleLogout);

// Hàm xử lý logout chung cho cả GET và POST
async function handleLogout(req, res) {
    try {
        // Lấy SAML message từ cả query params và body
        const samlRequest = req.query.SAMLRequest || req.body.SAMLRequest;
        const samlResponse = req.query.SAMLResponse || req.body.SAMLResponse;

        if (samlRequest) {
            // Đây là LogoutRequest từ IdP
            console.log('Received LogoutRequest from IdP');
            const requestId = await processLogoutRequest(samlRequest);
            // Xóa session
            req.session.destroy();
            // Tạo LogoutResponse
            const logoutResponse = generateLogoutResponse(requestId, 'Success');
            res.redirect(logoutResponse);
        } else if (samlResponse) {
            // Đây là LogoutResponse cho request của chúng ta
            console.log('Received LogoutResponse');
            await processLogoutResponse(samlResponse);
            req.session.destroy((err) => {
                if (err) {
                    console.error('Error destroying session:', err);
                }
                res.redirect('/login');
            });
        } else {
            throw new Error('Invalid SAML message');
        }
    } catch (error) {
        console.error('Error processing logout:', error);
        // Trong trường hợp lỗi, vẫn xóa session và chuyển về trang login
        req.session.destroy((err) => {
            if (err) {
                console.error('Error destroying session:', err);
            }
            res.redirect('/login');
        });
    }
}

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
}); 