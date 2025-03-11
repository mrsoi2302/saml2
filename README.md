# SAML2 Authentication Application

Ứng dụng xác thực SAML2 với xử lý thủ công các bước xác thực.

## Cài đặt

1. Clone repository
2. Cài đặt dependencies:
```bash
npm install
```

## Cấu hình

1. Tạo file `.env` từ mẫu `.env.example`
2. Cập nhật các thông số cấu hình trong file `.env`:
   - `PORT`: Port chạy ứng dụng
   - `IDP_METADATA_URL`: URL metadata của Identity Provider
   - `SP_ENTITY_ID`: Entity ID của Service Provider
   - `SP_ACS_URL`: URL Assertion Consumer Service

## Chạy ứng dụng

Development:
```bash
npm run dev
```

Production:
```bash
npm start
```

## Các endpoint

- `/metadata`: Endpoint cung cấp metadata của SP
- `/login`: Endpoint bắt đầu quá trình đăng nhập SAML
- `/acs`: Endpoint nhận và xử lý SAML Response 