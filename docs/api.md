# LandcSSO API 文档

## 1. 认证相关接口

### 1.1 授权端点

- **URL**: `/auth/authorize`
- **方法**: GET
- **描述**: 处理OAuth 2.0授权请求

**请求参数**:

| 参数名 | 类型 | 必填 | 描述 |
|-------|------|------|------|
| client_id | string | 是 | 客户端ID |
| redirect_uri | string | 是 | 重定向URI |
| response_type | string | 是 | 响应类型，固定为"code" |
| scope | string | 否 | 请求的权限范围 |
| state | string | 是 | 客户端生成的随机字符串，用于防止CSRF攻击 |
| nonce | string | 否 | 用于ID Token的防重放攻击 |
| code_challenge | string | 否 | PKCE代码挑战 |
| code_challenge_method | string | 否 | PKCE代码挑战方法，支持"S256"或"plain" |

**响应**:

- 成功: 重定向到redirect_uri，携带code和state参数
- 失败: 重定向到redirect_uri，携带error和error_description参数

**逻辑**:

1. 验证client_id和redirect_uri
2. 检查用户是否已登录
3. 未登录则显示登录页面
4. 已登录则显示授权页面（如果需要）
5. 用户同意授权后，生成授权码
6. 重定向到redirect_uri，携带授权码

### 1.2 令牌端点

- **URL**: `/auth/token`
- **方法**: POST
- **描述**: 处理OAuth 2.0令牌请求

**请求参数**:

| 参数名 | 类型 | 必填 | 描述 |
|-------|------|------|------|
| grant_type | string | 是 | 授权类型，支持"authorization_code"、"refresh_token"、"client_credentials"、"password" |
| code | string | 否 | 授权码，当grant_type为"authorization_code"时必填 |
| client_id | string | 否 | 客户端ID |
| client_secret | string | 否 | 客户端密钥 |
| redirect_uri | string | 否 | 重定向URI，当grant_type为"authorization_code"时必填 |
| refresh_token | string | 否 | 刷新令牌，当grant_type为"refresh_token"时必填 |
| username | string | 否 | 用户名，当grant_type为"password"时必填 |
| password | string | 否 | 密码，当grant_type为"password"时必填 |
| scope | string | 否 | 请求的权限范围 |

**响应**:

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 1800,
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "scope": "openid profile email",
  "id_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**逻辑**:

1. 验证请求参数
2. 根据grant_type处理不同的授权类型
3. 生成访问令牌和刷新令牌
4. 保存令牌信息到数据库
5. 返回令牌响应

### 1.3 登出端点

- **URL**: `/auth/logout`
- **方法**: POST
- **描述**: 处理用户登出请求

**请求参数**:

| 参数名 | 类型 | 必填 | 描述 |
|-------|------|------|------|
| token | string | 否 | 访问令牌 |
| client_id | string | 否 | 客户端ID |

**响应**:

```json
{
  "code": 10000,
  "message": "登出成功",
  "data": null
}
```

**逻辑**:

1. 验证令牌（如果提供）
2. 撤销用户的所有令牌
3. 删除用户的会话
4. 通知客户端登出（如果需要）
5. 返回登出成功响应

### 1.4 用户信息端点

- **URL**: `/auth/userinfo`
- **方法**: GET
- **描述**: 获取用户信息

**请求头**:

| 头部名 | 类型 | 必填 | 描述 |
|-------|------|------|------|
| Authorization | string | 是 | Bearer {access_token} |

**响应**:

```json
{
  "sub": "1",
  "name": "Admin User",
  "given_name": "Admin",
  "family_name": "User",
  "nickname": "admin",
  "preferred_username": "admin",
  "profile": "https://example.com/profile/admin",
  "picture": "https://example.com/avatar/admin.jpg",
  "website": "https://example.com",
  "email": "admin@example.com",
  "email_verified": true,
  "gender": "male",
  "birthdate": "1990-01-01",
  "zoneinfo": "Asia/Shanghai",
  "locale": "zh-CN",
  "phone_number": "+8613800138000",
  "phone_number_verified": true,
  "address": {
    "formatted": "北京市海淀区",
    "street_address": "中关村大街1号",
    "locality": "北京市",
    "region": "海淀区",
    "postal_code": "100080",
    "country": "中国"
  },
  "updated_at": 1768028111
}
```

**逻辑**:

1. 验证访问令牌
2. 从令牌中提取用户信息
3. 查询用户详细信息
4. 返回用户信息响应

### 1.5 公钥端点

- **URL**: `/auth/jwks`
- **方法**: GET
- **描述**: 获取JWT公钥

**响应**:

```json
{
  "keys": [
    {
      "kty": "RSA",
      "alg": "RS256",
      "use": "sig",
      "kid": "key:1234567890",
      "n": "...",
      "e": "AQAB"
    }
  ]
}
```

**逻辑**:

1. 获取当前使用的公钥
2. 转换为JWKS格式
3. 返回公钥响应

### 1.6 令牌验证端点

- **URL**: `/auth/introspect`
- **方法**: POST
- **描述**: 验证令牌的有效性

**请求参数**:

| 参数名 | 类型 | 必填 | 描述 |
|-------|------|------|------|
| token | string | 是 | 要验证的令牌 |
| client_id | string | 否 | 客户端ID |
| client_secret | string | 否 | 客户端密钥 |

**响应**:

```json
{
  "active": true,
  "scope": "openid profile email",
  "client_id": "client1",
  "user_id": "1",
  "username": "admin",
  "token_type": "Bearer",
  "exp": 1768031711,
  "iat": 1768028111,
  "nbf": 1768028111,
  "iss": "https://sso.example.com",
  "sub": "1",
  "aud": "client1"
}
```

**逻辑**:

1. 验证令牌格式
2. 检查令牌是否在黑名单中
3. 验证令牌签名
4. 检查令牌是否过期
5. 返回令牌验证结果

## 2. 用户管理接口

### 2.1 用户注册

- **URL**: `/user/register`
- **方法**: POST
- **描述**: 注册新用户

**请求参数**:

| 参数名 | 类型 | 必填 | 描述 |
|-------|------|------|------|
| username | string | 是 | 用户名 |
| email | string | 是 | 邮箱 |
| password | string | 是 | 密码 |
| nickname | string | 否 | 昵称 |
| phone | string | 否 | 手机号 |

**响应**:

```json
{
  "code": 10000,
  "message": "注册成功",
  "data": {
    "id": 1,
    "username": "testuser",
    "email": "test@example.com",
    "nickname": "Test User",
    "avatar": "",
    "phone": "",
    "status": 1
  }
}
```

**逻辑**:

1. 验证请求参数
2. 检查用户名是否已存在
3. 检查邮箱是否已存在
4. 加密密码
5. 创建用户
6. 返回注册成功响应

### 2.2 用户登录

- **URL**: `/user/login`
- **方法**: POST
- **描述**: 用户登录

**请求参数**:

| 参数名 | 类型 | 必填 | 描述 |
|-------|------|------|------|
| username | string | 是 | 用户名 |
| password | string | 是 | 密码 |

**响应**:

```json
{
  "code": 10000,
  "message": "登录成功",
  "data": {
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "token_type": "Bearer",
    "expires_in": 1800,
    "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "scope": "openid profile email"
  }
}
```

**逻辑**:

1. 验证请求参数
2. 查找用户
3. 验证密码
4. 检查用户状态
5. 生成令牌
6. 创建会话
7. 返回登录成功响应

### 2.3 获取用户资料

- **URL**: `/user/profile`
- **方法**: GET
- **描述**: 获取用户资料

**请求头**:

| 头部名 | 类型 | 必填 | 描述 |
|-------|------|------|------|
| Authorization | string | 是 | Bearer {access_token} |

**响应**:

```json
{
  "code": 10000,
  "message": "获取成功",
  "data": {
    "id": 1,
    "username": "admin",
    "email": "admin@example.com",
    "nickname": "Admin User",
    "avatar": "https://example.com/avatar/admin.jpg",
    "phone": "+8613800138000",
    "status": 1
  }
}
```

**逻辑**:

1. 验证访问令牌
2. 从令牌中提取用户ID
3. 查询用户资料
4. 返回用户资料响应

### 2.4 更新用户资料

- **URL**: `/user/profile`
- **方法**: PUT
- **描述**: 更新用户资料

**请求头**:

| 头部名 | 类型 | 必填 | 描述 |
|-------|------|------|------|
| Authorization | string | 是 | Bearer {access_token} |

**请求参数**:

| 参数名 | 类型 | 必填 | 描述 |
|-------|------|------|------|
| nickname | string | 否 | 昵称 |
| avatar | string | 否 | 头像URL |
| phone | string | 否 | 手机号 |

**响应**:

```json
{
  "code": 10000,
  "message": "更新成功",
  "data": {
    "id": 1,
    "username": "admin",
    "email": "admin@example.com",
    "nickname": "Admin User",
    "avatar": "https://example.com/avatar/admin.jpg",
    "phone": "+8613800138000",
    "status": 1
  }
}
```

**逻辑**:

1. 验证访问令牌
2. 从令牌中提取用户ID
3. 验证请求参数
4. 更新用户资料
5. 返回更新成功响应

### 2.5 修改密码

- **URL**: `/user/change-password`
- **方法**: POST
- **描述**: 修改用户密码

**请求头**:

| 头部名 | 类型 | 必填 | 描述 |
|-------|------|------|------|
| Authorization | string | 是 | Bearer {access_token} |

**请求参数**:

| 参数名 | 类型 | 必填 | 描述 |
|-------|------|------|------|
| old_password | string | 是 | 旧密码 |
| new_password | string | 是 | 新密码 |

**响应**:

```json
{
  "code": 10000,
  "message": "密码修改成功",
  "data": null
}
```

**逻辑**:

1. 验证访问令牌
2. 从令牌中提取用户ID
3. 验证旧密码
4. 加密新密码
5. 更新密码
6. 撤销用户的所有令牌
7. 返回密码修改成功响应

## 3. 客户端管理接口

### 3.1 客户端列表

- **URL**: `/client/list`
- **方法**: GET
- **描述**: 获取客户端列表

**请求头**:

| 头部名 | 类型 | 必填 | 描述 |
|-------|------|------|------|
| Authorization | string | 是 | Bearer {access_token} |

**请求参数**:

| 参数名 | 类型 | 必填 | 描述 |
|-------|------|------|------|
| page | int | 否 | 页码，默认1 |
| page_size | int | 否 | 每页大小，默认10 |

**响应**:

```json
{
  "code": 10000,
  "message": "获取成功",
  "data": {
    "list": [
      {
        "id": 1,
        "client_id": "client1",
        "client_secret": "secret1",
        "name": "Client 1",
        "redirect_uris": ["https://example.com/callback"],
        "scope": "openid profile email",
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "client_secret_basic",
        "status": 1,
        "created_at": "2026-01-10T12:00:00Z"
      }
    ],
    "total": 1,
    "page": 1,
    "page_size": 10
  }
}
```

**逻辑**:

1. 验证访问令牌
2. 检查用户权限
3. 查询客户端列表
4. 返回客户端列表响应

### 3.2 创建客户端

- **URL**: `/client/create`
- **方法**: POST
- **描述**: 创建新客户端

**请求头**:

| 头部名 | 类型 | 必填 | 描述 |
|-------|------|------|------|
| Authorization | string | 是 | Bearer {access_token} |

**请求参数**:

| 参数名 | 类型 | 必填 | 描述 |
|-------|------|------|------|
| name | string | 是 | 客户端名称 |
| redirect_uris | array | 是 | 重定向URI列表 |
| scope | string | 否 | 权限范围 |
| grant_types | array | 否 | 授权类型列表 |
| response_types | array | 否 | 响应类型列表 |
| token_endpoint_auth_method | string | 否 | 令牌端点认证方法 |

**响应**:

```json
{
  "code": 10000,
  "message": "创建成功",
  "data": {
    "id": 1,
    "client_id": "client1",
    "client_secret": "secret1",
    "name": "Client 1",
    "redirect_uris": ["https://example.com/callback"],
    "scope": "openid profile email",
    "grant_types": ["authorization_code", "refresh_token"],
    "response_types": ["code"],
    "token_endpoint_auth_method": "client_secret_basic",
    "status": 1,
    "created_at": "2026-01-10T12:00:00Z"
  }
}
```

**逻辑**:

1. 验证访问令牌
2. 检查用户权限
3. 验证请求参数
4. 生成客户端ID和密钥
5. 创建客户端
6. 返回创建成功响应

### 3.3 更新客户端

- **URL**: `/client/update`
- **方法**: PUT
- **描述**: 更新客户端信息

**请求头**:

| 头部名 | 类型 | 必填 | 描述 |
|-------|------|------|------|
| Authorization | string | 是 | Bearer {access_token} |

**请求参数**:

| 参数名 | 类型 | 必填 | 描述 |
|-------|------|------|------|
| id | int | 是 | 客户端ID |
| name | string | 否 | 客户端名称 |
| redirect_uris | array | 否 | 重定向URI列表 |
| scope | string | 否 | 权限范围 |
| grant_types | array | 否 | 授权类型列表 |
| response_types | array | 否 | 响应类型列表 |
| token_endpoint_auth_method | string | 否 | 令牌端点认证方法 |
| status | int | 否 | 状态，1-启用，0-禁用 |

**响应**:

```json
{
  "code": 10000,
  "message": "更新成功",
  "data": {
    "id": 1,
    "client_id": "client1",
    "client_secret": "secret1",
    "name": "Client 1 Updated",
    "redirect_uris": ["https://example.com/callback"],
    "scope": "openid profile email",
    "grant_types": ["authorization_code", "refresh_token"],
    "response_types": ["code"],
    "token_endpoint_auth_method": "client_secret_basic",
    "status": 1,
    "created_at": "2026-01-10T12:00:00Z"
  }
}
```

**逻辑**:

1. 验证访问令牌
2. 检查用户权限
3. 验证请求参数
4. 更新客户端信息
5. 返回更新成功响应

### 3.4 删除客户端

- **URL**: `/client/delete`
- **方法**: DELETE
- **描述**: 删除客户端

**请求头**:

| 头部名 | 类型 | 必填 | 描述 |
|-------|------|------|------|
| Authorization | string | 是 | Bearer {access_token} |

**请求参数**:

| 参数名 | 类型 | 必填 | 描述 |
|-------|------|------|------|
| id | int | 是 | 客户端ID |

**响应**:

```json
{
  "code": 10000,
  "message": "删除成功",
  "data": null
}
```

**逻辑**:

1. 验证访问令牌
2. 检查用户权限
3. 验证请求参数
4. 删除客户端
5. 返回删除成功响应

## 4. 审计日志接口

### 4.1 日志列表

- **URL**: `/audit/list`
- **方法**: GET
- **描述**: 获取审计日志列表

**请求头**:

| 头部名 | 类型 | 必填 | 描述 |
|-------|------|------|------|
| Authorization | string | 是 | Bearer {access_token} |

**请求参数**:

| 参数名 | 类型 | 必填 | 描述 |
|-------|------|------|------|
| page | int | 否 | 页码，默认1 |
| page_size | int | 否 | 每页大小，默认10 |
| event_type | string | 否 | 事件类型 |
| user_id | int | 否 | 用户ID |
| start_time | string | 否 | 开始时间，格式：2026-01-10T12:00:00Z |
| end_time | string | 否 | 结束时间，格式：2026-01-10T12:00:00Z |
| status | string | 否 | 状态，success或failure |

**响应**:

```json
{
  "code": 10000,
  "message": "获取成功",
  "data": {
    "list": [
      {
        "id": 1,
        "event_type": "login",
        "user_id": 1,
        "username": "admin",
        "ip": "127.0.0.1",
        "user_agent": "Mozilla/5.0...",
        "details": "用户登录",
        "status": "success",
        "created_at": "2026-01-10T12:00:00Z"
      }
    ],
    "total": 1,
    "page": 1,
    "page_size": 10
  }
}
```

**逻辑**:

1. 验证访问令牌
2. 检查用户权限
3. 验证请求参数
4. 查询审计日志
5. 返回审计日志列表响应

### 4.2 日志详情

- **URL**: `/audit/detail`
- **方法**: GET
- **描述**: 获取审计日志详情

**请求头**:

| 头部名 | 类型 | 必填 | 描述 |
|-------|------|------|------|
| Authorization | string | 是 | Bearer {access_token} |

**请求参数**:

| 参数名 | 类型 | 必填 | 描述 |
|-------|------|------|------|
| id | int | 是 | 日志ID |

**响应**:

```json
{
  "code": 10000,
  "message": "获取成功",
  "data": {
    "id": 1,
    "event_type": "login",
    "user_id": 1,
    "username": "admin",
    "ip": "127.0.0.1",
    "user_agent": "Mozilla/5.0...",
    "details": "用户登录",
    "status": "success",
    "created_at": "2026-01-10T12:00:00Z"
  }
}
```

**逻辑**:

1. 验证访问令牌
2. 检查用户权限
3. 验证请求参数
4. 查询审计日志详情
5. 返回审计日志详情响应

## 5. 监控接口

### 5.1 系统状态

- **URL**: `/monitor/status`
- **方法**: GET
- **描述**: 获取系统状态

**请求头**:

| 头部名 | 类型 | 必填 | 描述 |
|-------|------|------|------|
| Authorization | string | 是 | Bearer {access_token} |

**响应**:

```json
{
  "code": 10000,
  "message": "获取成功",
  "data": {
    "system": {
      "cpu": 20.5,
      "memory": 45.2,
      "disk": 30.1
    },
    "services": {
      "mysql": "up",
      "redis": "up",
      "sso": "up"
    },
    "metrics": {
      "auth_success_rate": 99.5,
      "auth_latency": 0.1,
      "token_issuance_rate": 10.2
    }
  }
}
```

**逻辑**:

1. 验证访问令牌
2. 检查用户权限
3. 收集系统状态信息
4. 收集服务状态信息
5. 收集监控指标
6. 返回系统状态响应

### 5.2 指标列表

- **URL**: `/monitor/metrics`
- **方法**: GET
- **描述**: 获取监控指标列表

**请求头**:

| 头部名 | 类型 | 必填 | 描述 |
|-------|------|------|------|
| Authorization | string | 是 | Bearer {access_token} |

**请求参数**:

| 参数名 | 类型 | 必填 | 描述 |
|-------|------|------|------|
| metric | string | 否 | 指标名称 |
| start_time | string | 否 | 开始时间，格式：2026-01-10T12:00:00Z |
| end_time | string | 否 | 结束时间，格式：2026-01-10T12:00:00Z |

**响应**:

```json
{
  "code": 10000,
  "message": "获取成功",
  "data": [
    {
      "name": "auth_success_rate",
      "value": 99.5,
      "timestamp": "2026-01-10T12:00:00Z"
    },
    {
      "name": "auth_latency",
      "value": 0.1,
      "timestamp": "2026-01-10T12:00:00Z"
    },
    {
      "name": "token_issuance_rate",
      "value": 10.2,
      "timestamp": "2026-01-10T12:00:00Z"
    }
  ]
}
```

**逻辑**:

1. 验证访问令牌
2. 检查用户权限
3. 验证请求参数
4. 查询监控指标
5. 返回监控指标列表响应

## 6. 健康检查接口

### 6.1 健康检查

- **URL**: `/health`
- **方法**: GET
- **描述**: 健康检查

**响应**:

```json
{
  "status": "ok"
}
```

**逻辑**:

1. 检查服务是否正常运行
2. 返回健康检查响应
