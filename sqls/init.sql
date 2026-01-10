-- 创建数据库
CREATE DATABASE IF NOT EXISTS `sso` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

USE `sso`;

-- 用户表
CREATE TABLE IF NOT EXISTS `users` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `username` varchar(50) NOT NULL COMMENT '用户名',
  `email` varchar(100) NOT NULL COMMENT '邮箱',
  `password` varchar(100) NOT NULL COMMENT '密码',
  `nickname` varchar(50) DEFAULT NULL COMMENT '昵称',
  `avatar` varchar(255) DEFAULT NULL COMMENT '头像',
  `phone` varchar(20) DEFAULT NULL COMMENT '手机号',
  `status` int(11) DEFAULT '1' COMMENT '状态：1-活跃，0-禁用',
  `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
  `updated_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_username` (`username`),
  UNIQUE KEY `uk_email` (`email`),
  KEY `idx_status` (`status`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='用户表';

-- 令牌表
CREATE TABLE IF NOT EXISTS `tokens` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `user_id` bigint(20) unsigned NOT NULL COMMENT '用户ID',
  `access_token` varchar(500) NOT NULL COMMENT '访问令牌',
  `refresh_token` varchar(500) NOT NULL COMMENT '刷新令牌',
  `expires_at` datetime NOT NULL COMMENT '访问令牌过期时间',
  `refresh_expires_at` datetime NOT NULL COMMENT '刷新令牌过期时间',
  `client_id` varchar(100) DEFAULT NULL COMMENT '客户端ID',
  `scope` varchar(255) DEFAULT NULL COMMENT '权限范围',
  `revoked` tinyint(1) DEFAULT '0' COMMENT '是否已撤销：1-是，0-否',
  `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
  `updated_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_access_token` (`access_token`),
  UNIQUE KEY `uk_refresh_token` (`refresh_token`),
  KEY `idx_user_id` (`user_id`),
  KEY `idx_client_id` (`client_id`),
  KEY `idx_revoked` (`revoked`),
  KEY `idx_expires_at` (`expires_at`),
  KEY `idx_refresh_expires_at` (`refresh_expires_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='令牌表';

-- 客户端表
CREATE TABLE IF NOT EXISTS `clients` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `client_id` varchar(100) NOT NULL COMMENT '客户端ID',
  `client_secret` varchar(100) NOT NULL COMMENT '客户端密钥',
  `name` varchar(100) NOT NULL COMMENT '客户端名称',
  `redirect_uris` text COMMENT '重定向URI列表，JSON格式',
  `scope` varchar(255) DEFAULT NULL COMMENT '权限范围',
  `grant_types` text COMMENT '授权类型列表，JSON格式',
  `response_types` text COMMENT '响应类型列表，JSON格式',
  `token_endpoint_auth_method` varchar(50) DEFAULT 'client_secret_basic' COMMENT '令牌端点认证方法',
  `status` int(11) DEFAULT '1' COMMENT '状态：1-启用，0-禁用',
  `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
  `updated_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_client_id` (`client_id`),
  KEY `idx_status` (`status`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='客户端表';

-- 审计事件表
CREATE TABLE IF NOT EXISTS `audit_events` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `event_type` varchar(50) NOT NULL COMMENT '事件类型',
  `user_id` bigint(20) unsigned DEFAULT NULL COMMENT '用户ID',
  `username` varchar(50) DEFAULT NULL COMMENT '用户名',
  `ip` varchar(50) DEFAULT NULL COMMENT 'IP地址',
  `user_agent` varchar(255) DEFAULT NULL COMMENT '用户代理',
  `details` text COMMENT '详细信息',
  `status` varchar(20) NOT NULL COMMENT '状态：success-成功，failure-失败',
  `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
  PRIMARY KEY (`id`),
  KEY `idx_user_id` (`user_id`),
  KEY `idx_event_type` (`event_type`),
  KEY `idx_status` (`status`),
  KEY `idx_created_at` (`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='审计事件表';

-- 插入默认管理员用户（密码：123456）
INSERT INTO `users` (`username`, `email`, `password`, `nickname`, `status`) VALUES
('admin', 'admin@example.com', '$2a$10$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW', '管理员', 1)
ON DUPLICATE KEY UPDATE `email` = VALUES(`email`), `nickname` = VALUES(`nickname`), `status` = VALUES(`status`);

-- 插入默认客户端
INSERT INTO `clients` (`client_id`, `client_secret`, `name`, `redirect_uris`, `scope`, `grant_types`, `response_types`) VALUES
('test-client', 'test-secret', '测试客户端', '["http://localhost:3000/callback"]', 'openid profile email', '["authorization_code", "refresh_token"]', '["code"]')
ON DUPLICATE KEY UPDATE `name` = VALUES(`name`), `redirect_uris` = VALUES(`redirect_uris`), `scope` = VALUES(`scope`), `grant_types` = VALUES(`grant_types`), `response_types` = VALUES(`response_types`);

-- 登录历史表
CREATE TABLE IF NOT EXISTS `login_histories` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `user_id` bigint(20) unsigned NOT NULL COMMENT '用户ID',
  `ip` varchar(50) NOT NULL COMMENT 'IP地址',
  `device_fingerprint` varchar(255) DEFAULT NULL COMMENT '设备指纹',
  `user_agent` varchar(255) DEFAULT NULL COMMENT '用户代理',
  `login_time` datetime NOT NULL COMMENT '登录时间',
  `status` int(11) DEFAULT '1' COMMENT '状态：1-成功，0-失败',
  `is_abnormal` tinyint(1) DEFAULT '0' COMMENT '是否异地登录',
  `remark` varchar(255) DEFAULT NULL COMMENT '备注',
  `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
  PRIMARY KEY (`id`),
  KEY `idx_user_id` (`user_id`),
  KEY `idx_ip` (`ip`),
  KEY `idx_login_time` (`login_time`),
  KEY `idx_status` (`status`),
  KEY `idx_is_abnormal` (`is_abnormal`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='登录历史表';

-- 监控指标表
CREATE TABLE IF NOT EXISTS `monitor_metrics` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `metric_type` varchar(50) NOT NULL COMMENT '指标类型：system, auth, token',
  `metric_name` varchar(50) NOT NULL COMMENT '指标名称',
  `metric_value` double NOT NULL COMMENT '指标值',
  `labels` text COMMENT '标签，JSON格式',
  `timestamp` datetime NOT NULL COMMENT '时间戳',
  `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
  PRIMARY KEY (`id`),
  KEY `idx_metric_type` (`metric_type`),
  KEY `idx_metric_name` (`metric_name`),
  KEY `idx_timestamp` (`timestamp`),
  KEY `idx_created_at` (`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='监控指标表';

-- 异常事件表
CREATE TABLE IF NOT EXISTS `anomaly_events` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `event_type` varchar(50) NOT NULL COMMENT '事件类型',
  `severity` varchar(20) NOT NULL COMMENT '严重程度：low, medium, high',
  `description` text NOT NULL COMMENT '描述',
  `user_id` bigint(20) unsigned DEFAULT NULL COMMENT '用户ID',
  `ip` varchar(50) DEFAULT NULL COMMENT 'IP地址',
  `device_fingerprint` varchar(255) DEFAULT NULL COMMENT '设备指纹',
  `status` varchar(20) DEFAULT 'pending' COMMENT '状态：pending, processed',
  `timestamp` datetime NOT NULL COMMENT '时间戳',
  `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
  `updated_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',
  PRIMARY KEY (`id`),
  KEY `idx_event_type` (`event_type`),
  KEY `idx_severity` (`severity`),
  KEY `idx_user_id` (`user_id`),
  KEY `idx_status` (`status`),
  KEY `idx_timestamp` (`timestamp`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='异常事件表';

-- 授权码表
CREATE TABLE IF NOT EXISTS `authorization_codes` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `code` varchar(100) NOT NULL COMMENT '授权码',
  `user_id` bigint(20) unsigned NOT NULL COMMENT '用户ID',
  `client_id` varchar(100) NOT NULL COMMENT '客户端ID',
  `redirect_uri` varchar(255) NOT NULL COMMENT '重定向URI',
  `scope` varchar(255) DEFAULT NULL COMMENT '权限范围',
  `state` varchar(100) DEFAULT NULL COMMENT '状态',
  `nonce` varchar(100) DEFAULT NULL COMMENT '随机值',
  `code_challenge` varchar(255) DEFAULT NULL COMMENT '代码挑战',
  `code_challenge_method` varchar(20) DEFAULT NULL COMMENT '代码挑战方法',
  `expires_at` datetime NOT NULL COMMENT '过期时间',
  `used` tinyint(1) DEFAULT '0' COMMENT '是否已使用',
  `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_code` (`code`),
  KEY `idx_user_id` (`user_id`),
  KEY `idx_client_id` (`client_id`),
  KEY `idx_expires_at` (`expires_at`),
  KEY `idx_used` (`used`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='授权码表';
