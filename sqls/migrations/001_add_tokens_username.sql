-- 增量迁移：tokens 表新增 username 列
--
-- 适用场景：已按旧版 sqls/init.sql 建过库、且配置里 database.auto_migrate=false
-- 的环境（生产常规做法）。init.sql 用的是 CREATE TABLE IF NOT EXISTS，
-- 对已存在的表不会补列，因此需要单独执行本脚本。
--
-- 执行：
--   mysql -u <user> -p <database> < sqls/migrations/001_add_tokens_username.sql
--
-- 为什么需要这一列：令牌签发时把用户名写进 claims，刷新令牌时要据此保持
-- 新令牌与原令牌一致。没有这一列，RefreshToken 读旧令牌记录时会因为
-- GORM 查询不存在的字段而失败，表现为「刷新令牌 500」。
--
-- 注意：MySQL 不支持 ADD COLUMN IF NOT EXISTS（MariaDB 支持），
-- 重复执行会报 "Duplicate column name 'username'"，忽略即可。

ALTER TABLE `tokens`
  ADD COLUMN `username` varchar(100) DEFAULT NULL
  COMMENT '用户名（签发时写入令牌 claims，刷新时沿用）'
  AFTER `scope`;
