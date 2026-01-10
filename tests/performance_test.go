package tests

import (
	"bytes"
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"
)

// 性能测试配置
const (
	concurrency   = 100              // 并发用户数
	totalRequests = 10000            // 总请求数
	timeout       = 10 * time.Second // 请求超时时间
)

// 测试结果结构
type TestResult struct {
	Endpoint        string
	TotalRequests   int
	SuccessRequests int
	FailedRequests  int
	AvgResponseTime time.Duration
	MaxResponseTime time.Duration
	MinResponseTime time.Duration
	P95ResponseTime time.Duration
	P99ResponseTime time.Duration
}

// 测试端点
var testEndpoints = []string{
	"/health",
	"/auth/token",
	"/auth/userinfo",
	"/client/list",
}

// 测试请求体
var testBodies = map[string]string{
	"/auth/token": `{
		"grant_type": "password",
		"username": "admin",
		"password": "123456"
	}`,
}

// 测试请求头
var testHeaders = map[string]map[string]string{
	"/auth/token": {
		"Content-Type": "application/json",
	},
	"/auth/userinfo": {
		"Content-Type":  "application/json",
		"Authorization": "Bearer test-token",
	},
}

// TestPerformance 性能测试
func TestPerformance(t *testing.T) {
	// 跳过测试，因为这需要实际的服务运行
	t.Skipf("性能测试需要实际运行的服务，跳过测试")

	baseURL := "http://localhost:8080"
	results := make([]TestResult, 0, len(testEndpoints))

	for _, endpoint := range testEndpoints {
		result := runPerformanceTest(baseURL, endpoint, concurrency, totalRequests)
		results = append(results, result)
		printTestResult(result)
	}

	// 生成性能测试报告
	generatePerformanceReport(results)
}

// runPerformanceTest 运行性能测试
func runPerformanceTest(baseURL, endpoint string, concurrency, totalRequests int) TestResult {
	result := TestResult{
		Endpoint:        endpoint,
		TotalRequests:   totalRequests,
		SuccessRequests: 0,
		FailedRequests:  0,
		AvgResponseTime: 0,
		MaxResponseTime: 0,
		MinResponseTime: time.Hour,
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	responseTimes := make([]time.Duration, 0, totalRequests)

	// 计算每个并发用户需要发送的请求数
	requestsPerUser := totalRequests / concurrency
	if totalRequests%concurrency > 0 {
		requestsPerUser++
	}

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(userID int) {
			defer wg.Done()

			client := &http.Client{
				Timeout: timeout,
			}

			for j := 0; j < requestsPerUser && result.TotalRequests > result.SuccessRequests+result.FailedRequests; j++ {
				startTime := time.Now()

				// 构建请求
				req, err := buildRequest(baseURL, endpoint)
				if err != nil {
					mu.Lock()
					result.FailedRequests++
					mu.Unlock()
					continue
				}

				// 发送请求
				resp, err := client.Do(req)
				if err != nil {
					mu.Lock()
					result.FailedRequests++
					mu.Unlock()
					continue
				}

				// 读取响应
				resp.Body.Close()

				// 计算响应时间
				responseTime := time.Since(startTime)

				mu.Lock()
				responseTimes = append(responseTimes, responseTime)
				result.SuccessRequests++

				// 更新响应时间统计
				if responseTime > result.MaxResponseTime {
					result.MaxResponseTime = responseTime
				}
				if responseTime < result.MinResponseTime {
					result.MinResponseTime = responseTime
				}
				mu.Unlock()
			}
		}(i)
	}

	wg.Wait()

	// 计算平均响应时间
	if len(responseTimes) > 0 {
		totalTime := time.Duration(0)
		for _, rt := range responseTimes {
			totalTime += rt
		}
		result.AvgResponseTime = totalTime / time.Duration(len(responseTimes))

		// 计算P95和P99响应时间
		if len(responseTimes) > 0 {
			// 简单排序计算百分位数
			for i := 0; i < len(responseTimes); i++ {
				for j := i + 1; j < len(responseTimes); j++ {
					if responseTimes[i] > responseTimes[j] {
						responseTimes[i], responseTimes[j] = responseTimes[j], responseTimes[i]
					}
				}
			}

			p95Index := int(float64(len(responseTimes)) * 0.95)
			p99Index := int(float64(len(responseTimes)) * 0.99)

			if p95Index < len(responseTimes) {
				result.P95ResponseTime = responseTimes[p95Index]
			}
			if p99Index < len(responseTimes) {
				result.P99ResponseTime = responseTimes[p99Index]
			}
		}
	}

	return result
}

// buildRequest 构建HTTP请求
func buildRequest(baseURL, endpoint string) (*http.Request, error) {
	url := baseURL + endpoint

	// 构建请求体
	var body bytes.Buffer
	if bodyStr, ok := testBodies[endpoint]; ok {
		body.WriteString(bodyStr)
	}

	// 创建请求
	req, err := http.NewRequest("GET", url, &body)
	if err != nil {
		return nil, err
	}

	// 设置请求方法
	if endpoint == "/auth/token" {
		req.Method = "POST"
	}

	// 设置请求头
	if headers, ok := testHeaders[endpoint]; ok {
		for key, value := range headers {
			req.Header.Set(key, value)
		}
	}

	// 设置默认请求头
	if req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}

	return req, nil
}

// printTestResult 打印测试结果
func printTestResult(result TestResult) {
	fmt.Printf("\n===== %s 性能测试结果 =====\n", result.Endpoint)
	fmt.Printf("总请求数: %d\n", result.TotalRequests)
	fmt.Printf("成功请求数: %d\n", result.SuccessRequests)
	fmt.Printf("失败请求数: %d\n", result.FailedRequests)
	fmt.Printf("成功率: %.2f%%\n", float64(result.SuccessRequests)/float64(result.TotalRequests)*100)
	fmt.Printf("平均响应时间: %v\n", result.AvgResponseTime)
	fmt.Printf("最大响应时间: %v\n", result.MaxResponseTime)
	fmt.Printf("最小响应时间: %v\n", result.MinResponseTime)
	fmt.Printf("P95响应时间: %v\n", result.P95ResponseTime)
	fmt.Printf("P99响应时间: %v\n", result.P99ResponseTime)
	fmt.Println("=============================")
}

// generatePerformanceReport 生成性能测试报告
func generatePerformanceReport(results []TestResult) {
	fmt.Println("\n===== 性能测试综合报告 =====")
	for _, result := range results {
		fmt.Printf("%s: \n", result.Endpoint)
		fmt.Printf("  成功率: %.2f%%\n", float64(result.SuccessRequests)/float64(result.TotalRequests)*100)
		fmt.Printf("  平均响应时间: %v\n", result.AvgResponseTime)
		fmt.Printf("  P99响应时间: %v\n", result.P99ResponseTime)
	}
	fmt.Println("=============================")

	// 检查性能指标是否满足要求
	fmt.Println("\n===== 性能指标评估 =====")
	for _, result := range results {
		if result.P99ResponseTime > 100*time.Millisecond {
			fmt.Printf("%s: P99响应时间超过100ms，需要优化\n", result.Endpoint)
		} else {
			fmt.Printf("%s: P99响应时间满足要求（<100ms）\n", result.Endpoint)
		}
	}
	fmt.Println("=============================")
}
