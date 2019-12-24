package alipay

import (
	"fmt"
)

//参数 interface
type Option interface {
	apply(*CertClient)
}

// 参数执行func
type optionFunc func(*CertClient)

// 实现参数interface
func (of optionFunc) apply(c *CertClient) {
	of(c)
}

//设置format
func SetFormat(s string) Option {
	return optionFunc(func(c *CertClient) {
		c.format = s
	})
}

//设置charset
func SetCharset(s string) Option {
	return optionFunc(func(c *CertClient) {
		c.charset = s
	})
}

//设置signType
func SetSignType(s string) Option {
	return optionFunc(func(c *CertClient) {
		c.signType = s
	})
}

//设置version
func SetVersion(s string) Option {
	return optionFunc(func(c *CertClient) {
		c.version = s
	})
}

// 设置应用公钥证书
func SetAppPublicCertFilePath(s string) Option {
	return optionFunc(func(c *CertClient) {
		c.appPublicCertFilepath = s
	})
}

// 设置应用私钥证书路径
func SetAppPrivateCertFilePath(s string) Option {
	return optionFunc(func(c *CertClient) {
		c.appPrivateCertFilepath = s
	})
}

// 设置支付宝公钥证书
func SetAlipayPublicCertFilePath(s string) Option {
	return optionFunc(func(c *CertClient) {
		c.alipayPublicCertFilepath = s
	})
}

// 设置支付宝根证书
func SetAlipayRootCertFilePath(s string) Option {
	return optionFunc(func(c *CertClient) {
		c.alipayRootCertFilepath = s
	})
}

// 是否测试环境
func SetDev(b bool) Option {
	return optionFunc(func(c *CertClient) {
		c.dev = b
	})
}

/*
	支付错误信息结构体
*/
type AlipayErr struct {
	Code    string `json:"code"`
	Msg     string `json:"msg"`
	SubCode string `json:"sub_code"`
	SubMsg  string `json:"sub_msg"`
}

// 实现 error
func (this *AlipayErr) Error() string {
	return fmt.Sprintf("%s - %s", this.Code, this.SubMsg)
}
