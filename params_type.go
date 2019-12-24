package alipay

import ()

/*
	支付宝请求数据 接口
*/
type AlipayParam interface {
	// 获取method    支付宝调用的接口方法
	GetMethod() string
	//	获取参数集合  参数集合中不应该包含method
	GetParams() map[string]string
	//	获取回调地址
	GetNotifyUrl() string
}
